package com.metadium.did;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.net.URI;
import java.util.Collections;
import java.util.Map;

import org.junit.Test;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;
import org.web3j.crypto.Sign.SignatureData;
import org.web3j.utils.Numeric;

import com.metadium.did.crypto.DigestSigner;
import com.metadium.did.crypto.ECKeyUtils;
import com.metadium.did.crypto.ExternalMetadiumKey;
import com.metadium.did.crypto.MetadiumKey;
import com.metadium.did.crypto.MetadiumKeyImpl;
import com.metadium.did.exception.DidException;
import com.metadium.did.protocol.MetaDelegator;
import com.nimbusds.jose.JOSEException;
import com.metadium.vc.VerifiableCredential;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.SignedJWT;

/**
 * Offline tests. A local key plays the role of the external key store; no network is used.
 */
public class ExternalSignerTest {
	/** key store simulator. mode: 0=r||s, 1=r||s||v(0/1), 2=r||s||v(27/28), 3=high-s r||s, 4=DER */
	private static DigestSigner keyStore(final ECKeyPair keyPair, final int mode) {
		return new DigestSigner() {
			@Override
			public byte[] signDigest(byte[] digest) {
				ECDSASignature sig = keyPair.sign(digest); // canonical (low-s)
				BigInteger r = sig.r;
				BigInteger s = sig.s;
				if (mode == 3) {
					s = Sign.CURVE_PARAMS.getN().subtract(s);
				}
				byte[] rs = new byte[64];
				System.arraycopy(Numeric.toBytesPadded(r, 32), 0, rs, 0, 32);
				System.arraycopy(Numeric.toBytesPadded(s, 32), 0, rs, 32, 32);
				if (mode == 4) {
					return der(r, s);
				}
				if (mode == 1 || mode == 2) {
					byte[] out = new byte[65];
					System.arraycopy(rs, 0, out, 0, 64);
					out[64] = (byte)(mode == 1 ? 0 : 27);
					return out;
				}
				return rs;
			}
		};
	}

	/** ASN.1 DER encoding of an ECDSA signature, as returned by AWS KMS / Google Cloud KMS */
	private static byte[] der(BigInteger r, BigInteger s) {
		byte[] rb = r.toByteArray();
		byte[] sb = s.toByteArray();
		byte[] out = new byte[6 + rb.length + sb.length];
		out[0] = 0x30;
		out[1] = (byte)(4 + rb.length + sb.length);
		out[2] = 0x02;
		out[3] = (byte)rb.length;
		System.arraycopy(rb, 0, out, 4, rb.length);
		out[4 + rb.length] = 0x02;
		out[5 + rb.length] = (byte)sb.length;
		System.arraycopy(sb, 0, out, 6 + rb.length, sb.length);
		return out;
	}

	private static ECKeyPair newKeyPair() throws Exception {
		return ECKeyUtils.generateSecp256k1ECKeyPair();
	}

	@Test
	public void signsLikeLocalKeyForAllSignerOutputForms() throws Exception {
		ECKeyPair pair = newKeyPair();
		MetadiumKey local = new MetadiumKey(pair);
		byte[] message = "I authorize the creation of an Identity on my behalf.".getBytes();
		SignatureData expected = local.sign(message);

		for (int mode = 0; mode <= 4; mode++) {
			ExternalMetadiumKey external = new ExternalMetadiumKey(pair.getPublicKey(), keyStore(pair, mode));
			SignatureData actual = external.sign(message);
			assertEquals("mode " + mode, expected.getV()[0], actual.getV()[0]);
			assertArrayEquals("mode " + mode, expected.getR(), actual.getR());
			assertArrayEquals("mode " + mode, expected.getS(), actual.getS());
			assertTrue(external.verify(message, actual));
			assertEquals(local.getAddress(), external.getAddress());
			assertEquals(local.getPublicKey(), external.getPublicKey());
		}
	}

	@Test
	public void rejectsSignatureOfOtherKey() throws Exception {
		ECKeyPair pair = newKeyPair();
		ECKeyPair other = newKeyPair();
		ExternalMetadiumKey external = new ExternalMetadiumKey(pair.getPublicKey(), keyStore(other, 0));
		try {
			external.sign("message".getBytes());
			fail();
		}
		catch (IllegalStateException expected) {
		}
	}

	@Test
	public void rejectsUnsupportedSignatureForm() throws Exception {
		ECKeyPair pair = newKeyPair();
		DigestSigner bad = new DigestSigner() {
			@Override
			public byte[] signDigest(byte[] digest) {
				return new byte[10];
			}
		};
		try {
			new ExternalMetadiumKey(pair.getPublicKey(), bad).sign("message".getBytes());
			fail();
		}
		catch (IllegalStateException expected) {
		}
	}

	@Test
	public void jwsSignerAcceptsDerAndRejectsOtherKey() throws Exception {
		ECKeyPair pair = newKeyPair();
		ECKeyPair other = newKeyPair();
		MetadiumWallet wallet = new MetadiumWallet("did:meta:test:0000000000000000000000000000000000000000000000000000000000000001",
				new ExternalMetadiumKey(pair.getPublicKey(), keyStore(pair, 4)));
		Map<String, Object> claims = Collections.<String, Object>singletonMap("name", "x");
		String holder = "did:meta:test:0000000000000000000000000000000000000000000000000000000000000002";

		// DER signature of the right key
		ExternalMetadiumKey good = new ExternalMetadiumKey(pair.getPublicKey(), keyStore(pair, 4));
		SignedJWT jwt = wallet.issueCredential(Collections.singletonList("NameCredential"), null, null, null, holder, claims, good.getJWSSigner());
		ECDSAVerifier verifier = new ECDSAVerifier(ECKeyUtils.getPublicKey("04" + Numeric.toHexStringNoPrefixZeroPadded(pair.getPublicKey(), 128)));
		verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		assertTrue(jwt.verify(verifier));

		// a wrong key in the key store is detected when signing, not at the verifier
		ExternalMetadiumKey wrong = new ExternalMetadiumKey(pair.getPublicKey(), keyStore(other, 0));
		try {
			wallet.issueCredential(Collections.singletonList("NameCredential"), null, null, null, holder, claims, wrong.getJWSSigner());
			fail();
		}
		catch (JOSEException expected) {
		}
	}

	/** records the key given to the service key operations and stops before any network call */
	private static class SpyDelegator extends MetaDelegator {
		MetadiumKeyImpl received;

		@Override
		public String addKeyDelegated(MetadiumKeyImpl key, String serviceId, String serviceKeyAddress) {
			received = key;
			throw new IllegalStateException("stop");
		}

		@Override
		public String removeKeyDelegated(MetadiumKeyImpl key, String serviceId, String serviceKeyAddress) {
			received = key;
			throw new IllegalStateException("stop");
		}

		@Override
		public String removeKeysDelegated(MetadiumKeyImpl key) {
			received = key;
			throw new IllegalStateException("stop");
		}
	}

	@Test
	public void serviceKeyOperationsUseTheExternalKey() throws Exception {
		ECKeyPair pair = newKeyPair();
		MetadiumWallet wallet = new MetadiumWallet("did:meta:test:0000000000000000000000000000000000000000000000000000000000000001",
				new ExternalMetadiumKey(pair.getPublicKey(), keyStore(pair, 0)));
		String address = "0x0000000000000000000000000000000000000001";

		for (int i = 0; i < 3; i++) {
			SpyDelegator delegator = new SpyDelegator();
			try {
				if (i == 0) {
					wallet.addServiceKey(delegator, "service", address);
				}
				else if (i == 1) {
					wallet.removeServiceKey(delegator, "service", address);
				}
				else {
					wallet.removeAllServiceKey(delegator);
				}
				fail();
			}
			catch (DidException expected) {
				// not UnsupportedOperationException: the external key reached the delegator call
				assertTrue(expected.getCause() instanceof IllegalStateException);
			}
			assertSame(wallet.getKeyImpl(), delegator.received);
		}
	}

	@Test
	public void credentialSignedByExternalSignerIsVerifiable() throws Exception {
		ECKeyPair pair = newKeyPair();
		ExternalMetadiumKey external = new ExternalMetadiumKey(pair.getPublicKey(), keyStore(pair, 3));
		MetadiumWallet wallet = new MetadiumWallet("did:meta:test:0000000000000000000000000000000000000000000000000000000000000001", external);

		String vc = wallet.issueCredential(
				Collections.singletonList("StudentCredential"),
				URI.create("http://example.com/credential/1"),
				null, null, "did:meta:test:0000000000000000000000000000000000000000000000000000000000000002",
				Collections.<String, Object>singletonMap("name", "student"),
				external.getJWSSigner()).serialize();

		SignedJWT jwt = SignedJWT.parse(vc);
		ECDSAVerifier verifier = new ECDSAVerifier(ECKeyUtils.getPublicKey("04" + Numeric.toHexStringNoPrefixZeroPadded(pair.getPublicKey(), 128)));
		verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		assertTrue(jwt.verify(verifier));
		assertEquals(wallet.getKid(), jwt.getHeader().getKeyID());
		assertEquals(wallet.getDid(), new VerifiableCredential(jwt).getIssuer().toString());
	}

	@Test
	public void localKeyPathIsUnchanged() throws Exception {
		ECKeyPair pair = newKeyPair();
		MetadiumWallet wallet = new MetadiumWallet("did:meta:test:0000000000000000000000000000000000000000000000000000000000000001", new MetadiumKey(pair));

		SignedJWT jwt = wallet.issueCredential(
				Collections.singletonList("NameCredential"), null, null, null,
				"did:meta:test:0000000000000000000000000000000000000000000000000000000000000002",
				Collections.<String, Object>singletonMap("name", "x"));

		ECDSAVerifier verifier = new ECDSAVerifier(ECKeyUtils.getPublicKey("04" + Numeric.toHexStringNoPrefixZeroPadded(pair.getPublicKey(), 128)));
		verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		assertTrue(jwt.verify(verifier));
		assertEquals("ES256K", jwt.getHeader().getAlgorithm().getName());

		// toJson / fromJson / getKey keep working for local keys
		MetadiumWallet restored = MetadiumWallet.fromJson(wallet.toJson());
		assertEquals(wallet.getDid(), restored.getDid());
		assertEquals(pair.getPrivateKey(), restored.getKey().getPrivateKey());
	}

	@Test
	public void externalWalletHidesPrivateKeyApis() throws Exception {
		ECKeyPair pair = newKeyPair();
		MetadiumWallet wallet = new MetadiumWallet("did:meta:test:0000000000000000000000000000000000000000000000000000000000000001",
				new ExternalMetadiumKey(pair.getPublicKey(), keyStore(pair, 0)));
		try {
			wallet.getKey();
			fail();
		}
		catch (UnsupportedOperationException expected) {
		}
		try {
			wallet.toJson();
			fail();
		}
		catch (UnsupportedOperationException expected) {
		}
	}
}
