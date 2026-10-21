package com.metadium.did;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.net.URI;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Test;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import com.metadium.did.crypto.DigestSigner;
import com.metadium.did.crypto.ECKeyUtils;
import com.metadium.did.crypto.ExternalMetadiumKey;
import com.metadium.did.crypto.ExternalRawJWSSigner;
import com.metadium.did.crypto.MetadiumKey;
import com.metadium.did.crypto.RawSigner;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.SignedJWT;

/**
 * Offline tests of {@link RawSigner} (a key store that hashes the signing input itself) and of the challenge of a presentation.
 */
public class ExternalRawSignerTest {
	private static final String DID = "did:meta:test:0000000000000000000000000000000000000000000000000000000000000001";

	private static ECKeyPair newKeyPair() throws Exception {
		return ECKeyUtils.generateSecp256k1ECKeyPair();
	}

	private static byte[] sha256(byte[] input) throws Exception {
		return MessageDigest.getInstance("SHA-256").digest(input);
	}

	/**
	 * key store that hashes the input with SHA-256 and signs. mode: 0=r||s, 1=r||s||v, 2=high-s r||s, 3=DER, 4=r out of range
	 */
	private static RawSigner keyStore(final ECKeyPair keyPair, final int mode) {
		return new RawSigner() {
			@Override
			public byte[] sign(byte[] signingInput) throws Exception {
				ECDSASignature sig = keyPair.sign(sha256(signingInput));
				BigInteger r = sig.r;
				BigInteger s = sig.s;
				if (mode == 2) {
					s = Sign.CURVE_PARAMS.getN().subtract(s);
				}
				if (mode == 4) {
					r = Sign.CURVE_PARAMS.getN();
				}
				byte[] out = new byte[mode == 1 ? 65 : 64];
				System.arraycopy(Numeric.toBytesPadded(r, 32), 0, out, 0, 32);
				System.arraycopy(Numeric.toBytesPadded(s, 32), 0, out, 32, 32);
				if (mode == 3) {
					return der(r, s);
				}
				return out;
			}
		};
	}

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

	private static boolean verifies(SignedJWT jwt, BigInteger publicKey) throws Exception {
		ECDSAVerifier verifier = new ECDSAVerifier(ECKeyUtils.getPublicKey("04" + Numeric.toHexStringNoPrefixZeroPadded(publicKey, 128)));
		verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		return jwt.verify(verifier);
	}

	private static MetadiumWallet walletOf(ExternalMetadiumKey key) {
		return new MetadiumWallet(DID, key);
	}

	// RawSigner

	@Test
	public void vcSignedThroughARawSignerVerifies() throws Exception {
		ECKeyPair pair = newKeyPair();
		// the key store of this key signs a JWS only through the RawSigner: its digest signer must not be called
		ExternalMetadiumKey key = new ExternalMetadiumKey(pair.getPublicKey(), new DigestSigner() {
			@Override
			public byte[] signDigest(byte[] digest) {
				throw new IllegalStateException("not used for a JWS");
			}
		});
		MetadiumWallet wallet = walletOf(key);

		for (int mode = 0; mode <= 3; mode++) {
			SignedJWT jwt = wallet.issueCredential(Collections.singletonList("TestCredential"), URI.create("https://example/vc/1"), null, null, DID,
				Collections.<String, Object>singletonMap("name", "x"), key.getRawJWSSigner(keyStore(pair, mode)));
			assertTrue("mode " + mode, verifies(jwt, pair.getPublicKey()));
		}
	}

	@Test
	public void highSIsNormalized() throws Exception {
		ECKeyPair pair = newKeyPair();
		ExternalRawJWSSigner signer = new ExternalRawJWSSigner(keyStore(pair, 2), pair.getPublicKey());
		byte[] sig = signer.sign(new JWSHeader(JWSAlgorithm.ES256K), "a.b".getBytes()).decode();
		BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig, 32, 64));
		assertTrue(s.compareTo(Sign.CURVE_PARAMS.getN().shiftRight(1)) <= 0);
	}

	@Test
	public void signatureOfAnotherKeyIsRejected() throws Exception {
		ECKeyPair pair = newKeyPair();
		ECKeyPair other = newKeyPair();
		ExternalRawJWSSigner signer = new ExternalRawJWSSigner(keyStore(other, 0), pair.getPublicKey());
		try {
			signer.sign(new JWSHeader(JWSAlgorithm.ES256K), "a.b".getBytes());
			fail();
		}
		catch (JOSEException expected) {
			assertTrue(expected.getMessage().contains("does not match"));
		}
	}

	@Test
	public void outOfRangeSignatureIsRejected() throws Exception {
		ECKeyPair pair = newKeyPair();
		ExternalRawJWSSigner signer = new ExternalRawJWSSigner(keyStore(pair, 4), pair.getPublicKey());
		try {
			signer.sign(new JWSHeader(JWSAlgorithm.ES256K), "a.b".getBytes());
			fail();
		}
		catch (JOSEException expected) {
			assertTrue(expected.getMessage().contains("out of range"));
		}
	}

	@Test
	public void algorithmOtherThanEs256kIsRejected() throws Exception {
		ECKeyPair pair = newKeyPair();
		ExternalRawJWSSigner signer = new ExternalRawJWSSigner(keyStore(pair, 0), pair.getPublicKey());
		try {
			signer.sign(new JWSHeader(JWSAlgorithm.ES256), "a.b".getBytes());
			fail();
		}
		catch (JOSEException expected) {
			assertTrue(expected.getMessage().contains("Unsupported algorithm"));
		}
	}

	@Test
	public void keyStoreFailureBecomesJoseException() throws Exception {
		ECKeyPair pair = newKeyPair();
		ExternalRawJWSSigner signer = new ExternalRawJWSSigner(new RawSigner() {
			@Override
			public byte[] sign(byte[] signingInput) throws Exception {
				throw new java.io.IOException("key store is down");
			}
		}, pair.getPublicKey());
		try {
			signer.sign(new JWSHeader(JWSAlgorithm.ES256K), "a.b".getBytes());
			fail();
		}
		catch (JOSEException expected) {
			assertTrue(expected.getMessage().contains("key store is down"));
		}
	}

	@Test
	public void signerReceivesTheSigningInputNotAHash() throws Exception {
		final ECKeyPair pair = newKeyPair();
		final List<byte[]> received = new ArrayList<byte[]>();
		RawSigner spy = new RawSigner() {
			@Override
			public byte[] sign(byte[] signingInput) throws Exception {
				received.add(signingInput);
				return keyStore(pair, 0).sign(signingInput);
			}
		};
		byte[] input = "header.payload".getBytes();
		new ExternalRawJWSSigner(spy, pair.getPublicKey()).sign(new JWSHeader(JWSAlgorithm.ES256K), input);
		assertEquals(1, received.size());
		assertTrue(Arrays.equals(input, received.get(0)));
	}

	// challenge of a presentation

	@Test
	public void presentationCarriesTheChallengeAndTheAudience() throws Exception {
		MetadiumKey key = new MetadiumKey();
		MetadiumWallet wallet = new MetadiumWallet(DID, key);

		SignedJWT jwt = wallet.issuePresentation(Collections.singletonList("TestPresentation"), null, null, null,
			Collections.singletonList("vc.jwt"), null, "challenge-123", "did:meta:test:verifier");

		assertEquals("challenge-123", jwt.getJWTClaimsSet().getStringClaim("nonce"));
		assertEquals(Collections.singletonList("did:meta:test:verifier"), jwt.getJWTClaimsSet().getAudience());
		assertTrue(verifies(jwt, key.getPublicKey()));
	}

	@Test
	public void presentationWithoutChallengeKeepsTheRandomNonce() throws Exception {
		MetadiumWallet wallet = new MetadiumWallet(DID, new MetadiumKey());

		SignedJWT first = wallet.issuePresentation(Collections.singletonList("TestPresentation"), null, null, null, Collections.singletonList("vc.jwt"));
		SignedJWT second = wallet.issuePresentation(Collections.singletonList("TestPresentation"), null, null, null, Collections.singletonList("vc.jwt"), null, null, null);

		assertNotNull(first.getJWTClaimsSet().getStringClaim("nonce"));
		assertNotNull(second.getJWTClaimsSet().getStringClaim("nonce"));
		assertNotEquals(first.getJWTClaimsSet().getStringClaim("nonce"), second.getJWTClaimsSet().getStringClaim("nonce"));
		assertTrue(second.getJWTClaimsSet().getAudience().isEmpty());
	}

	@Test
	public void presentationWithAnExternalKeyUsesTheChallenge() throws Exception {
		final ECKeyPair pair = newKeyPair();
		ExternalMetadiumKey key = new ExternalMetadiumKey(pair.getPublicKey(), new DigestSigner() {
			@Override
			public byte[] signDigest(byte[] digest) {
				ECDSASignature sig = pair.sign(digest);
				byte[] out = new byte[64];
				System.arraycopy(Numeric.toBytesPadded(sig.r, 32), 0, out, 0, 32);
				System.arraycopy(Numeric.toBytesPadded(sig.s, 32), 0, out, 32, 32);
				return out;
			}
		});

		SignedJWT jwt = walletOf(key).issuePresentation(Collections.singletonList("TestPresentation"), null, null, null,
			Collections.singletonList("vc.jwt"), null, "challenge-456", "did:meta:test:verifier");

		assertEquals("challenge-456", jwt.getJWTClaimsSet().getStringClaim("nonce"));
		assertTrue(verifies(jwt, pair.getPublicKey()));
		assertFalse(jwt.getJWTClaimsSet().getAudience().isEmpty());
	}
}
