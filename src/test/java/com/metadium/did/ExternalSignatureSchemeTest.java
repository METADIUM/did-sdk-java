package com.metadium.did;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Sign;
import org.web3j.crypto.Sign.SignatureData;
import org.web3j.utils.Numeric;

import com.metadium.did.crypto.DigestSigner;
import com.metadium.did.crypto.ECKeyUtils;
import com.metadium.did.crypto.ExternalMetadiumKey;
import com.metadium.did.crypto.ExternalSignatureUtils;
import com.metadium.did.crypto.SignatureScheme;

/**
 * {@link SignatureScheme}: what the key store signs for a delegator request. Offline.
 */
public class ExternalSignatureSchemeTest {

	private static byte[] rs(ECDSASignature sig) {
		byte[] out = new byte[64];
		System.arraycopy(Numeric.toBytesPadded(sig.r, 32), 0, out, 0, 32);
		System.arraycopy(Numeric.toBytesPadded(sig.s, 32), 0, out, 32, 32);
		return out;
	}

	/** a key store that signs the 32 bytes it receives as they are, and remembers them */
	private static class RecordingSigner implements DigestSigner {
		final ECKeyPair pair;
		final List<byte[]> received = new ArrayList<byte[]>();

		RecordingSigner(ECKeyPair pair) {
			this.pair = pair;
		}

		@Override
		public byte[] signDigest(byte[] digest) {
			received.add(digest);
			return rs(pair.sign(digest));
		}
	}

	private static byte[] personalHash(byte[] digest) {
		byte[] prefix = "\u0019Ethereum Signed Message:\n32".getBytes(StandardCharsets.UTF_8);
		byte[] data = new byte[prefix.length + 32];
		System.arraycopy(prefix, 0, data, 0, prefix.length);
		System.arraycopy(digest, 0, data, prefix.length, 32);
		return Hash.sha3(data);
	}

	private static final byte[] MESSAGE = "0x19 0x00 registry I authorize the creation of an Identity on my behalf.".getBytes(StandardCharsets.UTF_8);

	@Test
	public void theDefaultSchemeIsTheRawDigestAndUnchanged() throws Exception {
		ECKeyPair pair = ECKeyUtils.generateSecp256k1ECKeyPair();
		RecordingSigner signer = new RecordingSigner(pair);
		ExternalMetadiumKey key = new ExternalMetadiumKey(pair.getPublicKey(), signer);

		SignatureData signature = key.sign(MESSAGE);

		assertEquals(SignatureScheme.RAW_DIGEST, key.getScheme());
		assertArrayEquals(Hash.sha3(MESSAGE), signer.received.get(0));
		// the same check as before: the signature recovers the key from keccak256(message)
		assertEquals(pair.getPublicKey(), Sign.signedMessageToKey(MESSAGE, signature));
		assertTrue(key.verify(MESSAGE, signature));
	}

	@Test
	public void personalSignGivesTheSignerThePersonalMessageHashOfTheDigest() throws Exception {
		ECKeyPair pair = ECKeyUtils.generateSecp256k1ECKeyPair();
		RecordingSigner signer = new RecordingSigner(pair);
		ExternalMetadiumKey key = new ExternalMetadiumKey(pair.getPublicKey(), signer, SignatureScheme.PERSONAL_SIGN);

		SignatureData signature = key.sign(MESSAGE);

		byte[] digest = Hash.sha3(MESSAGE);
		assertEquals(1, signer.received.size());
		assertArrayEquals(personalHash(digest), signer.received.get(0));
		assertArrayEquals(personalHash(digest), ExternalSignatureUtils.personalMessageHash(digest));
		// v is 27 or 28 and the signature recovers the key from the personal message hash
		assertTrue(signature.getV()[0] == 27 || signature.getV()[0] == 28);
		assertEquals(pair.getPublicKey(), Sign.signedMessageHashToKey(personalHash(digest), signature));
		assertTrue(key.verify(MESSAGE, signature));
		// it does not recover the key from the raw digest: this is not the raw form
		assertFalse(pair.getPublicKey().equals(Sign.signedMessageToKey(MESSAGE, signature)));
	}

	@Test
	public void personalSignIsCanonicalLowS() throws Exception {
		ECKeyPair pair = ECKeyUtils.generateSecp256k1ECKeyPair();
		final BigInteger half = Sign.CURVE_PARAMS.getN().shiftRight(1);
		// a key store that returns the high-s form
		ExternalMetadiumKey key = new ExternalMetadiumKey(pair.getPublicKey(), new DigestSigner() {
			@Override
			public byte[] signDigest(byte[] digest) {
				ECDSASignature sig = pair.sign(digest);
				byte[] out = new byte[64];
				System.arraycopy(Numeric.toBytesPadded(sig.r, 32), 0, out, 0, 32);
				System.arraycopy(Numeric.toBytesPadded(Sign.CURVE_PARAMS.getN().subtract(sig.s), 32), 0, out, 32, 32);
				return out;
			}
		}, SignatureScheme.PERSONAL_SIGN);

		SignatureData signature = key.sign(MESSAGE);

		assertTrue(new BigInteger(1, signature.getS()).compareTo(half) <= 0);
		assertEquals(pair.getPublicKey(), Sign.signedMessageHashToKey(personalHash(Hash.sha3(MESSAGE)), signature));
	}

	@Test
	public void personalSignRefusesASignatureOfTheRawDigest() throws Exception {
		// the key store ignored the scheme and signed the digest it should have wrapped: refused before a transaction is sent
		final ECKeyPair pair = ECKeyUtils.generateSecp256k1ECKeyPair();
		final byte[][] firstSeen = new byte[1][];
		ExternalMetadiumKey key = new ExternalMetadiumKey(pair.getPublicKey(), new DigestSigner() {
			@Override
			public byte[] signDigest(byte[] digest) {
				return rs(pair.sign(Hash.sha3(MESSAGE)));
			}
		}, SignatureScheme.PERSONAL_SIGN);

		try {
			key.sign(MESSAGE);
			fail();
		}
		catch (IllegalStateException expected) {
			assertTrue(expected.getMessage().contains("does not match"));
		}
	}

	@Test
	public void rawDigestRefusesASignatureOfThePersonalMessageHash() throws Exception {
		final ECKeyPair pair = ECKeyUtils.generateSecp256k1ECKeyPair();
		ExternalMetadiumKey key = new ExternalMetadiumKey(pair.getPublicKey(), new DigestSigner() {
			@Override
			public byte[] signDigest(byte[] digest) {
				return rs(pair.sign(personalHash(digest)));
			}
		});

		try {
			key.sign(MESSAGE);
			fail();
		}
		catch (IllegalStateException expected) {
			assertTrue(expected.getMessage().contains("does not match"));
		}
	}

	@Test
	public void personalSignWorksWithTheSignerOfAnotherKeyRefused() throws Exception {
		ECKeyPair pair = ECKeyUtils.generateSecp256k1ECKeyPair();
		ExternalMetadiumKey key = new ExternalMetadiumKey(pair.getPublicKey(), new RecordingSigner(ECKeyUtils.generateSecp256k1ECKeyPair()), SignatureScheme.PERSONAL_SIGN);

		try {
			key.sign(MESSAGE);
			fail();
		}
		catch (IllegalStateException expected) {
			assertTrue(expected.getMessage().contains("does not match"));
		}
	}

	@Test
	public void fromPublicKeyBytesTakesAScheme() throws Exception {
		ECKeyPair pair = ECKeyUtils.generateSecp256k1ECKeyPair();
		byte[] xy = Numeric.toBytesPadded(pair.getPublicKey(), 64);

		ExternalMetadiumKey key = ExternalMetadiumKey.fromPublicKeyBytes(xy, new RecordingSigner(pair), SignatureScheme.PERSONAL_SIGN);

		assertEquals(SignatureScheme.PERSONAL_SIGN, key.getScheme());
		assertEquals(pair.getPublicKey(), key.getPublicKey());
		assertEquals(SignatureScheme.RAW_DIGEST, ExternalMetadiumKey.fromPublicKeyBytes(xy, new RecordingSigner(pair)).getScheme());
	}

	@Test(expected = IllegalArgumentException.class)
	public void aSchemeIsRequired() throws Exception {
		ECKeyPair pair = ECKeyUtils.generateSecp256k1ECKeyPair();
		new ExternalMetadiumKey(pair.getPublicKey(), new RecordingSigner(pair), null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void thePersonalMessageHashNeedsADigestOf32Bytes() {
		ExternalSignatureUtils.personalMessageHash(new byte[31]);
	}

	@Test
	public void theJwsSignerIsNotAffectedByTheScheme() throws Exception {
		// a VC / VP is signed over the SHA-256 of the JWS signing input; the scheme is for delegator requests only
		ECKeyPair pair = ECKeyUtils.generateSecp256k1ECKeyPair();
		RecordingSigner signer = new RecordingSigner(pair);
		ExternalMetadiumKey key = new ExternalMetadiumKey(pair.getPublicKey(), signer, SignatureScheme.PERSONAL_SIGN);
		MetadiumWallet wallet = new MetadiumWallet("did:meta:test:0000000000000000000000000000000000000000000000000000000000000001", key);

		com.nimbusds.jwt.SignedJWT jwt = wallet.issueCredential(java.util.Collections.singletonList("TestCredential"),
				java.net.URI.create("https://example/vc/1"), null, null, wallet.getDid(), java.util.Collections.<String, Object>singletonMap("n", "x"));

		com.nimbusds.jose.crypto.ECDSAVerifier verifier = new com.nimbusds.jose.crypto.ECDSAVerifier(ECKeyUtils.getPublicKey("04" + Numeric.toHexStringNoPrefixZeroPadded(pair.getPublicKey(), 128)));
		verifier.getJCAContext().setProvider(com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton.getInstance());
		assertTrue(jwt.verify(verifier));
	}
}
