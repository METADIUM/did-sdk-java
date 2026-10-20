package com.metadium.did.crypto;

import java.math.BigInteger;
import java.security.SignatureException;

import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.crypto.Sign.SignatureData;
import org.web3j.utils.Numeric;

/**
 * {@link MetadiumKeyImpl} whose private key is held by an external key store.
 * Only the public key is known to the SDK; every signature is made through {@link DigestSigner}.
 *
 * The digest and the signature format are the same as {@link MetadiumKey#sign(byte[])}: keccak256 of the message,
 * signed as a digest, with v = 27 or 28 and low-s. The r and s bytes can differ from a local signature when the key store
 * uses a random nonce instead of RFC 6979.
 *
 * <p>{@link DigestSigner} is called synchronously on the calling thread and is usually a network call.
 * Do not call it from the UI thread on Android. Use a key that is dedicated to DID: the key store signs arbitrary digests.
 */
public class ExternalMetadiumKey implements MetadiumKeyImpl {
	private final BigInteger publicKey;
	private final DigestSigner signer;

	/**
	 * @param publicKey uncompressed secp256k1 public key without the 0x04 prefix (64 bytes as an integer). It must be a point on the curve
	 * @param signer    external signer
	 * @throws IllegalArgumentException if the public key is not a point on the secp256k1 curve
	 */
	public ExternalMetadiumKey(BigInteger publicKey, DigestSigner signer) {
		if (publicKey == null || signer == null) {
			throw new IllegalArgumentException("publicKey and signer are required");
		}
		ExternalSignatureUtils.validatePublicKey(publicKey);
		this.publicKey = publicKey;
		this.signer = signer;
	}

	/**
	 * Create from the public key bytes returned by a key store.
	 * See {@link ExternalSignatureUtils#toPublicKey(byte[])} for the accepted forms (X||Y, 0x04||X||Y, compressed, SubjectPublicKeyInfo DER).
	 *
	 * @param publicKey public key bytes
	 * @param signer    external signer
	 * @throws IllegalArgumentException if the form is not supported or the point is not on the curve
	 */
	public static ExternalMetadiumKey fromPublicKeyBytes(byte[] publicKey, DigestSigner signer) {
		return new ExternalMetadiumKey(ExternalSignatureUtils.toPublicKey(publicKey), signer);
	}

	@Override
	public SignatureData sign(byte[] message) {
		return signDigest(Hash.sha3(message));
	}

	/**
	 * Sign a 32-byte digest through the external signer and return the canonical (low-s) signature with v = 27 or 28.
	 */
	public SignatureData signDigest(byte[] digest) {
		if (digest == null || digest.length != 32) {
			throw new IllegalArgumentException("digest must be 32 bytes");
		}
		byte[] raw;
		try {
			raw = signer.signDigest(digest);
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (Exception e) {
			if (e instanceof InterruptedException) {
				Thread.currentThread().interrupt();
			}
			throw new IllegalStateException("External signer failed", e);
		}
		BigInteger[] rs = ExternalSignatureUtils.parseRS(raw);
		BigInteger r = rs[0];
		BigInteger s = rs[1];

		// Always recover from the public key. Whether the signer's v is raw (0/1), 27/28 or EIP-155, the result is the same.
		// Only 0 and 1 are tried because v is 27 or 28 (web3j signMessage can also produce 29, 30, which a delegator request does not use).
		int recId = ExternalSignatureUtils.findRecoveryId(r, s, digest, publicKey);
		if (recId < 0) {
			throw new IllegalStateException("Signature does not match the public key");
		}
		return new SignatureData(
			(byte)(27 + recId),
			Numeric.toBytesPadded(r, 32),
			Numeric.toBytesPadded(s, 32));
	}

	@Override
	public boolean verify(byte[] message, SignatureData signature) throws SignatureException {
		return Sign.signedMessageToKey(message, signature).equals(publicKey);
	}

	@Override
	public String getAddress() {
		return Numeric.prependHexPrefix(Keys.getAddress(publicKey));
	}

	@Override
	public BigInteger getPublicKey() {
		return publicKey;
	}

	/**
	 * Create a JWS signer (ES256K) that uses the same external signer, for signing VC / VP.
	 * The signature is checked against the public key of this key, so a wrong key in the key store is detected at signing.
	 */
	public ExternalJWSSigner getJWSSigner() {
		return new ExternalJWSSigner(signer, publicKey);
	}

	/**
	 * Create a JWS signer (ES256K) for a key store that takes the signing input and hashes it itself.
	 * Delegator requests of this key are still signed through the {@link DigestSigner} of this key.
	 * The signature is checked against the public key of this key.
	 *
	 * @param rawSigner key store that receives the JWS signing input
	 */
	public ExternalRawJWSSigner getRawJWSSigner(RawSigner rawSigner) {
		return new ExternalRawJWSSigner(rawSigner, publicKey);
	}
}
