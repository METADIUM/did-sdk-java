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
 * The produced signature is identical to {@link MetadiumKey#sign(byte[])}: keccak256 of the message, signed as a digest.
 */
public class ExternalMetadiumKey implements MetadiumKeyImpl {
	private final BigInteger publicKey;
	private final DigestSigner signer;

	/**
	 * @param publicKey uncompressed secp256k1 public key without the 0x04 prefix (64 bytes as an integer)
	 * @param signer    external signer
	 */
	public ExternalMetadiumKey(BigInteger publicKey, DigestSigner signer) {
		if (publicKey == null || signer == null) {
			throw new IllegalArgumentException("publicKey and signer are required");
		}
		this.publicKey = publicKey;
		this.signer = signer;
	}

	@Override
	public SignatureData sign(byte[] message) {
		return signDigest(Hash.sha3(message));
	}

	/**
	 * Sign a 32-byte digest through the external signer and return the canonical (low-s) signature with v = 27 or 28.
	 */
	public SignatureData signDigest(byte[] digest) {
		byte[] raw;
		try {
			raw = signer.signDigest(digest);
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new IllegalStateException("External signer failed", e);
		}
		BigInteger[] rs = ExternalSignatureUtils.parseRS(raw);
		BigInteger r = rs[0];
		BigInteger s = rs[1];

		// Always recover from the public key. Whether the signer's v is raw (0/1), 27/28 or EIP-155, the result is the same.
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
}
