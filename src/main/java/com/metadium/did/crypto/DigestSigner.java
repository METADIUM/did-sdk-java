package com.metadium.did.crypto;

/**
 * Callback to an external key store (HSM, KMS, wallet service) that signs a 32-byte digest
 * with a secp256k1 private key that never leaves the key store.
 *
 * <p>The digest is already final: the SDK has done the hashing (keccak256 of the message for delegator requests,
 * SHA-256 of the signing input for VC / VP), so the implementation must sign it as-is with no additional hashing.
 */
public interface DigestSigner {
	/**
	 * Sign the digest as-is (no additional hashing).
	 *
	 * @param digest 32-byte digest to sign
	 * @return r || s (64 bytes), r || s || v (65 bytes) or ASN.1 DER (as returned by AWS KMS and Google Cloud KMS).
	 *         The recovery id (v) is optional because it is recovered from the public key.
	 * @throws Exception if the key store failed to sign
	 */
	byte[] signDigest(byte[] digest) throws Exception;
}
