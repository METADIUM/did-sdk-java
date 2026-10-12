package com.metadium.did.crypto;

/**
 * Callback to an external key store (HSM, KMS, wallet service) that signs a 32-byte digest
 * with a secp256k1 private key that never leaves the key store.
 */
public interface DigestSigner {
	/**
	 * Sign the digest as-is (no additional hashing).
	 *
	 * @param digest 32-byte digest to sign
	 * @return 64 bytes (r || s) or 65 bytes (r || s || v). The recovery id (v) is optional because
	 *         it is recovered from the public key when it is missing.
	 * @throws Exception if the key store failed to sign
	 */
	byte[] signDigest(byte[] digest) throws Exception;
}
