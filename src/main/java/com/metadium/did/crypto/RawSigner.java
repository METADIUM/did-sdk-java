package com.metadium.did.crypto;

/**
 * Callback to an external key store (HSM, KMS, wallet service) that receives the <b>signing input itself</b>
 * and does the hashing on its side. Use it when the key store cannot sign a digest that someone else has hashed.
 * If the key store signs a 32-byte digest as-is, use {@link DigestSigner} instead.
 *
 * <p>For a JWS (VC / VP) the key store must hash the input with SHA-256 and sign the hash with secp256k1 (ES256K).
 */
public interface RawSigner {
	/**
	 * Sign the signing input: SHA-256 hash of {@code signingInput}, then ECDSA (secp256k1).
	 *
	 * @param signingInput JWS signing input, that is {@code BASE64URL(header) + "." + BASE64URL(payload)} as bytes
	 * @return r || s (64 bytes), r || s || v (65 bytes) or ASN.1 DER. The recovery id (v) is optional
	 * @throws Exception if the key store failed to sign
	 */
	byte[] sign(byte[] signingInput) throws Exception;
}
