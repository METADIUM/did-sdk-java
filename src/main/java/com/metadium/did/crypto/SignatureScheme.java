package com.metadium.did.crypto;

/**
 * What a key store signs for a delegator request (the on-chain contract accepts both).
 *
 * <p>The SDK builds a 32-byte digest of the request: {@code keccak256(0x19 0x00 || registry || ... || timestamp)}.
 * The scheme says which 32 bytes the {@link DigestSigner} receives. It signs them as they are, without a further hash.
 */
public enum SignatureScheme {
	/** The digest itself. The default, and what this SDK always did. */
	RAW_DIGEST,

	/**
	 * The Ethereum personal message hash of the digest: {@code keccak256("\x19Ethereum Signed Message:\n32" || digest)},
	 * the form of {@code personal_sign} and of did-sdk-swift. Use it for a key store or wallet that only signs this form.
	 */
	PERSONAL_SIGN
}
