package com.metadium.did.smoke;

import com.metadium.did.crypto.DigestSigner;

/**
 * The keys of the smoke test {@link RealEnvironmentSmokeTest}.
 *
 * <p>The default implementation, {@link SoftwareKeyStore}, keeps the keys in memory. To run the test with the real external key store,
 * write a class with a public no-argument constructor that implements this interface and pass its name with
 * {@code -Dsmoke.keystore=com.example.MyKeyStore}.
 */
public interface SmokeKeyStore {

	/** A key of the key store: the public key and the signer that signs a 32-byte digest as-is with its private key */
	final class Key {
		/** public key bytes as the key store returns them (X||Y, 04||X||Y, compressed or SubjectPublicKeyInfo DER) */
		public final byte[] publicKey;
		public final DigestSigner signer;

		public Key(byte[] publicKey, DigestSigner signer) {
			this.publicKey = publicKey;
			this.signer = signer;
		}
	}

	/**
	 * The key with this name. Create it in the key store if it does not exist.
	 * The test asks for "student", "student-new" and "issuer", and uses dedicated keys that are not used for anything else.
	 */
	Key key(String name) throws Exception;
}
