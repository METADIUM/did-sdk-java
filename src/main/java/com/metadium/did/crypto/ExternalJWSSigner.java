package com.metadium.did.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Collections;

import org.web3j.utils.Numeric;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;
import com.nimbusds.jose.util.Base64URL;

/**
 * ES256K {@link JWSSigner} that delegates the signature to an external key store through {@link DigestSigner}.
 * The digest is SHA-256 of the JWS signing input, and the signature is the 64 bytes (r || s, low-s) form required by JWS.
 */
public class ExternalJWSSigner extends BaseJWSProvider implements JWSSigner {
	private final DigestSigner signer;
	private final BigInteger publicKey;

	/**
	 * @param signer external signer. The signature is not checked against a public key; use {@link #ExternalJWSSigner(DigestSigner, BigInteger)} to check it.
	 */
	public ExternalJWSSigner(DigestSigner signer) {
		this(signer, null);
	}

	/**
	 * @param signer    external signer
	 * @param publicKey public key (64 bytes as an integer) of the key in the key store. If given, a signature made by another key is rejected.
	 */
	public ExternalJWSSigner(DigestSigner signer, BigInteger publicKey) {
		super(Collections.singleton(JWSAlgorithm.ES256K));
		if (signer == null) {
			throw new IllegalArgumentException("signer is required");
		}
		this.signer = signer;
		this.publicKey = publicKey;
	}

	@Override
	public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
		if (!JWSAlgorithm.ES256K.equals(header.getAlgorithm())) {
			throw new JOSEException("Unsupported algorithm: " + header.getAlgorithm());
		}
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(signingInput);
			BigInteger[] rs = ExternalSignatureUtils.parseRS(signer.signDigest(digest));
			if (publicKey != null && ExternalSignatureUtils.findRecoveryId(rs[0], rs[1], digest, publicKey) < 0) {
				throw new JOSEException("Signature does not match the public key");
			}
			byte[] concat = new byte[64];
			System.arraycopy(Numeric.toBytesPadded(rs[0], 32), 0, concat, 0, 32);
			System.arraycopy(Numeric.toBytesPadded(rs[1], 32), 0, concat, 32, 32);
			return Base64URL.encode(concat);
		}
		catch (JOSEException e) {
			throw e;
		}
		catch (Exception e) {
			throw new JOSEException("External signer failed: " + e.getMessage(), e);
		}
	}
}
