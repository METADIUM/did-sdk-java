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
 * ES256K {@link JWSSigner} for a key store that takes the signing input and hashes it itself ({@link RawSigner}).
 * The returned signature is normalized (range check, low-s) and, if the public key is given, checked to be made by that key
 * against SHA-256 of the signing input. The result is the 64 bytes (r || s) form required by JWS.
 *
 * <p>Compare {@link ExternalJWSSigner}: there the SDK hashes and the key store signs a digest.
 */
public class ExternalRawJWSSigner extends BaseJWSProvider implements JWSSigner {
	private final RawSigner signer;
	private final BigInteger publicKey;

	/**
	 * @param signer    external signer
	 * @param publicKey public key (64 bytes as an integer) of the key in the key store. Nullable, but then a signature
	 *                  made by another key is not detected until the verifier rejects it
	 */
	public ExternalRawJWSSigner(RawSigner signer, BigInteger publicKey) {
		super(Collections.singleton(JWSAlgorithm.ES256K));
		if (signer == null) {
			throw new IllegalArgumentException("signer is required");
		}
		if (publicKey != null) {
			ExternalSignatureUtils.validatePublicKey(publicKey);
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
			BigInteger[] rs = ExternalSignatureUtils.parseRS(signer.sign(signingInput));
			if (publicKey != null) {
				byte[] digest = MessageDigest.getInstance("SHA-256").digest(signingInput);
				if (ExternalSignatureUtils.findRecoveryId(rs[0], rs[1], digest, publicKey) < 0) {
					throw new JOSEException("Signature does not match the public key");
				}
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
			if (e instanceof InterruptedException) {
				Thread.currentThread().interrupt();
			}
			throw new JOSEException("External signer failed: " + e.getMessage(), e);
		}
	}
}
