package com.metadium.did.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;

import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;
import com.nimbusds.jose.util.Base64URL;

/**
 * ES256K {@link JWSSigner} that delegates the signature to an external key store through {@link DigestSigner}.
 * The digest is SHA-256 of the JWS signing input, and the signature is the 64 bytes (r || s) form required by JWS.
 */
public class ExternalJWSSigner extends BaseJWSProvider implements JWSSigner {
	private static final BigInteger HALF_CURVE_ORDER = Sign.CURVE_PARAMS.getN().shiftRight(1);

	private final DigestSigner signer;

	public ExternalJWSSigner(DigestSigner signer) {
		super(Collections.singleton(JWSAlgorithm.ES256K));
		if (signer == null) {
			throw new IllegalArgumentException("signer is required");
		}
		this.signer = signer;
	}

	@Override
	public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
		if (!JWSAlgorithm.ES256K.equals(header.getAlgorithm())) {
			throw new JOSEException("Unsupported algorithm: " + header.getAlgorithm());
		}
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(signingInput);
			byte[] raw = signer.signDigest(digest);
			if (raw == null || (raw.length != 64 && raw.length != 65)) {
				throw new JOSEException("External signer must return 64 (r||s) or 65 (r||s||v) bytes");
			}
			BigInteger r = new BigInteger(1, Arrays.copyOfRange(raw, 0, 32));
			BigInteger s = new BigInteger(1, Arrays.copyOfRange(raw, 32, 64));
			if (s.compareTo(HALF_CURVE_ORDER) > 0) {
				s = Sign.CURVE_PARAMS.getN().subtract(s);
			}
			byte[] concat = new byte[64];
			System.arraycopy(Numeric.toBytesPadded(r, 32), 0, concat, 0, 32);
			System.arraycopy(Numeric.toBytesPadded(s, 32), 0, concat, 32, 32);
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
