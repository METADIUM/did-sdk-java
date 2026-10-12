package com.metadium.did.crypto;

import java.math.BigInteger;
import java.util.Arrays;

import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Sign;

/**
 * Helpers to handle signatures returned by an external key store.
 */
public final class ExternalSignatureUtils {
	private static final BigInteger CURVE_ORDER = Sign.CURVE_PARAMS.getN();
	private static final BigInteger HALF_CURVE_ORDER = CURVE_ORDER.shiftRight(1);

	private ExternalSignatureUtils() {
	}

	/**
	 * Get r and s from the value returned by an external signer, and convert s to the canonical (low-s) form.
	 *
	 * Accepted forms: r||s (64 bytes), r||s||v (65 bytes) and ASN.1 DER (starts with 0x30, as returned by AWS KMS and Google Cloud KMS).
	 *
	 * @param raw signature returned by the external signer
	 * @return {r, s}
	 * @throws IllegalStateException if the form is not supported
	 */
	public static BigInteger[] parseRS(byte[] raw) {
		if (raw == null) {
			throw new IllegalStateException("External signer returned null");
		}

		BigInteger r;
		BigInteger s;
		if (raw.length == 64 || raw.length == 65) {
			r = new BigInteger(1, Arrays.copyOfRange(raw, 0, 32));
			s = new BigInteger(1, Arrays.copyOfRange(raw, 32, 64));
		}
		else if (raw.length > 8 && raw[0] == 0x30) {
			BigInteger[] rs = parseDer(raw);
			r = rs[0];
			s = rs[1];
		}
		else {
			throw new IllegalStateException("External signer must return r||s (64 bytes), r||s||v (65 bytes) or DER");
		}

		if (r.signum() <= 0 || r.compareTo(CURVE_ORDER) >= 0 || s.signum() <= 0 || s.compareTo(CURVE_ORDER) >= 0) {
			throw new IllegalStateException("External signer returned r or s out of range");
		}

		if (s.compareTo(HALF_CURVE_ORDER) > 0) {
			s = CURVE_ORDER.subtract(s);
		}
		return new BigInteger[] {r, s};
	}

	/**
	 * Convert a secp256k1 public key given by a key store to the form used by this SDK (X||Y as an integer).
	 *
	 * Accepted forms: X||Y (64 bytes), 0x04||X||Y (65 bytes), compressed (33 bytes) and X.509 SubjectPublicKeyInfo DER
	 * (as returned by AWS KMS and Google Cloud KMS GetPublicKey, which ends with the 65 bytes uncompressed point).
	 * The point must be on the curve.
	 *
	 * @throws IllegalArgumentException if the form is not supported or the point is not on the curve
	 */
	public static BigInteger toPublicKey(byte[] publicKey) {
		if (publicKey == null) {
			throw new IllegalArgumentException("publicKey is required");
		}

		byte[] point;
		if (publicKey.length == 64) {
			point = new byte[65];
			point[0] = 0x04;
			System.arraycopy(publicKey, 0, point, 1, 64);
		}
		else if (publicKey.length == 65 && publicKey[0] == 0x04) {
			point = publicKey;
		}
		else if (publicKey.length == 33 && (publicKey[0] == 0x02 || publicKey[0] == 0x03)) {
			point = publicKey;
		}
		else if (publicKey.length > 65 && publicKey[publicKey.length - 65] == 0x04) {
			point = Arrays.copyOfRange(publicKey, publicKey.length - 65, publicKey.length);
		}
		else {
			throw new IllegalArgumentException("Unsupported public key form");
		}

		// decodePoint throws IllegalArgumentException if the point is not on the curve
		byte[] encoded = Sign.CURVE_PARAMS.getCurve().decodePoint(point).getEncoded(false);
		return new BigInteger(1, Arrays.copyOfRange(encoded, 1, 65));
	}

	/**
	 * @throws IllegalArgumentException if the public key (X||Y as an integer) is not a point on the secp256k1 curve
	 */
	public static void validatePublicKey(BigInteger publicKey) {
		if (publicKey == null || publicKey.signum() <= 0 || publicKey.bitLength() > 512) {
			throw new IllegalArgumentException("Invalid public key");
		}
		byte[] xy = new byte[64];
		byte[] bytes = publicKey.toByteArray();
		int len = Math.min(bytes.length, 64);
		System.arraycopy(bytes, bytes.length - len, xy, 64 - len, len);
		toPublicKey(xy);
	}

	private static BigInteger[] parseDer(byte[] der) {
		// SEQUENCE { INTEGER r, INTEGER s }. A secp256k1 signature is at most 72 bytes, so lengths use the short form.
		int pos = 0;
		if (der[pos++] != 0x30 || (der[pos] & 0x80) != 0 || (der[pos++] & 0xff) != der.length - 2) {
			throw new IllegalStateException("Invalid DER signature");
		}
		BigInteger[] rs = new BigInteger[2];
		for (int i = 0; i < 2; i++) {
			if (pos + 2 > der.length || der[pos++] != 0x02) {
				throw new IllegalStateException("Invalid DER signature");
			}
			int len = der[pos++] & 0xff;
			if (len == 0 || len > 33 || pos + len > der.length) {
				throw new IllegalStateException("Invalid DER signature");
			}
			rs[i] = new BigInteger(1, Arrays.copyOfRange(der, pos, pos + len));
			pos += len;
		}
		if (pos != der.length) {
			throw new IllegalStateException("Invalid DER signature");
		}
		return rs;
	}

	/**
	 * Find the recovery id (0 or 1) with which the signature recovers to the public key.
	 *
	 * @return 0 or 1, or -1 if the signature was not made by the public key
	 */
	public static int findRecoveryId(BigInteger r, BigInteger s, byte[] digest, BigInteger publicKey) {
		ECDSASignature signature = new ECDSASignature(r, s);
		for (int recId = 0; recId < 2; recId++) {
			if (publicKey.equals(Sign.recoverFromSignature(recId, signature, digest))) {
				return recId;
			}
		}
		return -1;
	}
}
