package com.metadium.did.crypto;

import java.math.BigInteger;
import java.security.SignatureException;

import org.web3j.crypto.Sign;
import org.web3j.crypto.Sign.SignatureData;

/**
 * Metadium key interface
 * 
 * @author ybjeon
 *
 */
public interface MetadiumKeyImpl {
	/**
	 * sign message
	 * @param message to sign
	 * @return signature
	 */
	Sign.SignatureData sign(byte[] message);
	
	/**
	 * verify to message
	 * @param message   to verify
	 * @param signature to verify
	 * @return signature
	 * @throws SignatureException
	 */
	boolean verify(byte[] message, SignatureData signature) throws SignatureException;
	
	/**
	 * Get address
	 * @return address
	 */
	String getAddress();
	
	/**
	 * Get public key
	 * @return public key
	 */
	BigInteger getPublicKey();
}
