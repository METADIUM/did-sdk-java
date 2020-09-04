package com.metadium.did.crypto;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.SignatureException;

import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.crypto.Sign.SignatureData;
import org.web3j.utils.Numeric;

/**
 * Metadium wallet <p/>
 * 
 * Secp256k1
 * 
 * 
 * @author ybjeon
 *
 */
public class MetadiumKey implements MetadiumKeyImpl {
	private ECKeyPair ecKeyPair;
	
	public MetadiumKey(ECKeyPair ecKeyPair) {
		this.ecKeyPair = ecKeyPair;
	}
	
	public MetadiumKey() throws InvalidAlgorithmParameterException {
		this(ECKeyUtils.generateSecp256k1ECKeyPair());
	}

	@Override
	public SignatureData sign(byte[] message) {
		return Sign.signMessage(message, ecKeyPair);
	}

	@Override
	public boolean verify(byte[] message, SignatureData signature) throws SignatureException {
		return Sign.signedMessageToKey(message, signature).equals(ecKeyPair.getPublicKey());
	}

	@Override
	public String getAddress() {
		return Numeric.prependHexPrefix(Keys.getAddress(ecKeyPair));
	}

	@Override
	public BigInteger getPublicKey() {
		return ecKeyPair.getPublicKey();
	}
	
	public BigInteger getPrivateKey() {
		return ecKeyPair.getPrivateKey();
	}
}
