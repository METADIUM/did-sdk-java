package com.metadium.did.wapper;

import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameter;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthGetCode;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.tx.TransactionManager;

import java.io.IOException;
import java.math.BigInteger;

/**
 * Non-sign transaction manager.<br>
 * only getting
 */
public class NotSignTransactionManager extends TransactionManager {
	private Web3j web3j;
	
    public NotSignTransactionManager(Web3j web3j) {
        super(web3j, null);
        this.web3j = web3j;
    }

    @Override
    public EthSendTransaction sendTransaction(BigInteger gasPrice, BigInteger gasLimit, String to, String data, BigInteger value) throws IOException {
    	return null;
    }

	@Override
	public EthSendTransaction sendTransaction(BigInteger gasPrice, BigInteger gasLimit, String to, String data,
			BigInteger value, boolean constructor) throws IOException {
		return null;
	}

	@Override
	public EthSendTransaction sendTransactionEIP1559(BigInteger gasPremium, BigInteger feeCap, BigInteger gasLimit,
			String to, String data, BigInteger value, boolean constructor) throws IOException {
		return null;
	}

	@Override
	public String sendCall(String to, String data, DefaultBlockParameter defaultBlockParameter) throws IOException {
		return web3j.ethCall(Transaction.createEthCallTransaction(getFromAddress(), to, data), defaultBlockParameter).send().getValue();
	}

	@Override
	public EthGetCode getCode(String contractAddress, DefaultBlockParameter defaultBlockParameter) throws IOException {
		return web3j.ethGetCode(contractAddress, defaultBlockParameter).send();
	}
}
