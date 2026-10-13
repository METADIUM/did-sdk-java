package com.metadium.did;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.web3j.crypto.ECKeyPair;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.utils.Numeric;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.metadium.did.contract.IdentityRegistry;
import com.metadium.did.crypto.ECKeyUtils;
import com.metadium.did.crypto.ExternalMetadiumKey;
import com.metadium.did.crypto.MetadiumKey;
import com.metadium.did.crypto.MetadiumKeyImpl;
import com.metadium.did.exception.DidException;
import com.metadium.did.exception.DidPartialFailureException;
import com.metadium.did.exception.DidStep;
import com.metadium.did.protocol.JSONRPCException;
import com.metadium.did.protocol.MetaDelegator;
import com.metadium.did.util.Web3jUtils;
import com.metadium.did.wapper.NotSignTransactionManager;
import com.metadium.did.wapper.ZeroContractGasProvider;
import com.metadium.vc.Verifiable;
import com.metadium.vc.VerifiableCredential;
import com.metadium.vc.VerifiablePresentation;
import com.metaidum.did.resolver.client.DIDResolverAPI;
import com.metaidum.did.resolver.client.document.DidDocument;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Metadium DID.
 * 
 * Has key, did
 * 
 * @author ybjeon
 *
 */
public class MetadiumWallet {
	/** private key */
	private MetadiumKeyImpl key;
	
	/** did */
	private String did;
	
	private MetadiumWallet(MetadiumKeyImpl key) {
		this.key = key;
	}
	
	/**
	 * Wallet 생성
	 * @param did 생성된 DID
	 * @param key DID생성한 key
	 */
	public MetadiumWallet(String did, MetadiumKey key) {
		this.did = did;
		this.key = key;
	}
	
	/**
	 * Wallet 생성. 개인 키를 외부 키 보관 서비스가 가지는 경우에 사용
	 * @param did 생성된 DID
	 * @param key DID생성한 key. {@link com.metadium.did.crypto.ExternalMetadiumKey} 등
	 */
	public MetadiumWallet(String did, MetadiumKeyImpl key) {
		this.did = did;
		this.key = key;
	}
	
	/**
	 * Get wallet key
	 * @return key. null if the wallet has no key
	 * @throws UnsupportedOperationException if the private key is held by an external key store. Use {@link #getKeyImpl()}
	 */
	public MetadiumKey getKey() {
		if (key == null) {
			return null;
		}
		if (!(key instanceof MetadiumKey)) {
			throw new UnsupportedOperationException("The private key is held by an external key store. Use getKeyImpl()");
		}
		return (MetadiumKey)key;
	}
	
	/**
	 * Get key. 로컬 개인 키이거나 외부 키 보관 서비스를 쓰는 경우 모두 사용 가능
	 * @return
	 */
	public MetadiumKeyImpl getKeyImpl() {
		return key;
	}
	
	/**
	 * Create Did
	 * @param metaDelegator
	 * @return
	 * @throws DidException
	 */
	public static MetadiumWallet createDid(MetaDelegator metaDelegator) throws DidException {
		return createDid(metaDelegator, null);
	}
	
	/**
	 * create DID from key
	 * 
	 * @param metaDelegator {@link MetaDelegator}
	 * @param key 지갑 키
	 * @return 생성된 DID 지갑
	 * @throws DidException
	 */
	public static MetadiumWallet createDid(MetaDelegator metaDelegator, MetadiumKey key) throws DidException {
		return createDid(metaDelegator, (MetadiumKeyImpl)key);
	}
	
	/**
	 * create DID from key. 개인 키를 외부 키 보관 서비스가 가지는 경우에 사용
	 * 
	 * @param metaDelegator {@link MetaDelegator}
	 * @param key 지갑 키. {@link com.metadium.did.crypto.ExternalMetadiumKey} 등. null 이면 새 키를 생성
	 * @return 생성된 DID 지갑
	 * @throws DidException
	 */
	public static MetadiumWallet createDid(MetaDelegator metaDelegator, MetadiumKeyImpl key) throws DidException {
		MetadiumWallet metadiumDid;
		try {
			metadiumDid = new MetadiumWallet(key == null ? new MetadiumKey() : key);
		}
		catch (InvalidAlgorithmParameterException e) {
			throw new DidException(e);
		}
		
		List<String> completed = new ArrayList<String>();
		List<DidStep> steps = new ArrayList<DidStep>();
		try {
			String txHash = metaDelegator.createIdentityDelegated(metadiumDid.key);
			TransactionReceipt transactionReceipt = confirm(metaDelegator, txHash, "create DID", DidStep.Operation.CREATE_IDENTITY, DidStep.Target.CURRENT_KEY, steps);
			// The identity exists on-chain from here, even if the DID is not known yet (for example a bad event)
			completed.add("create_identity tx="+txHash);
			
			IdentityRegistry identityRegistry = IdentityRegistry.load(
					metaDelegator.getAllServiceAddress().identityRegistry,
					metaDelegator.getWeb3j(),
					new NotSignTransactionManager(metaDelegator.getWeb3j()),
					new ZeroContractGasProvider()
			);
			
			List<IdentityRegistry.IdentityCreatedEventResponse> responses = identityRegistry.getIdentityCreatedEvents(transactionReceipt);
			if (responses.size() == 0) {
				throw new DidException("Failed to create DID. bad event");
			}
			
			metadiumDid.did = metaDelegator.einToDid(responses.get(0).ein);
			
			String result = metaDelegator.addPublicKeyDelegated(metadiumDid.key, metadiumDid.key.getPublicKey());
			confirm(metaDelegator, result, "add public_key", DidStep.Operation.ADD_PUBLIC_KEY, DidStep.Target.CURRENT_KEY, steps);
			return metadiumDid;
		}
		catch (Exception e) {
			DidStep unconfirmed = unconfirmedStep(steps);
			if (completed.isEmpty() && unconfirmed == null) {
				// nothing was created
				throw e instanceof DidException ? (DidException)e : new DidException(e);
			}
			
			String didText = metadiumDid.did == null ? "" : " "+metadiumDid.did;
			if (unconfirmed != null) {
				// A transaction may still be mined, so the state is unknown. Do not undo anything.
				throw new DidPartialFailureException("Failed to create DID"+didText+". "+UNCONFIRMED_MESSAGE, e, metadiumDid.did, completed, Collections.singletonList("check "+unconfirmed), steps, new ArrayList<DidStep>());
			}
			
			// The identity exists on-chain without a public key. Remove the associated address as the compensation.
			List<String> unrecovered = new ArrayList<String>();
			List<DidStep> compensation = new ArrayList<DidStep>();
			try {
				confirm(metaDelegator, metaDelegator.removeAssociatedAddressDelegated(metadiumDid.key), "remove associated_key", DidStep.Operation.REMOVE_ASSOCIATED_ADDRESS, DidStep.Target.CURRENT_KEY, compensation);
			}
			catch (Exception re) {
				e.addSuppressed(re);
				unrecovered.add("remove associated_key");
			}
			// The identity itself (EIN) always remains on-chain; only its associated address can be removed.
			throw new DidPartialFailureException("Failed to create DID"+didText+". "+(unrecovered.isEmpty() ? "The associated address was removed. The identity remains on-chain." : "The identity remains on-chain without public_key and with its associated address."), e, metadiumDid.did, completed, unrecovered, steps, compensation);
		}
	}
	
	private static final String UNCONFIRMED_MESSAGE = "A transaction was submitted but its receipt could not be read, so its effect is unknown and nothing was rolled back.";
	
	/**
	 * Wait for the transaction and check that it succeeded. The step is added to {@code steps} with its status.
	 * 
	 * @return receipt
	 * @throws DidException if the transaction failed (reverted), or if it was submitted but the receipt could not be read
	 *                      (timeout, network error): the transaction may still be mined, see {@link DidStep.Status#SUBMITTED_UNCONFIRMED}
	 */
	private static TransactionReceipt confirm(MetaDelegator metaDelegator, String txHash, String what, DidStep.Operation operation, DidStep.Target target, List<DidStep> steps) throws DidException {
		TransactionReceipt transactionReceipt;
		try {
			transactionReceipt = Web3jUtils.ethGetTransactionReceipt(metaDelegator.getWeb3j(), txHash);
		}
		catch (IOException e) {
			steps.add(new DidStep(operation, target, txHash, DidStep.Status.SUBMITTED_UNCONFIRMED));
			throw new DidException("The transaction to "+what+" was submitted but not confirmed. tx is "+txHash, e);
		}
		if (!transactionReceipt.getStatus().equals("0x1")) {
			steps.add(new DidStep(operation, target, txHash, DidStep.Status.FAILED));
			throw new DidException("Failed to "+what+". tx is "+transactionReceipt.getTransactionHash());
		}
		steps.add(new DidStep(operation, target, txHash, DidStep.Status.CONFIRMED));
		return transactionReceipt;
	}
	
	/** The step that was submitted but not confirmed, or null */
	private static DidStep unconfirmedStep(List<DidStep> steps) {
		for (DidStep step : steps) {
			if (step.getStatus() == DidStep.Status.SUBMITTED_UNCONFIRMED) {
				return step;
			}
		}
		return null;
	}
	
	/**
	 * DID 가 블럭체인상에 존재하는지 확인
	 * @param metaDelegator		{@link MetaDelegator}
	 * @return 존재하는 경우 true
	 * @throws DidException
	 * @throws Exception
	 */
	public boolean existsDid(MetaDelegator metaDelegator) throws DidException, Exception {
        IdentityRegistry identityRegistry = IdentityRegistry.load(
                metaDelegator.getAllServiceAddress().identityRegistry,
                metaDelegator.getWeb3j(),
                new NotSignTransactionManager(metaDelegator.getWeb3j()),
                new ZeroContractGasProvider()
        );
        
        try {
	        return identityRegistry.hasIdentity(key.getAddress()).send();
        }
        catch (Exception e) {
        	throw new IOException(e);
        }
	}
	
	/**
	 * 서비스 키 추가
	 * 
	 * @param metaDelegator     {@link MetaDelegator}
	 * @param serviceId         추가할 서비스의 ID
	 * @param serviceKeyAddress 추가할 서비스 키의 address
	 * @return 키 추가한 transaction hash
	 * @throws DidException
	 */
	public String addServiceKey(MetaDelegator metaDelegator, String serviceId, String serviceKeyAddress) throws DidException {
		try {
			String txHash = metaDelegator.addKeyDelegated(key, serviceId, serviceKeyAddress);
			TransactionReceipt transactionReceipt = Web3jUtils.ethGetTransactionReceipt(metaDelegator.getWeb3j(), txHash);
			if (transactionReceipt.getStatus().equals("0x1")) {
				return txHash;
			}
			throw new DidException("Failed to add service key. tx is "+transactionReceipt.getTransactionHash());
		}
		catch (Exception e) {
			throw new DidException(e);
		}
	}
	
	/**
	 *서비스 키 삭제
	 *
	 * @param metaDelegator     {@link MetaDelegator}
	 * @param serviceId         삭제할 서비스의 ID
	 * @param serviceKeyAddress 삭제할 서비스 키의 address
	 * @return 키 삭제한 transaction hash
	 * @throws DidException
	 */
	public String removeServiceKey(MetaDelegator metaDelegator, String serviceId, String serviceKeyAddress) throws DidException {
		try {
			String txHash = metaDelegator.removeKeyDelegated(key, serviceId, serviceKeyAddress);
			TransactionReceipt transactionReceipt = Web3jUtils.ethGetTransactionReceipt(metaDelegator.getWeb3j(), txHash);
			if (transactionReceipt.getStatus().equals("0x1")) {
				return txHash;
			}
			throw new DidException("Failed to remove service key. tx is "+transactionReceipt.getTransactionHash());
		}
		catch (Exception e) {
			throw new DidException(e);
		}
	}
	
	/**
	 * 모든 서비스 키를 삭제한다.
	 * @param metaDelegator {@link MetaDelegator}
	 * @return 키 삭제한 transaction hash
	 * @throws DidException
	 */
	public String removeAllServiceKey(MetaDelegator metaDelegator) throws DidException {
		try {
			String txHash = metaDelegator.removeKeysDelegated(key);
			TransactionReceipt transactionReceipt = Web3jUtils.ethGetTransactionReceipt(metaDelegator.getWeb3j(), txHash);
			if (transactionReceipt.getStatus().equals("0x1")) {
				return txHash;
			}
			throw new DidException("Failed to remove all service key. tx is "+transactionReceipt.getTransactionHash());
		}
		catch (Exception e) {
			throw new DidException(e);
		}
	}
	
	/**
	 * update key.<p/>
	 * associatedKey 와 publicKey 를 지정한 키로 변경한다.
	 * 
	 * @param metaDelegator {@link MetaDelegator}
	 * @param newKey        변경한 키
	 * @return block number 변경한 transaction 의 block number
	 * @throws DidException
	 */
	public BigInteger updateKeyOfDid(MetaDelegator metaDelegator, MetadiumKey newKey) throws DidException {
		return updateKeyOfDid(metaDelegator, (MetadiumKeyImpl)newKey);
	}
	
	/**
	 * update key. 새 키를 외부 키 보관 서비스가 가지는 경우에 사용
	 * 
	 * @param metaDelegator {@link MetaDelegator}
	 * @param newKey        변경한 키
	 * @return block number 변경한 transaction 의 block number
	 * @throws DidException
	 */
	public BigInteger updateKeyOfDid(MetaDelegator metaDelegator, MetadiumKeyImpl newKey) throws DidException {
		final String addAssociated = "add associated_key of new key";
		final String addPublic = "add public_key of new key";
		final String removeOldPublic = "remove public_key of old key";
		
		List<String> completed = new ArrayList<String>();
		List<DidStep> steps = new ArrayList<DidStep>();
		try {
			// add associated address
			String txHash = metaDelegator.addAssociatedAddressDelegated(key, newKey);
			confirm(metaDelegator, txHash, "add associated_key", DidStep.Operation.ADD_ASSOCIATED_ADDRESS, DidStep.Target.NEW_KEY, steps);
			completed.add(addAssociated+" tx="+txHash);
			
			// add public key
			txHash = metaDelegator.addPublicKeyDelegated(newKey, newKey.getPublicKey());
			confirm(metaDelegator, txHash, "add public_key", DidStep.Operation.ADD_PUBLIC_KEY, DidStep.Target.NEW_KEY, steps);
			completed.add(addPublic+" tx="+txHash);
			
			// remove old public key
			txHash = metaDelegator.removePublicKeyDelegated(key);
			confirm(metaDelegator, txHash, "remove old public_key", DidStep.Operation.REMOVE_PUBLIC_KEY, DidStep.Target.CURRENT_KEY, steps);
			completed.add(removeOldPublic+" tx="+txHash);
			
			// remove old associated address
			txHash = metaDelegator.removeAssociatedAddressDelegated(key);
			TransactionReceipt transactionReceipt = confirm(metaDelegator, txHash, "remove old associated_key", DidStep.Operation.REMOVE_ASSOCIATED_ADDRESS, DidStep.Target.CURRENT_KEY, steps);
			key = newKey;
			return transactionReceipt.getBlockNumber();
		}
		catch (Exception e) {
			DidStep unconfirmed = unconfirmedStep(steps);
			if (completed.isEmpty() && unconfirmed == null) {
				throw e instanceof DidException ? (DidException)e : new DidException(e);
			}
			
			if (unconfirmed != null) {
				// A transaction may still be mined, so the state is unknown. Undoing the other steps could make it worse.
				throw new DidPartialFailureException("Failed to update key of "+did+". "+UNCONFIRMED_MESSAGE, e, did, completed, Collections.singletonList("check "+unconfirmed), steps, new ArrayList<DidStep>());
			}
			
			// compensation. Every step is tried even if the previous one failed, for both a failed transaction and an exception of the signer.
			List<String> unrecovered = new ArrayList<String>();
			List<DidStep> compensation = new ArrayList<DidStep>();
			if (completedStep(completed, removeOldPublic)) {
				try {
					confirm(metaDelegator, metaDelegator.addPublicKeyDelegated(key, key.getPublicKey()), "restore public_key of old key", DidStep.Operation.ADD_PUBLIC_KEY, DidStep.Target.CURRENT_KEY, compensation);
				}
				catch (Exception re) {
					e.addSuppressed(re);
					unrecovered.add("restore public_key of old key");
				}
			}
			if (completedStep(completed, addPublic)) {
				try {
					confirm(metaDelegator, metaDelegator.removePublicKeyDelegated(newKey), "remove public_key of new key", DidStep.Operation.REMOVE_PUBLIC_KEY, DidStep.Target.NEW_KEY, compensation);
				}
				catch (Exception re) {
					e.addSuppressed(re);
					unrecovered.add("remove public_key of new key");
				}
			}
			if (completedStep(completed, addAssociated)) {
				try {
					confirm(metaDelegator, metaDelegator.removeAssociatedAddressDelegated(newKey), "remove associated_key of new key", DidStep.Operation.REMOVE_ASSOCIATED_ADDRESS, DidStep.Target.NEW_KEY, compensation);
				}
				catch (Exception re) {
					e.addSuppressed(re);
					unrecovered.add("remove associated_key of new key");
				}
			}
			throw new DidPartialFailureException("Failed to update key of "+did+". "+(unrecovered.isEmpty() ? "The completed steps were rolled back." : "Some completed steps could not be rolled back."), e, did, completed, unrecovered, steps, compensation);
		}
	}
	
	private static boolean completedStep(List<String> completed, String step) {
		for (String c : completed) {
			if (c.startsWith(step)) {
				return true;
			}
		}
		return false;
	}
	
	
	/**
	 * update key. 소유하지 않는 키를 추가 할때 사용하며 키 소유자에게서 추가할 키의 public key 와 서명값을 전달 받아야 한다.
	 * 
	 * @param metaDelegator delegator
	 * @param newPublicKey  변경할 키쌍의 공개키
	 * @param signature     변경할 키쌍의 개인키로 서명한 값. {@link MetaDelegator#signAddAssocatedKeyDelegate(String, com.metadium.did.crypto.MetadiumKeyImpl)}
	 * @return 키가 변경된 transaction 의 block number
	 * @throws DidException
	 */
	public BigInteger updateKeyOfDid(MetaDelegator metaDelegator, BigInteger newPublicKey, String signature) throws DidException {
		if (signature.length() < 260) {
			throw new DidException("Invalid signature");
		}
		
		try {
			// add associated address.
			String txHash = metaDelegator.addAssociatedAddressDelegated(key, newPublicKey, signature.substring(0, 130)+signature.substring(260));
			TransactionReceipt transactionReceipt = Web3jUtils.ethGetTransactionReceipt(metaDelegator.getWeb3j(), txHash);
			if (transactionReceipt.getStatus().equals("0x1")) {
				// add public key
				txHash = metaDelegator.addPublicKeyDelegated(newPublicKey, signature.substring(130, 260)+signature.substring(260));
				transactionReceipt = Web3jUtils.ethGetTransactionReceipt(metaDelegator.getWeb3j(), txHash);
				if (transactionReceipt.getStatus().equals("0x1")) {
					// remove old public key
					txHash = metaDelegator.removePublicKeyDelegated(key);
					transactionReceipt = Web3jUtils.ethGetTransactionReceipt(metaDelegator.getWeb3j(), txHash);
					if (transactionReceipt.getStatus().equals("0x1")) {
						// remove old associated address
						txHash = metaDelegator.removeAssociatedAddressDelegated(key);
						transactionReceipt = Web3jUtils.ethGetTransactionReceipt(metaDelegator.getWeb3j(), txHash);
						if (transactionReceipt.getStatus().equals("0x1")) {
							key = null;
							return transactionReceipt.getBlockNumber();
						}
						else {
							throw new DidException("Failed to remove old associated_key. tx is "+transactionReceipt.getTransactionHash());
						}
					}
					else {
						throw new DidException("Failed to remove old public_key. tx is "+transactionReceipt.getTransactionHash());
					}
				}
				else {
					throw new DidException("Failed to add public_key. tx is "+transactionReceipt.getTransactionHash());
				}
			}
			else {
				throw new DidException("Failed to add associated_key. tx is "+transactionReceipt.getTransactionHash());
			}
		} catch (Exception e) {
			throw new DidException(e);
		}
	}
	
	/**
	 * did 삭제
	 * 
	 * @param metaDelegator
	 * @throws DidException
	 */
	public void deleteDid(MetaDelegator metaDelegator) throws DidException {
		List<String> completed = new ArrayList<String>();
		List<DidStep> steps = new ArrayList<DidStep>();
		try {
			String txHash = metaDelegator.removePublicKeyDelegated(key);
			confirm(metaDelegator, txHash, "delete public_key for delete did", DidStep.Operation.REMOVE_PUBLIC_KEY, DidStep.Target.CURRENT_KEY, steps);
			completed.add("remove public_key tx="+txHash);
			
			txHash = metaDelegator.removeAssociatedAddressDelegated(key);
			confirm(metaDelegator, txHash, "delete associated_key for delete did", DidStep.Operation.REMOVE_ASSOCIATED_ADDRESS, DidStep.Target.CURRENT_KEY, steps);
		}
		catch (Exception e) {
			DidStep unconfirmed = unconfirmedStep(steps);
			if (completed.isEmpty() && unconfirmed == null) {
				throw new DidException("Failed to delete did.", e);
			}
			if (unconfirmed != null) {
				throw new DidPartialFailureException("Failed to delete did. "+UNCONFIRMED_MESSAGE, e, did, completed, Collections.singletonList("check "+unconfirmed), steps, new ArrayList<DidStep>());
			}
			throw new DidPartialFailureException("Failed to delete did. The public_key was removed but the associated_key remains.", e, did, completed, Collections.singletonList("remove associated_key"), steps, new ArrayList<DidStep>());
		}
	}
	
	/**
	 * Get did
	 * @return
	 */
	public String getDid() {
		return did;
	}
	
	/**
	 * Get key id
	 * @return
	 */
	public String getKid() {
		return did+"#MetaManagementKey#"+Numeric.cleanHexPrefix(key.getAddress());
	}
	
	/**
	 * Sign verifiable credential, presentation
	 * 
	 * @param verifiable to sign
	 * @param claimsSet to additional claims
	 * @return
	 * @throws JOSEException
	 */
	public SignedJWT sign(Verifiable verifiable, JWTClaimsSet claimsSet) throws JOSEException {
		requireKey();
		if (key instanceof ExternalMetadiumKey) {
			// the private key is held by an external key store
			return sign(verifiable, claimsSet, ((ExternalMetadiumKey)key).getJWSSigner());
		}
		return signWithSigner(verifiable, claimsSet, new ECDSASigner(getKey().getECPrivateKey()));
	}
	
	/**
	 * Sign verifiable credential, presentation with the given signer. 개인 키를 외부 키 보관 서비스가 가지는 경우에 사용
	 * 
	 * @param verifiable to sign
	 * @param claimsSet to additional claims
	 * @param signer ES256K JWS signer. {@link com.metadium.did.crypto.ExternalJWSSigner} 등
	 * @return signed JWT. The signature is verified with the public key of this wallet
	 * @throws JOSEException if signing failed or the signature was not made by the key of this wallet
	 */
	public SignedJWT sign(Verifiable verifiable, JWTClaimsSet claimsSet, JWSSigner signer) throws JOSEException {
		requireKey();
		SignedJWT jwt = signWithSigner(verifiable, claimsSet, signer);
		
		// kid points to the key of this wallet. Do not issue a credential that is signed by another key.
		ECDSAVerifier verifier = new ECDSAVerifier(ECKeyUtils.getPublicKey("04"+Numeric.toHexStringNoPrefixZeroPadded(key.getPublicKey(), 128)));
		verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		if (!jwt.verify(verifier)) {
			throw new JOSEException("The signature was not made by the key of this wallet. kid is "+getKid());
		}
		return jwt;
	}
	
	/**
	 * @throws JOSEException if the wallet has no key, for example after {@link #updateKeyOfDid(MetaDelegator, BigInteger, String)}
	 */
	private void requireKey() throws JOSEException {
		if (key == null) {
			throw new JOSEException("The wallet has no key");
		}
	}
	
	private SignedJWT signWithSigner(Verifiable verifiable, JWTClaimsSet claimsSet, JWSSigner signer) throws JOSEException {
		if (verifiable instanceof VerifiableCredential) {
			((VerifiableCredential)verifiable).setIssuer(URI.create(getDid()));
		}
		else if (verifiable instanceof VerifiablePresentation) {
			((VerifiablePresentation)verifiable).setHolder(URI.create(getDid()));
		}
		// nonce 생성
		byte[] nonce = new byte[32];
		new SecureRandom().nextBytes(nonce);
		return verifiable.sign(JWSAlgorithm.ES256K, getKid(), Base64.getEncoder().encodeToString(nonce), signer, claimsSet);
	}
	
	/**
	 * Issue verifiable credential
	 * 
	 * @param types credential types. "NameCredential", "IDCredential" ... See <a href="https://www.w3.org/TR/vc-data-model/#types">Types</a>
	 * @param id ID of credential. Nullable. See <a href="https://www.w3.org/TR/vc-data-model/#identifiers">Identifiers</a>
	 * @param issuanceDate issuance date of credential. Nullable. See <a href="https://www.w3.org/TR/vc-data-model/#issuance-date"></a>
	 * @param expirationDate expiration date of credential. Nullable. See <a href="https://www.w3.org/TR/vc-data-model/#expiration"></a>
	 * @param ownerDid did of owner of credential. See <a href="https://www.w3.org/TR/vc-data-model/#identifiers">Identifiers</a>
	 * @param subjects subjects of credential. See <a href="https://www.w3.org/TR/vc-data-model/#credential-subject">Credential Subjects</a>
	 * @return Signed verifiable credential. See <a href="https://www.w3.org/TR/vc-data-model/#json-web-token">JWT formats</a>
	 * @throws JOSEException
	 */
	public SignedJWT issueCredential(Collection<String> types, URI id, Date issuanceDate, Date expirationDate, String ownerDid, Map<String, Object> subjects) throws JOSEException {
		return issueCredential(types, id, issuanceDate, expirationDate, ownerDid, subjects, null);
	}
	
	/**
	 * Issue verifiable credential with the given signer. 개인 키를 외부 키 보관 서비스가 가지는 경우에 사용
	 * 
	 * @param signer ES256K JWS signer. null 이면 로컬 개인 키로 서명
	 * @see #issueCredential(Collection, URI, Date, Date, String, Map)
	 */
	public SignedJWT issueCredential(Collection<String> types, URI id, Date issuanceDate, Date expirationDate, String ownerDid, Map<String, Object> subjects, JWSSigner signer) throws JOSEException {
		VerifiableCredential vc = new VerifiableCredential();
		vc.addTypes(types);
		if (id != null) {
			vc.setId(id);
		}
		if (issuanceDate != null) {
			vc.setIssuanceDate(issuanceDate);
		}
		if (expirationDate != null) {
			vc.setExpirationDate(expirationDate);
		}
		Map<String, Object> clonedSubjects = new LinkedHashMap<String, Object>(subjects);
		clonedSubjects.put("id", ownerDid);
		vc.setCredentialSubject(clonedSubjects);
		return signWith(vc, null, signer);
	}
	
	/**
	 * Issue verifiable presentation
	 * 
	 * @param types types of presentation. "CustomPresentation", ... See <a href="https://www.w3.org/TR/vc-data-model/#types">Types</a>
	 * @param id ID of presentation. Nullable. See <a href="https://www.w3.org/TR/vc-data-model/#identifiers">Identifiers</a>
	 * @param issuanceDate issuance date of presentation. Nullable. See <a href="https://www.w3.org/TR/vc-data-model/#issuance-date"></a>
	 * @param expirationDate expiration date of presentation. Nullable. See <a href="https://www.w3.org/TR/vc-data-model/#expiration"></a>
	 * @param vcList list of JSON web token to serialized. See <a href="https://www.w3.org/TR/vc-data-model/#example-29-verifiable-credential-using-jwt-compact-serialization-non-normative">Example</a>
	 * @return Signed verifiable presentation. See <a href="https://www.w3.org/TR/vc-data-model/#json-web-token">JWT formats</a>
	 * @throws JOSEException
	 */
	public SignedJWT issuePresentation(Collection<String> types, URI id, Date issuanceDate, Date expirationDate, Collection<String> vcList) throws JOSEException {
		return issuePresentation(types, id, issuanceDate, expirationDate, vcList, null);
	}
	
	/**
	 * Issue verifiable presentation with the given signer. 개인 키를 외부 키 보관 서비스가 가지는 경우에 사용
	 * 
	 * @param signer ES256K JWS signer. null 이면 로컬 개인 키로 서명
	 * @see #issuePresentation(Collection, URI, Date, Date, Collection)
	 */
	public SignedJWT issuePresentation(Collection<String> types, URI id, Date issuanceDate, Date expirationDate, Collection<String> vcList, JWSSigner signer) throws JOSEException {
		VerifiablePresentation vp = new VerifiablePresentation();
		vp.addTypes(types);
		if (id != null) {
			vp.setId(id);
		}
		for (String vc : vcList) {
			vp.addVerifiableCredential(vc);
		}
		JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder();
		if (issuanceDate != null) {
			claims.notBeforeTime(issuanceDate);
			claims.issueTime(issuanceDate);
		}
		if (expirationDate != null) {
			claims.expirationTime(expirationDate);
		}
		
		return signWith(vp, claims.build(), signer);
	}
	
	private SignedJWT signWith(Verifiable verifiable, JWTClaimsSet claimsSet, JWSSigner signer) throws JOSEException {
		return signer == null ? sign(verifiable, claimsSet) : sign(verifiable, claimsSet, signer);
	}
	
	/**
	 * 
	 * @see #sign(Verifiable, JWTClaimsSet)
	 * @param verifiable
	 * @return
	 * @throws JOSEException
	 */
	public SignedJWT sign(Verifiable verifiable) throws JOSEException {
		return sign(verifiable, null);
	}
	
	/**
	 * Get DID document from resolver
	 *  
	 * @return
	 * @throws IOException
	 */
	public DidDocument getDidDocument() throws IOException {
		return DIDResolverAPI.getInstance().requestDocument(getDid(), false).getDidDocument();
	}
	
	/**
	 * to json string. 
	 * 
	 * <pre>
	 * {@code
	 * 	{"did":"meta:did:0000...ea43", "private_key":"3d3ac083d.." }
	 * }
	 * </pre>
	 * 
	 * @return
	 */
	public String toJson() {
		JsonObject object = new JsonObject();
		object.addProperty("did", did);
		object.addProperty("private_key", Numeric.toHexStringNoPrefixZeroPadded(getKey().getPrivateKey(), 64));
		return object.toString();
	}
	
	/**
	 * from json string to object.
	 * 
	 * @param json
	 * @return
	 * @throws ParseException
	 */
	public static MetadiumWallet fromJson(String json) throws ParseException {
		JsonElement element = new JsonParser().parse(json);
		if (!element.isJsonObject()) {
			throw new ParseException("Not object", 0);
		}
		
		JsonObject object = element.getAsJsonObject();
		String did = object.get("did").getAsString();
		BigInteger privateKey = Numeric.toBigInt(object.get("private_key").getAsString());
		
		return new MetadiumWallet(did, new MetadiumKey(ECKeyPair.create(privateKey)));
	}
}
