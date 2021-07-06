package com.metadium.did;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Base64;
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
import com.metadium.did.crypto.MetadiumKey;
import com.metadium.did.exception.DidException;
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
import com.nimbusds.jose.crypto.ECDSASigner;
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
	private MetadiumKey key;
	
	/** did */
	private String did;
	
	private MetadiumWallet(MetadiumKey key) {
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
	 * Get wallet
	 * @return
	 */
	public MetadiumKey getKey() {
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
		try {
			MetadiumWallet metadiumDid = new MetadiumWallet(key == null ? new MetadiumKey() : key);
			
			String txHash = metaDelegator.createIdentityDelegated(metadiumDid.key);
			TransactionReceipt transactionReceipt = Web3jUtils.ethGetTransactionReceipt(metaDelegator.getWeb3j(), txHash);
			
			if (transactionReceipt.getStatus().equals("0x1")) {
		        IdentityRegistry identityRegistry = IdentityRegistry.load(
		                metaDelegator.getAllServiceAddress().identityRegistry,
		                metaDelegator.getWeb3j(),
		                new NotSignTransactionManager(metaDelegator.getWeb3j()),
		                new ZeroContractGasProvider()
		        );
				
		        List<IdentityRegistry.IdentityCreatedEventResponse> responses = identityRegistry.getIdentityCreatedEvents(transactionReceipt);
	            if(responses.size() > 0){
	            	metadiumDid.did = metaDelegator.einToDid(responses.get(0).ein);
	                
	                String result = metaDelegator.addPublicKeyDelegated(metadiumDid.key, metadiumDid.key.getPublicKey());
	                TransactionReceipt addPublicReceipt = Web3jUtils.ethGetTransactionReceipt(metaDelegator.getWeb3j(), result);
	                if(addPublicReceipt.getStatus().equals("0x1")){
	                    return metadiumDid;
	                }
	                else {
	                	throw new DidException("Failed to add public_key. tx is "+addPublicReceipt.getTransactionHash());
	                }
	            }
	            else {
	            	throw new DidException("Failed to create DID. bad event");
	            }
			}
			else {
				throw new DidException("Failed to create DID. tx is "+transactionReceipt.getTransactionHash());
			}
		}
		catch (IOException | JSONRPCException | InvalidAlgorithmParameterException e) {
			throw new DidException(e);
		}
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
			String txHash = metaDelegator.addKeyDelegated(this.getKey(), serviceId, serviceKeyAddress);
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
			String txHash = metaDelegator.removeKeyDelegated(this.getKey(), serviceId, serviceKeyAddress);
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
			String txHash = metaDelegator.removeKeysDelegated(this.getKey());
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
		try {
			// add associated address
			String txHash = metaDelegator.addAssociatedAddressDelegated(key, newKey);
			TransactionReceipt transactionReceipt = Web3jUtils.ethGetTransactionReceipt(metaDelegator.getWeb3j(), txHash);
			if (transactionReceipt.getStatus().equals("0x1")) {
				// add public key
				txHash = metaDelegator.addPublicKeyDelegated(newKey, newKey.getPublicKey());
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
							key = newKey;
							return transactionReceipt.getBlockNumber();
						}
						else {
							metaDelegator.addPublicKeyDelegated(key, key.getPublicKey());
							metaDelegator.removePublicKeyDelegated(newKey);
							metaDelegator.removeAssociatedAddressDelegated(newKey);
							
							throw new DidException("Failed to remove old associated_key. tx is "+transactionReceipt.getTransactionHash());
						}
					}
					else {
						metaDelegator.removePublicKeyDelegated(newKey);
						metaDelegator.removeAssociatedAddressDelegated(newKey);
						
						throw new DidException("Failed to remove old public_key. tx is "+transactionReceipt.getTransactionHash());
					}
				}
				else {
					txHash = metaDelegator.removeAssociatedAddressDelegated(newKey);
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
		try {
			String txHash = metaDelegator.removePublicKeyDelegated(key);
			TransactionReceipt transactionReceipt = Web3jUtils.ethGetTransactionReceipt(metaDelegator.getWeb3j(), txHash);
			if (transactionReceipt.getStatus().equals("0x1")) {
				txHash = metaDelegator.removeAssociatedAddressDelegated(key);
				transactionReceipt = Web3jUtils.ethGetTransactionReceipt(metaDelegator.getWeb3j(), txHash);
				if (transactionReceipt.getStatus().equals("0x1")) {
					return;
				}
				else {
					throw new DidException("Failed to delete associated_key for delete did. tx is "+transactionReceipt.getTransactionHash());
				}
			}
			else {
				throw new DidException("Failed to delete public_key for delete did. tx is "+transactionReceipt.getTransactionHash());
			}
			
		} catch (Exception e) {
			throw new DidException("Failed to delete did.");
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
		if (verifiable instanceof VerifiableCredential) {
			((VerifiableCredential)verifiable).setIssuer(URI.create(getDid()));
		}
		else if (verifiable instanceof VerifiablePresentation) {
			((VerifiablePresentation)verifiable).setHolder(URI.create(getDid()));
		}
		// nonce 생성
		byte[] nonce = new byte[32];
		new SecureRandom().nextBytes(nonce);
		return verifiable.sign(getKid(), Base64.getEncoder().encodeToString(nonce), new ECDSASigner(key.getECPrivateKey()), claimsSet);
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
		return sign(vc, null);
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
		
		return sign(vp, claims.build());
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
		object.addProperty("private_key", Numeric.toHexStringNoPrefixZeroPadded(key.getPrivateKey(), 64));
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
