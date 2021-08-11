package com.metadium.did.protocol;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.DefaultBlockParameterNumber;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.Response;
import org.web3j.protocol.http.HttpService;
import org.web3j.tuples.generated.Tuple4;
import org.web3j.tx.ReadonlyTransactionManager;
import org.web3j.utils.Numeric;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.metadium.did.MetadiumWallet;
import com.metadium.did.contract.IdentityRegistry;
import com.metadium.did.contract.PublicKeyResolver;
import com.metadium.did.crypto.MetadiumKeyImpl;
import com.metadium.did.exception.DidException;
import com.metadium.did.protocol.data.RegistryAddress;
import com.metadium.did.util.Bytes;
import com.metadium.did.util.IdentityRegistryHelper;
import com.metadium.did.util.NumericUtils;
import com.metadium.did.wapper.NotSignTransactionManager;
import com.metadium.did.wapper.ZeroContractGasProvider;

import okhttp3.OkHttpClient;

/**
 * Client of Metadium Proxy server<br>
 * default test-net url is https://testdelegator.metadium.com<br/>
 * https://drive.google.com/open?id=1p5sOaJVfuelJ8ifgk4-De3zL0trnRXQo
 */
public class MetaDelegator {
    private static final String MAINNET_PROXY_URL = "https://delegator.metadium.com";

    private static final String METHOD_GET_ALL_SERVICE_ADDRESSES = "get_all_service_addresses";

    private HttpService httpService;

    private RegistryAddress registryAddress;

    private Web3j web3j;
    
    private String delegatorUrl;
    
    private String didPrefix;
    
    
    /**
     * create delegator.
     *
     * @param delegatorUrl delegator server url
     * @param nodeUrl      node url
     * @param didPrefix    did prefix. did:meta, did:meta:testnet, did:meta:enterprise ...
     * @param apiKey       apiKey. default "unknown"
     */
    public MetaDelegator(String delegatorUrl, String nodeUrl, String didPrefix, String apiKey) {
    	this.delegatorUrl = delegatorUrl;
    	
        web3j = Web3jBuilder.build(nodeUrl);

        OkHttpClient.Builder builder = new OkHttpClient.Builder();

        httpService = new HttpService(delegatorUrl, builder.build(), false);
        httpService.addHeader("API-KEY", apiKey == null || apiKey.length() == 0 ? "UNKOWN" : apiKey);
        
        this.didPrefix = didPrefix;
    }
    
    /**
     * create delegator.
     * 
     * @see MetaDelegator#MetaDelegator(String, String, String, String)
     *
     */
    public MetaDelegator(String delegatorUrl, String nodeUrl, String didPrefix) {
    	this(delegatorUrl, nodeUrl, didPrefix, null);
    }
    
    @Deprecated
    public MetaDelegator(String delegatorUrl, String nodeUrl) {
    	this(delegatorUrl, nodeUrl, MAINNET_PROXY_URL.equals(delegatorUrl) ? "did:meta" : "did:meta:testnet");
    }
    
    public MetaDelegator(String apiKey) {
    	this(MAINNET_PROXY_URL, Web3jBuilder.MAINNET_NODE_URL, "did:meta", apiKey);
    }

    public MetaDelegator() {
        this(null);
    }
    
    @SuppressWarnings("unused")
	@Deprecated
    private boolean isMainNet() {
    	return MAINNET_PROXY_URL.equals(delegatorUrl);
    }

    /**
     * Convert EIN to DID
     * @param ein
     * @return
     */
    public String einToDid(BigInteger ein) {
        return didPrefix+":"+Numeric.toHexStringNoPrefixZeroPadded(ein, 64);
    }

    /**
     * Get current Web3j
     * @return Web3j
     */
    public Web3j getWeb3j() {
        return web3j;
    }

    /**
     * Get System registry address
     *
     * @return registry address
     * @throws DidException 
     */
    @SuppressWarnings("unchecked")
    public RegistryAddress getAllServiceAddress() throws DidException {
        if (registryAddress != null) {
            return registryAddress;
        }

        try {
            @SuppressWarnings("rawtypes")
			Response<Map> response = new Request(METHOD_GET_ALL_SERVICE_ADDRESSES, null, httpService, Response.class).send();
            if (response.getError() == null) {
                registryAddress = new ObjectMapper().convertValue(response.getResult(), RegistryAddress.class);
            } else {
                throw new JSONRPCException(response.getError());
            }
        }
        catch (Exception e) {
        	throw new DidException(e);
        }

        return registryAddress;
    }


    /**
     * Get timestamp of node
     *
     * @param web3j web
     * @return epoch timestamp
     */
    private long getTimestamp(Web3j web3j){
        if(web3j != null){
            try{
                return web3j.ethGetBlockByNumber(DefaultBlockParameterName.LATEST, false).send().getBlock().getTimestamp().longValue();
            }catch(IOException e){
                // return system timestamp
            }
        }
        return System.currentTimeMillis() / 1000;
    }

    /**
     * Create meta id<br/>
     * 각 parameter 항목에 대해서는 IdentityRegistry.createIdentityDelegated 함수를 참고 하세요.<br/>
     * https://github.com/METADIUM/MetaResolvers/blob/master/contracts/IdentityRegistry.sol
     *
     * @param key         등록할 key
     * @return transaction hash
     * @throws IOException      io error
     * @throws JSONRPCException json-rpc error
     * @throws DidException  
     */
    @SuppressWarnings("unchecked")
    public String createIdentityDelegated(MetadiumKeyImpl key) throws IOException, JSONRPCException, DidException {
        RegistryAddress registryAddress = getAllServiceAddress();
        String associatedAddress = key.getAddress();

        long timestamp = getTimestamp(web3j);
        byte[] message = Bytes.concat(
                new byte[]{0x19, 0x00},
                Numeric.hexStringToByteArray(registryAddress.identityRegistry),
                "I authorize the creation of an Identity on my behalf.".getBytes(),
                Numeric.hexStringToByteArray(associatedAddress),
                Numeric.hexStringToByteArray(associatedAddress),
                NumericUtils.hexStringArrayToByteArray(registryAddress.providers.toArray(new String[0]), 32),
                NumericUtils.hexStringArrayToByteArray(registryAddress.resolvers.toArray(new String[0]), 32),
                Numeric.toBytesPadded(BigInteger.valueOf(timestamp), 32)
        );
        Sign.SignatureData signatureData = key.sign(message);

        Map<String, Object> params = new HashMap<>();
        params.put("recovery_address", associatedAddress);
        params.put("associated_address", associatedAddress);
        params.put("providers", registryAddress.providers);
        params.put("resolvers", registryAddress.resolvers);
        params.put("timestamp", timestamp);
        params.put("v", Numeric.toHexString(signatureData.getV()));
        params.put("r", Numeric.toHexString(signatureData.getR()));
        params.put("s", Numeric.toHexString(signatureData.getS()));

        @SuppressWarnings("rawtypes")
		Response<String> response = new Request("create_identity", Collections.singletonList(params), httpService, Response.class).send();
        if(response.getError() == null){
            return response.getResult();
        }else{
            throw new JSONRPCException(response.getError());
        }
    }

    /**
     * {@link com.coinplug.metadium.core.contract.ServiceKeyResolver} 에 key 를 추가
     * https://github.com/METADIUM/MetaResolvers/blob/master/contracts/examples/Resolvers/ServiceKey/ServiceKeyResolver.sol 에서 addKeyDelegated 함수 참고
     *
     * @param key       	DID 생성 key
     * @param serviceId         service id
     * @param serviceKeyAddress 추가할 address
     * @return transaction hash
     * @throws Exception transaction error
     */
    @SuppressWarnings("unchecked")
    public String addKeyDelegated(MetadiumKeyImpl key, String serviceId, String serviceKeyAddress) throws Exception {
        RegistryAddress registryAddress = getAllServiceAddress();
        String associatedAddress = key.getAddress();

        String resolverAddress = IdentityRegistryHelper.getServiceKeyResolverAddressOfIdentity(web3j, registryAddress, associatedAddress);


        long timestamp = getTimestamp(web3j);
        byte[] message = Bytes.concat(
                new byte[]{0x19, 0x00},
                Numeric.hexStringToByteArray(resolverAddress),
                "I authorize the addition of a service key on my behalf.".getBytes(),
                Numeric.hexStringToByteArray(serviceKeyAddress),
                serviceId.getBytes(),
                Numeric.toBytesPadded(BigInteger.valueOf(timestamp), 32)
        );
        Sign.SignatureData signatureData = key.sign(message);

        Map<String, Object> params = new HashMap<>();
        params.put("resolver_address", resolverAddress);
        params.put("associated_address", associatedAddress);
        params.put("key", serviceKeyAddress);
        params.put("symbol", serviceId);
        params.put("timestamp", timestamp);
        params.put("v", Numeric.toHexString(signatureData.getV()));
        params.put("r", Numeric.toHexString(signatureData.getR()));
        params.put("s", Numeric.toHexString(signatureData.getS()));

        @SuppressWarnings("rawtypes")
		Response<String> response = new Request("add_key_delegated", Collections.singletonList(params), httpService, Response.class).send();
        if(response.getError() == null){
            return response.getResult();
        }else{
            throw new JSONRPCException(response.getError());
        }
    }

    /**
     * {@link com.coinplug.metadium.core.contract.ServiceKeyResolver} 에 key 를 삭제
     * https://github.com/METADIUM/MetaResolvers/blob/master/contracts/examples/Resolvers/ServiceKey/ServiceKeyResolver.sol 에서 removeKeyDelegated 함수 참고
     *
     * @param key       	DID 생성 key
     * @param serviceId         삭제할 service id
     * @return transaction hash
     * @throws Exception transaction error
     */
    @SuppressWarnings("unchecked")
    public String removeKeyDelegated(MetadiumKeyImpl key, String serviceId, String serviceKeyAddress) throws Exception{
        RegistryAddress registryAddress = getAllServiceAddress();
        String associatedAddress = key.getAddress();

        String resolverAddress = IdentityRegistryHelper.getServiceKeyResolverAddressOfIdentity(web3j, registryAddress, associatedAddress);

        long timestamp = getTimestamp(web3j);
        byte[] message = Bytes.concat(
                new byte[]{0x19, 0x00},
                Numeric.hexStringToByteArray(resolverAddress),
                "I authorize the removal of a service key on my behalf.".getBytes(),
                Numeric.hexStringToByteArray(serviceKeyAddress),
                Numeric.toBytesPadded(BigInteger.valueOf(timestamp), 32)
        );
        Sign.SignatureData signatureData = key.sign(message);

        Map<String, Object> params = new HashMap<>();
        params.put("resolver_address", resolverAddress);
        params.put("associated_address", associatedAddress);
        params.put("key", serviceKeyAddress);
        params.put("timestamp", timestamp);
        params.put("v", Numeric.toHexString(signatureData.getV()));
        params.put("r", Numeric.toHexString(signatureData.getR()));
        params.put("s", Numeric.toHexString(signatureData.getS()));


        @SuppressWarnings("rawtypes")
		Response<String> response = new Request("remove_key_delegated", Collections.singletonList(params), httpService, Response.class).send();
        if(response.getError() == null){
            return response.getResult();
        }else{
            throw new JSONRPCException(response.getError());
        }
    }

    /**
     * {@link com.coinplug.metadium.core.contract.ServiceKeyResolver} 의 모든 key 를 삭제한다.
     * https://github.com/METADIUM/MetaResolvers/blob/master/contracts/examples/Resolvers/ServiceKey/ServiceKeyResolver.sol 에서 removeKeysDelegated 함수 참고
     *
     * @param key       	DID 생성 key
     * @return transaction hash
     * @throws Exception transaction error
     */
    @SuppressWarnings("unchecked")
    public String removeKeysDelegated(MetadiumKeyImpl key) throws Exception{
        RegistryAddress registryAddress = getAllServiceAddress();
        String associatedAddress = key.getAddress();

        String resolverAddress = IdentityRegistryHelper.getServiceKeyResolverAddressOfIdentity(web3j, registryAddress, associatedAddress);

        long timestamp = getTimestamp(web3j);
        byte[] message = Bytes.concat(
                new byte[]{0x19, 0x00},
                Numeric.hexStringToByteArray(resolverAddress),
                "I authorize the removal of all service keys on my behalf.".getBytes(),
                Numeric.toBytesPadded(BigInteger.valueOf(timestamp), 32)
        );
        Sign.SignatureData signatureData = key.sign(message);

        Map<String, Object> params = new HashMap<>();
        params.put("resolver_address", resolverAddress);
        params.put("associated_address", associatedAddress);
        params.put("timestamp", timestamp);
        params.put("v", Numeric.toHexString(signatureData.getV()));
        params.put("r", Numeric.toHexString(signatureData.getR()));
        params.put("s", Numeric.toHexString(signatureData.getS()));


        @SuppressWarnings("rawtypes")
		Response<String> response = new Request("remove_keys_delegated", Collections.singletonList(params), httpService, Response.class).send();
        if(response.getError() == null){
            return response.getResult();
        }else{
            throw new JSONRPCException(response.getError());
        }
    }

    /**
     * Add publicKey <br/>
     * https://github.com/METADIUM/MetaResolvers/blob/master/contracts/examples/Resolvers/PublicKey/PublicKeyResolver.sol
     *
     * @param key       	DID 생성 key
     * @param publicKey			추가할 public Key
     * @return transaction hash
     * @throws IOException      io error
     * @throws JSONRPCException json rpc error
     * @throws DidException  
     */
    @SuppressWarnings("unchecked")
    public String addPublicKeyDelegated(MetadiumKeyImpl key, BigInteger publicKey) throws IOException, JSONRPCException, DidException {
        RegistryAddress registryAddress = getAllServiceAddress();
        String associatedAddress = key.getAddress();

        String resolverAddress = registryAddress.publicKey;
        long timestamp = getTimestamp(web3j);
        String publicKeyStr = "0x" + Numeric.toHexStringNoPrefixZeroPadded(publicKey, 128);
        byte[] message = Bytes.concat(
                new byte[]{0x19, 0x00},
                Numeric.hexStringToByteArray(resolverAddress),
                "I authorize the addition of a public key on my behalf.".getBytes(),
                Numeric.hexStringToByteArray(associatedAddress),
                Numeric.hexStringToByteArray(publicKeyStr),
                Numeric.toBytesPadded(BigInteger.valueOf(timestamp), 32)
        );

        Sign.SignatureData signatureData = key.sign(message);

        Map<String, Object> params = new HashMap<>();
        params.put("resolver_address", resolverAddress);
        params.put("associated_address", associatedAddress);
        params.put("public_key", publicKeyStr);
        params.put("timestamp", timestamp);
        params.put("v", Numeric.toHexString(signatureData.getV()));
        params.put("r", Numeric.toHexString(signatureData.getR()));
        params.put("s", Numeric.toHexString(signatureData.getS()));


        @SuppressWarnings("rawtypes")
		Response<String> response = new Request("add_public_key_delegated", Collections.singletonList(params), httpService, Response.class).send();
        if(response.getError() == null){
            return response.getResult();
        }else{
            throw new JSONRPCException(response.getError());
        }
    }
    
    /**
     * Add publicKey.  본인이 소유하지 않은 키를 추가할때 사용<br/>
     * https://github.com/METADIUM/MetaResolvers/blob/master/contracts/examples/Resolvers/PublicKey/PublicKeyResolver.sol
     *
     * @param key       	DID 생성 key
     * @param publicKey		추가할 public Key
     * @param signature     추가할 키로 서명한 값. {@link #signAddAssocatedKeyDelegate(String, MetadiumKeyImpl)}
     * @return transaction hash
     * @throws IOException      io error
     * @throws JSONRPCException json rpc error
     * @throws DidException  
     */
    @SuppressWarnings("unchecked")
    public String addPublicKeyDelegated(BigInteger publicKey, String signature) throws IOException, JSONRPCException, DidException {
        RegistryAddress registryAddress = getAllServiceAddress();
        String associatedAddress = Numeric.prependHexPrefix(Keys.getAddress(publicKey));

        String resolverAddress = registryAddress.publicKey;
        long timestamp = Numeric.toBigInt(signature.substring(130)).longValue();

        Sign.SignatureData signatureData = stringToSignatureData(signature.substring(0,  130));

        Map<String, Object> params = new HashMap<>();
        params.put("resolver_address", resolverAddress);
        params.put("associated_address", associatedAddress);
        params.put("public_key", "0x" + Numeric.toHexStringNoPrefixZeroPadded(publicKey, 128));
        params.put("timestamp", timestamp);
        params.put("v", Numeric.toHexString(signatureData.getV()));
        params.put("r", Numeric.toHexString(signatureData.getR()));
        params.put("s", Numeric.toHexString(signatureData.getS()));


        @SuppressWarnings("rawtypes")
		Response<String> response = new Request("add_public_key_delegated", Collections.singletonList(params), httpService, Response.class).send();
        if(response.getError() == null){
            return response.getResult();
        }else{
            throw new JSONRPCException(response.getError());
        }
    }

    /**
     * Delete publicKey <br/>
     * https://github.com/METADIUM/MetaResolvers/blob/master/contracts/examples/Resolvers/PublicKey/PublicKeyResolver.sol
     *
     * @param key        삭제할 key
     * @return transaction hash
     * @throws IOException      io error
     * @throws JSONRPCException json rpc error
     * @throws DidException  
     */
    @SuppressWarnings("unchecked")
    public String removePublicKeyDelegated(MetadiumKeyImpl key) throws IOException, JSONRPCException, DidException {
        RegistryAddress registryAddress = getAllServiceAddress();
        String associatedAddress = key.getAddress();

        String resolverAddress = registryAddress.publicKey;
        long timestamp = getTimestamp(web3j);
        byte[] message = Bytes.concat(
                new byte[]{0x19, 0x00},
                Numeric.hexStringToByteArray(resolverAddress),
                "I authorize the removal of a public key on my behalf.".getBytes(),
                Numeric.hexStringToByteArray(associatedAddress),
                Numeric.toBytesPadded(BigInteger.valueOf(timestamp), 32)
        );

        Sign.SignatureData signatureData = key.sign(message);

        Map<String, Object> params = new HashMap<>();
        params.put("resolver_address", resolverAddress);
        params.put("associated_address", associatedAddress);
        params.put("timestamp", timestamp);
        params.put("v", Numeric.toHexString(signatureData.getV()));
        params.put("r", Numeric.toHexString(signatureData.getR()));
        params.put("s", Numeric.toHexString(signatureData.getS()));


        @SuppressWarnings("rawtypes")
		Response<String> response = new Request("remove_public_key_delegated", Collections.singletonList(params), httpService, Response.class).send();
        if(response.getError() == null){
            return response.getResult();
        }else{
            throw new JSONRPCException(response.getError());
        }
    }
    
    /**
     * Add Associated Address <br/>
     * https://github.com/METADIUM/MetaResolvers/blob/master/contracts/IdentityRegistry.sol
     *
     * @param key 		did 의 key
     * @param addKey	추가할 Key의 address
     * @return transaction hash
     * @throws Exception io error
     */
    @SuppressWarnings("unchecked")
    public String addAssociatedAddressDelegated(MetadiumKeyImpl key, MetadiumKeyImpl addKey) throws Exception{
        RegistryAddress registryAddress = getAllServiceAddress();
        String associatedAddress = key.getAddress();

        String identityRegistryAddress = registryAddress.identityRegistry;
        IdentityRegistry identityRegistry = IdentityRegistry.load(registryAddress.identityRegistry, web3j, new NotSignTransactionManager(web3j), new ZeroContractGasProvider());
        BigInteger ein = identityRegistry.getEIN(associatedAddress).send();
        long timestamp = getTimestamp(web3j);
        long timestampForAddKey = getTimestamp(web3j);
        
        byte[] message = Bytes.concat(
                new byte[]{0x19, 0x00},
                Numeric.hexStringToByteArray(identityRegistryAddress),
                "I authorize adding this address to my Identity.".getBytes(),
                Numeric.toBytesPadded(ein, 32),
                Numeric.hexStringToByteArray(addKey.getAddress()),
                Numeric.toBytesPadded(BigInteger.valueOf(timestamp), 32)
        );
        Sign.SignatureData signatureData = key.sign(message);

        byte[] messageForAddKey = Bytes.concat(
                new byte[]{0x19, 0x00},
                Numeric.hexStringToByteArray(identityRegistryAddress),
                "I authorize being added to this Identity.".getBytes(),
                Numeric.toBytesPadded(ein, 32),
                Numeric.hexStringToByteArray(addKey.getAddress()),
                Numeric.toBytesPadded(BigInteger.valueOf(timestampForAddKey), 32)
        );

        Sign.SignatureData signatureDataForAddKey = addKey.sign(messageForAddKey);

        Map<String, Object> params = new HashMap<>();
        params.put("approving_address", associatedAddress);
        params.put("address_to_add", addKey.getAddress());
        params.put("timestamp", Arrays.asList(timestamp, timestampForAddKey));
        params.put("v", Arrays.asList(Numeric.toHexString(signatureData.getV()), Numeric.toHexString(signatureDataForAddKey.getV())));
        params.put("r", Arrays.asList(Numeric.toHexString(signatureData.getR()), Numeric.toHexString(signatureDataForAddKey.getR())));
        params.put("s", Arrays.asList(Numeric.toHexString(signatureData.getS()), Numeric.toHexString(signatureDataForAddKey.getS())));

        @SuppressWarnings("rawtypes")
		Response<String> response = new Request("add_associated_address_delegated", Collections.singletonList(params), httpService, Response.class).send();
        if(response.getError() == null){
            return response.getResult();
        }else{
            throw new JSONRPCException(response.getError());
        }
    }
    
    /**
     * Add Associated Address. 본인이 소유하지 않은 키를 추가할때 사용<br/>
     * https://github.com/METADIUM/MetaResolvers/blob/master/contracts/IdentityRegistry.sol
     *
     * @param key 		    did 의 key
     * @param addPublicKey	추가할 public key
     * @param signature     추가할 키로 서명한 값 {@link #signAddAssocatedKeyDelegate(String, MetadiumKeyImpl)}
     * @return transaction hash
     * @throws Exception io error
     */
    @SuppressWarnings("unchecked")
    public String addAssociatedAddressDelegated(MetadiumKeyImpl key, BigInteger addPublicKey, String signature) throws Exception{
        RegistryAddress registryAddress = getAllServiceAddress();
        String associatedAddress = key.getAddress();
        String addKeyAddress = Numeric.prependHexPrefix(Keys.getAddress(addPublicKey));

        String identityRegistryAddress = registryAddress.identityRegistry;
        IdentityRegistry identityRegistry = IdentityRegistry.load(registryAddress.identityRegistry, web3j, new NotSignTransactionManager(web3j), new ZeroContractGasProvider());
        BigInteger ein = identityRegistry.getEIN(associatedAddress).send();
        long timestamp = getTimestamp(web3j);
        
        byte[] message = Bytes.concat(
                new byte[]{0x19, 0x00},
                Numeric.hexStringToByteArray(identityRegistryAddress),
                "I authorize adding this address to my Identity.".getBytes(),
                Numeric.toBytesPadded(ein, 32),
                Numeric.hexStringToByteArray(addKeyAddress),
                Numeric.toBytesPadded(BigInteger.valueOf(timestamp), 32)
        );
        Sign.SignatureData signatureData = key.sign(message);
        
        Sign.SignatureData signatureDataForAddKey = stringToSignatureData(signature.substring(0, 130));
        long timestampForAddKey = Numeric.toBigInt(signature.substring(130)).longValue();


        Map<String, Object> params = new HashMap<>();
        params.put("approving_address", associatedAddress);
        params.put("address_to_add", addKeyAddress);
        params.put("timestamp", Arrays.asList(timestamp, timestampForAddKey));
        params.put("v", Arrays.asList(Numeric.toHexString(signatureData.getV()), Numeric.toHexString(signatureDataForAddKey.getV())));
        params.put("r", Arrays.asList(Numeric.toHexString(signatureData.getR()), Numeric.toHexString(signatureDataForAddKey.getR())));
        params.put("s", Arrays.asList(Numeric.toHexString(signatureData.getS()), Numeric.toHexString(signatureDataForAddKey.getS())));

        @SuppressWarnings("rawtypes")
		Response<String> response = new Request("add_associated_address_delegated", Collections.singletonList(params), httpService, Response.class).send();
        if(response.getError() == null){
            return response.getResult();
        }else{
            throw new JSONRPCException(response.getError());
        }
    }

    /**
     * Delete Associated Address <br/>
     * https://github.com/METADIUM/MetaResolvers/blob/master/contracts/IdentityRegistry.sol
     *
     * @param key 삭제할 did 의 key
     * @return transaction hash
     * @throws Exception io error
     */
    @SuppressWarnings("unchecked")
    public String removeAssociatedAddressDelegated(MetadiumKeyImpl key) throws Exception {
        RegistryAddress registryAddress = getAllServiceAddress();
        String associatedAddress = key.getAddress();

        String identityRegistryAddress = registryAddress.identityRegistry;
        IdentityRegistry identityRegistry = IdentityRegistry.load(registryAddress.identityRegistry, web3j, new NotSignTransactionManager(web3j), new ZeroContractGasProvider());
        BigInteger ein = identityRegistry.getEIN(associatedAddress).send();
        long timestamp = getTimestamp(web3j);
        byte[] message = Bytes.concat(
                new byte[]{0x19, 0x00},
                Numeric.hexStringToByteArray(identityRegistryAddress),
                "I authorize removing this address from my Identity.".getBytes(),
                Numeric.toBytesPadded(ein, 32),
                Numeric.hexStringToByteArray(associatedAddress),
                Numeric.toBytesPadded(BigInteger.valueOf(timestamp), 32)
        );

        Sign.SignatureData signatureData = key.sign(message);

        Map<String, Object> params = new HashMap<>();
        params.put("address_to_remove", associatedAddress);
        params.put("timestamp", timestamp);
        params.put("v", Numeric.toHexString(signatureData.getV()));
        params.put("r", Numeric.toHexString(signatureData.getR()));
        params.put("s", Numeric.toHexString(signatureData.getS()));

        @SuppressWarnings("rawtypes")
		Response<String> response = new Request("remove_associated_address_delegated", Collections.singletonList(params), httpService, Response.class).send();
        if(response.getError() == null){
            return response.getResult();
        }else{
            throw new JSONRPCException(response.getError());
        }
    }
    
    /**
     * {@link org.web3j.crypto.Sign.SignatureData} to hex string r+s+v
     * @param signatureData
     * @return
     */
    public static String signatureDataToString(Sign.SignatureData signatureData) {
        ByteBuffer buffer = ByteBuffer.allocate(65);
        buffer.put(signatureData.getR());
        buffer.put(signatureData.getS());
        buffer.put(signatureData.getV());
        return Numeric.toHexStringNoPrefix(buffer.array());
    }

    /**
     * signature hex string to {@link org.web3j.crypto.Sign.SignatureData}
     * @param signature hex string of signature
     * @return signature object
     */
    public static Sign.SignatureData stringToSignatureData(String signature) {
        byte[] bytes = Numeric.hexStringToByteArray(signature);
        return new Sign.SignatureData(bytes[64], Arrays.copyOfRange(bytes, 0, 32), Arrays.copyOfRange(bytes, 32, 64));
    }
    
    /**
     * DID 소유자의 키를 주어진 키로 바꾸기 위한 서명값 생성
     * 소유자 측은 {@link MetadiumWallet#updateKeyOfDid(MetaDelegator, BigInteger, String)} 를 호출하여 주어진 키로 변경할 수 있다. 
     * 
     * @param did 키를 변경할 DID
     * @param key 변경될 키
     * @return 서명값. addAssociatedAddressDelegated서명(R+S+V) + addPublicKeyDelegated서명(R+S+V) + timestamp 
     * @throws DidException 
     */
    public String signAddAssocatedKeyDelegate(String did, MetadiumKeyImpl key) throws DidException {
    	String[] didSplit = did.split(":");
    	if (didSplit.length < 3) {
    		throw new IllegalArgumentException("Invalid did");
    	}
    	BigInteger ein = Numeric.toBigInt(didSplit[didSplit.length-1]);
    	
    	RegistryAddress registryAddress = getAllServiceAddress();
    	String identityRegistryAddress = registryAddress.identityRegistry;
    	String resolverAddress = registryAddress.publicKey;
    	
        long timestamp = getTimestamp(web3j);
        
        // sign addAssociatedAddressDelegated
        byte[] message = Bytes.concat(
                new byte[]{0x19, 0x00},
                Numeric.hexStringToByteArray(identityRegistryAddress),
                "I authorize being added to this Identity.".getBytes(),
                Numeric.toBytesPadded(ein, 32),
                Numeric.hexStringToByteArray(key.getAddress()),
                Numeric.toBytesPadded(BigInteger.valueOf(timestamp), 32)
        );
        Sign.SignatureData signatureData = key.sign(message);
        
        // sign addPublicKeyDelegated
        String publicKeyStr = "0x" + Numeric.toHexStringNoPrefixZeroPadded(key.getPublicKey(), 128);
        byte[] message2 = Bytes.concat(
                new byte[]{0x19, 0x00},
                Numeric.hexStringToByteArray(resolverAddress),
                "I authorize the addition of a public key on my behalf.".getBytes(),
                Numeric.hexStringToByteArray(key.getAddress()),
                Numeric.hexStringToByteArray(publicKeyStr),
                Numeric.toBytesPadded(BigInteger.valueOf(timestamp), 32)
        );

        Sign.SignatureData signatureData2 = key.sign(message2);

        
        return signatureDataToString(signatureData)+signatureDataToString(signatureData2)+Numeric.toHexStringNoPrefix(BigInteger.valueOf(timestamp));
    }
    
    /**
     * 주어진 block 에서 DID 의 publicKey 를 얻는다. 
     * @param did
     * @param blockNumber
     * @return
     * @throws Exception
     */
    public BigInteger getPublicKey(String did, BigInteger blockNumber) throws Exception {
    	if (did != null && did.matches("[0-9a-fA-F]{64}$")) {
    		throw new DidException("Did invalid");
    	}
    	
    	// did to ein
    	BigInteger ein = Numeric.toBigInt(did.substring(did.length()-64));
    	
    	// get contract address
    	RegistryAddress registryAddress = getAllServiceAddress();
    	if (registryAddress == null) {
    		throw new DidException("Fail to load RegistryAddress");
    	}
    	
    	// 조회할 block number
    	DefaultBlockParameterNumber blockParameterNumber = new DefaultBlockParameterNumber(blockNumber);
    	
    	IdentityRegistry identityRegistry = IdentityRegistry.load(registryAddress.identityRegistry, web3j, new ReadonlyTransactionManager(web3j, null), new ZeroContractGasProvider());
    	identityRegistry.setDefaultBlockParameter(blockParameterNumber);
    	Tuple4<String, List<String>, List<String>, List<String>> identity = identityRegistry.getIdentity(ein).send();
    	List<String> resolverList = identity.component4();
    	
    	// find public key resolver address
    	for (String publicKeyAddress : registryAddress.publicKeyAll) {
    		if (resolverList.contains(publicKeyAddress)) {
    			// Get public key
				PublicKeyResolver publicKeyResolver = PublicKeyResolver.load(
						publicKeyAddress,
						web3j, 
						new ReadonlyTransactionManager(web3j, null), 
						new ZeroContractGasProvider()
				);
				publicKeyResolver.setDefaultBlockParameter(blockParameterNumber);
				return Numeric.toBigInt(publicKeyResolver.getPublicKey(identity.component2().get(0)).send());
    		}
    	}
    	
		throw new DidException("Not found public key resolver");
    }
    
    /**
     * 현재 블럭 번호를 가져온다
     * @return 블럭 번호
     * @throws IOException
     */
    public BigInteger currentBlockNumber() throws IOException {
    	return web3j.ethBlockNumber().send().getBlockNumber();
    }
}
