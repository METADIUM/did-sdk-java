package com.metadium.did.protocol;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.web3j.crypto.Sign;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.Response;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Numeric;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.metadium.did.contract.IdentityRegistry;
import com.metadium.did.crypto.MetadiumKeyImpl;
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

    /**
     * create delegator.
     *
     * @param delegatorUrl delegator server url
     * @param nodeUrl      node url
     */
    public MetaDelegator(String delegatorUrl, String nodeUrl) {
    	this.delegatorUrl = delegatorUrl;
    	
        web3j = Web3jBuilder.build(nodeUrl);

        OkHttpClient.Builder builder = new OkHttpClient.Builder();

        httpService = new HttpService(delegatorUrl, builder.build(), false);
    }

    public MetaDelegator() {
        this(MAINNET_PROXY_URL, Web3jBuilder.MAINNET_NODE_URL);
    }
    
    private boolean isMainNet() {
    	return MAINNET_PROXY_URL.equals(delegatorUrl);
    }

    /**
     * Convert EIN to DID
     * @param ein
     * @return
     */
    public String einToDid(BigInteger ein) {
        return (isMainNet() ? "did:meta:" : "did:meta:testnet:")+Numeric.toHexStringNoPrefixZeroPadded(ein, 64);
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
     */
    @SuppressWarnings("unchecked")
    public RegistryAddress getAllServiceAddress() {
        if (registryAddress != null) {
            return registryAddress;
        }

        try {
            Response<Map> response = new Request(METHOD_GET_ALL_SERVICE_ADDRESSES, null, httpService, Response.class).send();
            if (response.getError() == null) {
                registryAddress = new ObjectMapper().convertValue(response.getResult(), RegistryAddress.class);
            } else {
                throw new JSONRPCException(response.getError());
            }
        }
        catch (Exception e) {
            registryAddress = isMainNet() ? RegistryAddress.DEFAULT_MAINNET_REGISTRY_ADDRESS : RegistryAddress.DEFAULT_TESTNET_REGISTRY_ADDRESS;
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
     */
    @SuppressWarnings("unchecked")
    public String createIdentityDelegated(MetadiumKeyImpl key) throws IOException, JSONRPCException{
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
        params.put("v", Numeric.toHexString(new byte[]{signatureData.getV()}));
        params.put("r", Numeric.toHexString(signatureData.getR()));
        params.put("s", Numeric.toHexString(signatureData.getS()));

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
        params.put("v", Numeric.toHexString(new byte[]{signatureData.getV()}));
        params.put("r", Numeric.toHexString(signatureData.getR()));
        params.put("s", Numeric.toHexString(signatureData.getS()));

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
        params.put("v", Numeric.toHexString(new byte[]{signatureData.getV()}));
        params.put("r", Numeric.toHexString(signatureData.getR()));
        params.put("s", Numeric.toHexString(signatureData.getS()));


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
        params.put("v", Numeric.toHexString(new byte[]{signatureData.getV()}));
        params.put("r", Numeric.toHexString(signatureData.getR()));
        params.put("s", Numeric.toHexString(signatureData.getS()));


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
     */
    @SuppressWarnings("unchecked")
    public String addPublicKeyDelegated(MetadiumKeyImpl key, BigInteger publicKey) throws IOException, JSONRPCException{
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
        params.put("v", Numeric.toHexString(new byte[]{signatureData.getV()}));
        params.put("r", Numeric.toHexString(signatureData.getR()));
        params.put("s", Numeric.toHexString(signatureData.getS()));


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
     */
    @SuppressWarnings("unchecked")
    public String removePublicKeyDelegated(MetadiumKeyImpl key) throws IOException, JSONRPCException{
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
        params.put("v", Numeric.toHexString(new byte[]{signatureData.getV()}));
        params.put("r", Numeric.toHexString(signatureData.getR()));
        params.put("s", Numeric.toHexString(signatureData.getS()));


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
        params.put("v", Arrays.asList(Numeric.toHexString(new byte[]{signatureData.getV()}), Numeric.toHexString(new byte[]{signatureDataForAddKey.getV()})));
        params.put("r", Arrays.asList(Numeric.toHexString(signatureData.getR()), Numeric.toHexString(signatureDataForAddKey.getR())));
        params.put("s", Arrays.asList(Numeric.toHexString(signatureData.getS()), Numeric.toHexString(signatureDataForAddKey.getS())));

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
        params.put("v", Numeric.toHexString(new byte[]{signatureData.getV()}));
        params.put("r", Numeric.toHexString(signatureData.getR()));
        params.put("s", Numeric.toHexString(signatureData.getS()));

        Response<String> response = new Request("remove_associated_address_delegated", Collections.singletonList(params), httpService, Response.class).send();
        if(response.getError() == null){
            return response.getResult();
        }else{
            throw new JSONRPCException(response.getError());
        }
    }
}
