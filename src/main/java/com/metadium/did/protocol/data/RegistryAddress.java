package com.metadium.did.protocol.data;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * registry address
 */
public class RegistryAddress {

    @JsonProperty("identity_registry")
    public String identityRegistry;

    @JsonProperty("providers")
    public List<String> providers;

    @JsonProperty("public_key")
    public String publicKey;

    @JsonProperty("public_key_all")
    public List<String> publicKeyAll;

    @JsonProperty("resolvers")
    public List<String> resolvers;

    @JsonProperty("service_key")
    public String serviceKey;

    @JsonProperty("service_key_all")
    public List<String> serviceKeyAll;

    public static RegistryAddress DEFAULT_MAINNET_REGISTRY_ADDRESS;
    public static RegistryAddress DEFAULT_TESTNET_REGISTRY_ADDRESS;

    static {
        DEFAULT_MAINNET_REGISTRY_ADDRESS = new RegistryAddress();
        DEFAULT_MAINNET_REGISTRY_ADDRESS.identityRegistry = "0x42bbff659772231bb63c7c175a1021e080a4cf9d";
        DEFAULT_MAINNET_REGISTRY_ADDRESS.providers = Arrays.asList("0x298fde31b830f43b664e32d84180462802c4ec01", "0x85d9d6df80356ac3893c63dba54560afb10fef78");
        DEFAULT_MAINNET_REGISTRY_ADDRESS.resolvers = Arrays.asList("0x5d4b8c6c6abecf9b5277747fa15980b964c40ce3", "0xd9f39ab902f835400cfb424529bb0423d7342331");
        DEFAULT_MAINNET_REGISTRY_ADDRESS.publicKey = "0xd9f39ab902f835400cfb424529bb0423d7342331";
        DEFAULT_MAINNET_REGISTRY_ADDRESS.publicKeyAll = Collections.singletonList(DEFAULT_MAINNET_REGISTRY_ADDRESS.publicKey);
        DEFAULT_MAINNET_REGISTRY_ADDRESS.serviceKey = "0x5d4b8c6c6abecf9b5277747fa15980b964c40ce3";
        DEFAULT_MAINNET_REGISTRY_ADDRESS.serviceKeyAll = Collections.singletonList(DEFAULT_MAINNET_REGISTRY_ADDRESS.serviceKey);

        DEFAULT_TESTNET_REGISTRY_ADDRESS = new RegistryAddress();
        DEFAULT_TESTNET_REGISTRY_ADDRESS.identityRegistry = "0xbe2bb3d7085ff04bde4b3f177a730a826f05cb70";
        DEFAULT_TESTNET_REGISTRY_ADDRESS.providers = Collections.singletonList("0x084f8293f1b047d3a217025b24cd7b5ace8fc657");
        DEFAULT_TESTNET_REGISTRY_ADDRESS.resolvers = Collections.singletonList("0xf4f9790205ee559a379c519e04042b20560eefad");
        DEFAULT_TESTNET_REGISTRY_ADDRESS.serviceKey = "0xf4f9790205ee559a379c519e04042b20560eefad";
        DEFAULT_TESTNET_REGISTRY_ADDRESS.serviceKeyAll = Arrays.asList("0x43fe3710e701730151c5fad21d205a4b9f68caf3", "0xf4f9790205ee559a379c519e04042b20560eefad");
    }
}
