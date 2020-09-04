package com.metadium.did.protocol;

import org.web3j.protocol.Web3j;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Async;

import okhttp3.OkHttpClient;

/**
 * Client of Metadium open api server.<br>
 * default url is https://api.metadium.com/dev
 */
public class Web3jBuilder {
    public final static String MAINNET_NODE_URL = "https://api.metadium.com/prod";

    public static Web3j build(String url) {
        OkHttpClient.Builder builder = new OkHttpClient.Builder();

        HttpService httpService = new HttpService(url, builder.build(), false);

        return  Web3j.build(httpService, 1000, Async.defaultExecutorService());
    }

    public static Web3j build() {
        return build(MAINNET_NODE_URL);
    }
}
