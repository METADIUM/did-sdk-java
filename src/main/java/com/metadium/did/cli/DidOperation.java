package com.metadium.did.cli;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.web3j.crypto.ECKeyPair;
import org.web3j.utils.Numeric;

import com.google.gson.Gson;
import com.metadium.did.MetadiumWallet;
import com.metadium.did.crypto.MetadiumKey;
import com.metadium.did.exception.DidException;
import com.metadium.did.protocol.MetaDelegator;
import com.metaidum.did.resolver.client.DIDResolverAPI;
import com.metaidum.did.resolver.client.document.DidDocument;


public class DidOperation {
	private final static String OPT_NETWORK = "network";
	private final static String OPT_DELEGATOR = "delegator";
	private final static String OPT_NODE = "node";
	private final static String OPT_RESOLVER = "resolver";
	private final static String OPT_DID_PREFIX = "didprefix";
	private final static String OPT_PRIVATE_KEY = "privatekey";
	

    private static Options makeOptions() {
        Options options = new Options();
        options.addOption("h", "help", false, "show command list");
        options.addOption("n", OPT_NETWORK, true, "mainnet, testnet or private.");
        options.addOption("d", OPT_DELEGATOR, true, "url of delegator. Only network is private");
        options.addOption("o", OPT_NODE, true, "url of open api node. Only network is private");
        options.addOption("r", OPT_RESOLVER, true, "url resolver. Only network is private");
        options.addOption("p", OPT_DID_PREFIX, true, "did prefix. Only network is private. ex) did:meta:private");
        options.addOption("k", OPT_PRIVATE_KEY, true, "private key of did. hex string. default: generate");
        return options;
    }
    
	public static void main(String[] args) {
		CommandLineParser parser = new DefaultParser();
		Options options = makeOptions();
		CommandLine commandLine;
        HelpFormatter formatter = new HelpFormatter();
        formatter.setWidth(128);

		try {
			commandLine = parser.parse(options, args);
		}
		catch (ParseException e) {
            formatter.printHelp( "--help", options );
            return;
		}
		
		if (commandLine.hasOption(OPT_NETWORK)) {
			String network = commandLine.getOptionValue(OPT_NETWORK);
			
			String key = null;
			if (commandLine.hasOption(OPT_PRIVATE_KEY)) {
				key = commandLine.getOptionValue(OPT_PRIVATE_KEY);
			}
			
			if (network.equals("mainnet")) {
				createDid(new MetaDelegator(), null, key);
				return;
			}
			else if (network.equals("testnet")) {
				MetaDelegator delegator = new MetaDelegator(
						"https://testdelegator.metadium.com",
						"https://api.metadium.com/dev",
						"did:meta:testnet"
				);
				createDid(delegator, "https://testnetresolver.metadium.com/1.0/", key);
				return;
			}
			else if (network.equals("private")) {
				if (commandLine.hasOption(OPT_DELEGATOR) && commandLine.hasOption(OPT_NODE) && commandLine.hasOption(OPT_RESOLVER) && commandLine.hasOption(OPT_DID_PREFIX)) {
					MetaDelegator delegator = new MetaDelegator(
							commandLine.getOptionValue(OPT_DELEGATOR),
							commandLine.getOptionValue(OPT_NODE),
							commandLine.getOptionValue(OPT_DID_PREFIX)
					);
					
					createDid(delegator, commandLine.getOptionValue(OPT_RESOLVER), key);
					return;
				}
				else {
					System.out.println("network is private, must include, delegator, node, resolver, didprefix parameter.");
				}
			}
			else {
				System.out.println("network must be one of mainnet, testnet, private.");
			}
		}
		else {
			System.out.println("Require network.");
		}
		
		formatter.printHelp( "--help", options );
	}
	
	private static void createDid(MetaDelegator delegator, String resolverUrl) {
		createDid(delegator, resolverUrl, null);
	}
	
	private static void createDid(MetaDelegator delegator, String resolverUrl, String privateKey) {
		MetadiumKey key = null;
		if (privateKey != null) {
			try {
				key = new MetadiumKey(ECKeyPair.create(Numeric.toBigInt(privateKey)));
			}
			catch (Exception e) {
				
			}
		}
		
		MetadiumWallet wallet;
		try {
			wallet = MetadiumWallet.createDid(delegator, key);
		}
		catch (DidException e) {
			System.err.println("Failed to create did. cause "+e.getMessage());
			return;
		}

		System.out.println("Created did");
		System.out.println("\tdid : "+wallet.getDid());
		System.out.println("\tkid : "+wallet.getKid());
		System.out.println("\tprivateKey : "+Numeric.toHexStringNoPrefixZeroPadded(wallet.getKey().getPrivateKey(), 64));
		System.out.println("\tpublicKey  : "+Numeric.toHexStringNoPrefixZeroPadded(wallet.getKey().getPublicKey(), 128));
		System.out.println("\taddress    : "+wallet.getKey().getAddress());
		
		if (resolverUrl != null) {
			DIDResolverAPI.getInstance().setResolverUrl(resolverUrl);
		}
		DidDocument didDoc = DIDResolverAPI.getInstance().getDocument(wallet.getDid());
		if (didDoc == null) {
			System.err.println("Error to get did document.");
		}
		
		System.out.println("Did document");
		System.out.println(new Gson().toJson(didDoc));
	}
	
	
}
