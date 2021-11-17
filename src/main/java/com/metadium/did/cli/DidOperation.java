package com.metadium.did.cli;

import java.io.File;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.io.FileUtils;
import org.web3j.utils.Numeric;

import com.metadium.did.MetadiumWallet;
import com.metadium.did.crypto.MetadiumKey;
import com.metadium.did.protocol.MetaDelegator;


public class DidOperation {
	private final static String OPT_HELP = "help";
	
	private final static String OPT_NETWORK = "network";
	private final static String OPT_DELEGATOR = "delegator";
	private final static String OPT_NODE = "node";
	private final static String OPT_RESOLVER = "resolver";
	private final static String OPT_DID_PREFIX = "didprefix";
	private final static String OPT_WALLET = "wallet";
	
	
	private final static String OPT_DID_CREATE = "create";
	private final static String OPT_DID_DELETE = "delete";
	private final static String OPT_DID_UPDATE = "update";

    private static Options makeOptions() {
        Options options = new Options();
        options.addOption("h", OPT_HELP, false, "show command list");
        options.addOption("n", OPT_NETWORK, true, "mainnet, testnet or private.");
        options.addOption("d", OPT_DELEGATOR, true, "url of delegator");
        options.addOption("o", OPT_NODE, true, "url of open api node");
        options.addOption("r", OPT_RESOLVER, true, "url resolver");
        options.addOption("p", OPT_DID_PREFIX, true, "did prefix");
        options.addOption("w", OPT_WALLET, true, "wallet path");
        
        OptionGroup operationOption = new OptionGroup();
        operationOption.addOption(Option.builder("dc").longOpt(OPT_DID_CREATE).desc("Create DID. Need wallet path to write.").build());
        operationOption.addOption(Option.builder("du").longOpt(OPT_DID_UPDATE).desc("Update DID. Need wallet path to read.").build());
        operationOption.addOption(Option.builder("dd").longOpt(OPT_DID_DELETE).desc("Delete DID. Need wallet path to read.").build());
        operationOption.setRequired(true);
        options.addOptionGroup(operationOption);
        
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
		
		if (commandLine.hasOption(OPT_HELP)) {
			formatter.printHelp( "--help", options);
			return;
		}
		
		
		if (commandLine.hasOption(OPT_NETWORK)) {
			String network = commandLine.getOptionValue(OPT_NETWORK);
			
			MetaDelegator delegator = null;
			
			if (network.equals("mainnet")) {
				delegator = new MetaDelegator();
			}
			else if (network.equals("testnet")) {
				delegator = new MetaDelegator(
						"https://testdelegator.metadium.com",
						"https://api.metadium.com/dev",
						"did:meta:testnet"
				);
			}
			else if (network.equals("private")) {
				if (commandLine.hasOption(OPT_DELEGATOR) && commandLine.hasOption(OPT_NODE) && commandLine.hasOption(OPT_RESOLVER) && commandLine.hasOption(OPT_DID_PREFIX)) {
					delegator = new MetaDelegator(
							commandLine.getOptionValue(OPT_DELEGATOR),
							commandLine.getOptionValue(OPT_NODE),
							commandLine.getOptionValue(OPT_DID_PREFIX)
					);
				}
				else {
					System.err.println("network is private, must include, delegator, node, resolver, didprefix parameter.");
				}
			}
			else {
				System.err.println("network must be one of mainnet, testnet, private.");
			}
			
			
			if (delegator != null) {
				if (commandLine.hasOption(OPT_DID_CREATE)) {
					if (commandLine.hasOption(OPT_WALLET)) {
						try {
							MetadiumWallet wallet = MetadiumWallet.createDid(delegator);
							String walletJson = wallet.toJson();
							FileUtils.writeStringToFile(new File(commandLine.getOptionValue(OPT_WALLET)), walletJson);
							System.out.println("Wallet : "+walletJson);
							System.out.println("Address : "+wallet.getKey().getAddress());
							System.out.println("PublicKey : "+Numeric.toHexStringNoPrefixZeroPadded(wallet.getKey().getPublicKey(), 128));
							return;
						} catch (Exception e) {
							e.printStackTrace();
						}
					}
				}
				else if (commandLine.hasOption(OPT_DID_UPDATE)) {
					if (commandLine.hasOption(OPT_WALLET)) {
						try {
							MetadiumWallet wallet = MetadiumWallet.fromJson(FileUtils.readFileToString(new File(commandLine.getOptionValue(OPT_WALLET))));
							wallet.updateKeyOfDid(delegator, new MetadiumKey());
							String walletJson = wallet.toJson();
							FileUtils.writeStringToFile(new File(commandLine.getOptionValue(OPT_WALLET)), walletJson);
							System.out.println("Updated wallet : "+walletJson);
							System.out.println("New address : "+wallet.getKey().getAddress());
							System.out.println("New PublicKey : "+Numeric.toHexStringNoPrefixZeroPadded(wallet.getKey().getPublicKey(), 128));
							return;
						} catch (Exception e) {
							e.printStackTrace();
						}
					}
				}
				else if (commandLine.hasOption(OPT_DID_DELETE)) {
					if (commandLine.hasOption(OPT_WALLET)) {
						try {
							MetadiumWallet wallet = MetadiumWallet.fromJson(FileUtils.readFileToString(new File(commandLine.getOptionValue(OPT_WALLET))));
							wallet.deleteDid(delegator);
							System.out.println("Deleted wallet : "+wallet.toJson());
							return;
						} catch (Exception e) {
							e.printStackTrace();
						}
					}
				}
				
			}
		}
		else {
			System.err.println("Require network.");
		}
		
		formatter.printHelp( "--help", options );
	}
}
