package com.metadium.did.smoke;

import java.util.HashMap;
import java.util.Map;

import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.ECKeyPair;
import org.web3j.utils.Numeric;

import com.metadium.did.crypto.DigestSigner;
import com.metadium.did.crypto.ECKeyUtils;

/**
 * Keys in memory, generated when they are asked for. It plays the key store, so the path to the delegator, the node and the resolver
 * can be checked before the real key store is available.
 */
public class SoftwareKeyStore implements SmokeKeyStore {
	private final Map<String, Key> keys = new HashMap<String, Key>();

	@Override
	public synchronized Key key(String name) throws Exception {
		Key key = keys.get(name);
		if (key == null) {
			final ECKeyPair pair = ECKeyUtils.generateSecp256k1ECKeyPair();
			byte[] publicKey = Numeric.toBytesPadded(pair.getPublicKey(), 64);
			key = new Key(publicKey, new DigestSigner() {
				@Override
				public byte[] signDigest(byte[] digest) {
					ECDSASignature signature = pair.sign(digest);
					byte[] out = new byte[64];
					System.arraycopy(Numeric.toBytesPadded(signature.r, 32), 0, out, 0, 32);
					System.arraycopy(Numeric.toBytesPadded(signature.s, 32), 0, out, 32, 32);
					return out;
				}
			});
			keys.put(name, key);
		}
		return key;
	}

}
