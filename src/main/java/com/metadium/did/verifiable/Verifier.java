package com.metadium.did.verifiable;

import java.io.IOException;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.metadium.did.exception.DidException;
import com.metaidum.did.resolver.client.DIDResolverAPI;
import com.metaidum.did.resolver.client.DIDResolverResponse;
import com.metaidum.did.resolver.client.document.DidDocument;
import com.metaidum.did.resolver.client.document.PublicKey;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.SignedJWT;

/**
 * Verify something with DID
 *  
 * @author ybjeon
 *
 */
public class Verifier {
	private Map<String, DidDocument> docCache = Collections.synchronizedMap(new HashMap<String, DidDocument>());
	
	/**
	 * Verify Verifiable Credential or Verifiable Presentation 
	 * @param signedJWT signed vc, vp
	 * @return
	 * @throws IOException resolver network error
	 * @throws DidException Not found or valid did, kid
	 */
	public boolean verify(SignedJWT signedJWT) throws IOException, DidException {
		String kid = signedJWT.getHeader().getKeyID();
		int idx = kid.indexOf('#');
		if (idx < 0) {
			// invalid key id
			throw new DidException("invalid keyId");
		}
		String did = kid.substring(0, idx);
		
		// Get DID document
		if (!docCache.containsKey(did)) {
			DIDResolverResponse response = DIDResolverAPI.getInstance().requestDocument(did, true);
			if (response == null || response.getDidDocument() == null) {
				// not found did
				throw new DidException("Not found did. "+did);
			}
			docCache.put(did, response.getDidDocument());
		}
		DidDocument doc = docCache.get(did);
		

		// Get Key
		PublicKey publicKeyOfIssuer = doc.getPublicKey(kid);
		if (publicKeyOfIssuer == null) {
			// Not found public key
			throw new DidException("Not found public key. "+kid);
		}
		ECPublicKey userPublicKey = (ECPublicKey)publicKeyOfIssuer.getPublicKey();
		
		// verify
		ECDSAVerifier verifier;
		try {
			verifier = new ECDSAVerifier(userPublicKey);
			verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
			return signedJWT.verify(verifier);
		}
		catch (JOSEException e) {
			// Invalid public key
			throw new DidException("Invalid public key", e);
		}
	}
}
