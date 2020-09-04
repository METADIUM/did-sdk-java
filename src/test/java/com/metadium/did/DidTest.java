package com.metadium.did;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.text.ParseException;

import org.junit.Test;

import com.metadium.did.crypto.MetadiumKey;
import com.metadium.did.exception.DidException;
import com.metadium.did.protocol.MetaDelegator;
import com.metaidum.did.resolver.client.DIDResolverAPI;
import com.metaidum.did.resolver.client.document.DidDocument;

public class DidTest {

	@Test
	public void testCRUD() throws DidException, InvalidAlgorithmParameterException, ParseException {
		MetaDelegator delegator = new MetaDelegator("https://testdelegator.metadium.com", "https://api.metadium.com/dev");
		
		// Create did
		MetadiumWallet wallet = MetadiumWallet.createDid(delegator);
		
		// Check did document
		DidDocument didDocument = DIDResolverAPI.getInstance().getDocument(wallet.getDid());
		assertNotNull(didDocument);
		assertNotNull(didDocument.getPublicKey(wallet.getKid()));
		
		// Update key of did
		String oldDid = wallet.getDid();
		BigInteger oldPrivateKey = wallet.getKey().getPrivateKey();
		wallet.updateKeyOfDid(delegator, new MetadiumKey());
		assertEquals(oldDid, wallet.getDid());
		assertNotEquals(oldPrivateKey, wallet.getKey().getPrivateKey());
		
		// Check did document
		didDocument = DIDResolverAPI.getInstance().getDocument(wallet.getDid());
		assertNotNull(didDocument);
		assertNotNull(didDocument.getPublicKey(wallet.getKid()));
		
		// Delete did
		wallet.deleteDid(delegator);
		
		// Check did document
		didDocument = DIDResolverAPI.getInstance().getDocument(wallet.getDid());
		assertNull(didDocument);
		
		// save test
		wallet = MetadiumWallet.createDid(delegator);
		String json = wallet.toJson();
		MetadiumWallet newWallet = MetadiumWallet.fromJson(json);
		assertEquals(wallet.getDid(), newWallet.getDid());
		assertEquals(wallet.getKey().getPrivateKey(), newWallet.getKey().getPrivateKey());
		
		
		
	}
}
