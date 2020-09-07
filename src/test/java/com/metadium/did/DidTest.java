package com.metadium.did;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.text.ParseException;

import org.junit.Test;
import org.web3j.utils.Numeric;

import com.metadium.did.crypto.MetadiumKey;
import com.metadium.did.exception.DidException;
import com.metadium.did.protocol.MetaDelegator;
import com.metaidum.did.resolver.client.DIDResolverAPI;
import com.metaidum.did.resolver.client.document.DidDocument;
import com.metaidum.did.resolver.client.document.PublicKey;

public class DidTest {

	@Test
	public void testCRUD() throws DidException, InvalidAlgorithmParameterException, ParseException {
		MetaDelegator delegator = new MetaDelegator("https://testdelegator.metadium.com", "https://testdelegator.metadium.com");
		
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
	
	@Test
	public void testRotatePublicKeyForDelegate() throws DidException, InvalidAlgorithmParameterException {
		MetaDelegator delegator = new MetaDelegator("https://testdelegator.metadium.com", "https://testdelegator.metadium.com");
		
		// 소유자 DID 생성
		MetadiumWallet wallet = MetadiumWallet.createDid(delegator);
		String did = wallet.getDid();
		BigInteger oldPrivateKey = wallet.getKey().getPrivateKey();
		System.out.println("created did = "+did);
		System.out.println("kid ="+wallet.getKid());
		DidDocument didDocument = DIDResolverAPI.getInstance().getDocument(wallet.getDid());
		assertNotNull(didDocument);
		System.out.println("publicKeyHex ="+didDocument.getPublicKey(wallet.getKid()).getPublicKeyHex());
		
		// 변경할 Key 생성
		MetadiumKey changingKey = new MetadiumKey();
		
		// 소유자에게 보낼 서명 값 생성
		String signature = delegator.signAddAssocatedKeyDelegate(did, changingKey);
		
		// 소유자가 키 변경
		wallet.updateKeyOfDid(delegator, changingKey.getPublicKey(), signature);
		
		// DID key 확인
		MetadiumWallet newWallet = new MetadiumWallet(did, changingKey);
		didDocument = DIDResolverAPI.getInstance().getDocument(newWallet.getDid());
		assertNotNull(didDocument);
		PublicKey publicKey = didDocument.getPublicKey(newWallet.getKid());
		assertNotNull(publicKey);
		assertNotEquals(oldPrivateKey, newWallet.getKey().getPrivateKey());
		System.out.println("changedKeyHex = "+publicKey.getPublicKeyHex());
		
		// 변경할 Key 생성
		MetadiumKey changingKey2 = new MetadiumKey();
		
		// 소유자에게 보낼 서명 값 생성
		String signature2 = delegator.signAddAssocatedKeyDelegate(did, changingKey2);
		
		// 소유자가 키 변경
		newWallet.updateKeyOfDid(delegator, changingKey2.getPublicKey(), signature2);
		
		// DID key 확인
		MetadiumWallet newWallet2 = new MetadiumWallet(did, changingKey2);
		didDocument = DIDResolverAPI.getInstance().getDocument(newWallet2.getDid());
		assertNotNull(didDocument.getPublicKey(newWallet2.getKid()));
		System.out.println("changedKeyHex = "+didDocument.getPublicKey(newWallet2.getKid()).getPublicKeyHex());

	}
}
