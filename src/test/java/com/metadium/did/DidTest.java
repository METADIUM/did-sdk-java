package com.metadium.did;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.text.ParseException;

import org.junit.Test;
import org.web3j.crypto.Bip32ECKeyPair;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.MnemonicUtils;
import org.web3j.utils.Numeric;

import com.metadium.did.crypto.MetadiumKey;
import com.metadium.did.exception.DidException;
import com.metadium.did.protocol.MetaDelegator;
import com.metaidum.did.resolver.client.DIDResolverAPI;
import com.metaidum.did.resolver.client.document.DidDocument;
import com.metaidum.did.resolver.client.document.PublicKey;

public class DidTest {

	@Test
	public void testCRUD() throws DidException, InvalidAlgorithmParameterException, ParseException, Exception {
		MetaDelegator delegator = new MetaDelegator("https://testdelegator.metadium.com", "https://testdelegator.metadium.com", "did:meta:testnet");
		
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
		
		assertTrue(wallet.existsDid(delegator));
		
		// Delete did
		wallet.deleteDid(delegator);
		
		assertTrue(!wallet.existsDid(delegator));
		
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
	public void testRotatePublicKeyForDelegate() throws Exception {
		MetaDelegator delegator = new MetaDelegator("https://testdelegator.metadium.com", "https://testdelegator.metadium.com", "did:meta:testnet");
		
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
		BigInteger changedBlockNumber = wallet.updateKeyOfDid(delegator, changingKey.getPublicKey(), signature);
		
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
		BigInteger changedBlockNumber2 = newWallet.updateKeyOfDid(delegator, changingKey2.getPublicKey(), signature2);
		
		// DID key 확인
		MetadiumWallet newWallet2 = new MetadiumWallet(did, changingKey2);
		didDocument = DIDResolverAPI.getInstance().getDocument(newWallet2.getDid());
		assertNotNull(didDocument.getPublicKey(newWallet2.getKid()));
		System.out.println("changedKeyHex = "+didDocument.getPublicKey(newWallet2.getKid()).getPublicKeyHex());
		
		// 첫번째 변경된 public key 블럭번호로 확인
		assertTrue(changingKey.getPublicKey().equals(delegator.getPublicKey(did, changedBlockNumber)));
		
		// 두번째 변경된 public key 블럭번호로 확인
		assertTrue(changingKey2.getPublicKey().equals(delegator.getPublicKey(did, changedBlockNumber2)));
	}

	@Test
	public void testServiceKey() throws DidException, InvalidAlgorithmParameterException, ParseException {
		MetaDelegator delegator = new MetaDelegator("https://testdelegator.metadium.com", "https://api.metadium.com/dev", "did:meta:testnet");
		
		// Create did
		MetadiumWallet wallet = MetadiumWallet.createDid(delegator);
		System.out.println("did="+wallet.getDid());
		
		// 서비스 키 추가
		MetadiumKey serviceKey1 = new MetadiumKey();
		assertNotNull(wallet.addServiceKey(delegator, "serviceKey1", serviceKey1.getAddress()));
		
		// 체크 서비스 키
		DidDocument didDocument = DIDResolverAPI.getInstance().getDocument(wallet.getDid());
		PublicKey service1Pk = null;
		for (PublicKey publicKeyDoc : didDocument.getPublicKey()) {
			if (publicKeyDoc.getPublicKeyHash() != null && publicKeyDoc.getPublicKeyHash().equals(Numeric.cleanHexPrefix(serviceKey1.getAddress()))) {
				service1Pk = publicKeyDoc;
				break;
			}
		}
		assertNotNull(service1Pk);
		
		// 서비스 키 추가
		MetadiumKey serviceKey2 = new MetadiumKey();
		assertNotNull(wallet.addServiceKey(delegator, "serviceKey2", serviceKey2.getAddress()));
		didDocument = DIDResolverAPI.getInstance().getDocument(wallet.getDid());
		PublicKey service2Pk = null;
		for (PublicKey publicKeyDoc : didDocument.getPublicKey()) {
			if (publicKeyDoc.getPublicKeyHash() != null && publicKeyDoc.getPublicKeyHash().equals(Numeric.cleanHexPrefix(serviceKey2.getAddress()))) {
				service2Pk = publicKeyDoc;
				break;
			}
		}
		assertNotNull(service2Pk);
		
		// service1Key 삭제
		assertNotNull(wallet.removeServiceKey(delegator, "serviceKey1", serviceKey1.getAddress()));
		didDocument = DIDResolverAPI.getInstance().getDocument(wallet.getDid());
		service1Pk = null;
		for (PublicKey publicKeyDoc : didDocument.getPublicKey()) {
			if (publicKeyDoc.getPublicKeyHash() != null && publicKeyDoc.getPublicKeyHash().equals(Numeric.cleanHexPrefix(serviceKey1.getAddress()))) {
				service1Pk = publicKeyDoc;
				break;
			}
		}
		assertNull(service1Pk);
		
		// serviceKey 전체 삭제
		assertNotNull(wallet.removeAllServiceKey(delegator));
		didDocument = DIDResolverAPI.getInstance().getDocument(wallet.getDid());
		service2Pk = null;
		for (PublicKey publicKeyDoc : didDocument.getPublicKey()) {
			if (publicKeyDoc.getPublicKeyHash() != null && publicKeyDoc.getPublicKeyHash().equals(Numeric.cleanHexPrefix(serviceKey2.getAddress()))) {
				service2Pk = publicKeyDoc;
				break;
			}
		}
		assertNull(service2Pk);
	}
	
	@Test
	public void createDidEnterpriseTest() throws DidException, InvalidAlgorithmParameterException, ParseException {
		MetaDelegator delegator = new MetaDelegator("https://ent-delegator.mykeepin.com", "https://ent-api.mykeepin.com", "did:meta:enterprise");
//		MetaDelegator delegator = new MetaDelegator("https://ent-delegator.mykeepin.com", "https://ent-delegator.mykeepin.com", "did:meta:enterprise");
		
		// Create did
		MetadiumWallet wallet = MetadiumWallet.createDid(delegator);
		
		// Check did document
		DIDResolverAPI.getInstance().setResolverUrl("https://ent-resolver.mykeepin.com/1.0/");
		DidDocument didDocument = DIDResolverAPI.getInstance().getDocument(wallet.getDid());
		assertNotNull(didDocument);
		assertNotNull(didDocument.getPublicKey(wallet.getKid()));
		
		String json = wallet.toJson();
		System.out.println("wallet = "+json);
		System.out.println("public_key="+didDocument.getPublicKey(wallet.getKid()).getPublicKeyHex());
		System.out.println("kid="+wallet.getKid());
	}
	
	@Test
	public void createDidWithMnemonic() throws Exception {
		// create mnemonic
        byte[] initialEntropy = new byte[16];
        new SecureRandom().nextBytes(initialEntropy);
        String mnemonic = MnemonicUtils.generateMnemonic(initialEntropy);
        
        // private to mnemonic
        byte[] seed = MnemonicUtils.generateSeed(mnemonic, null);
        Bip32ECKeyPair master = Bip32ECKeyPair.generateKeyPair(seed);
        ECKeyPair keyPair = Bip32ECKeyPair.deriveKeyPair(master, /*KeyManager.BIP44_META_PATH*/new int[] {44 | 0x80000000, 916 | 0x80000000, 0x80000000, 0, 0});

        // DID 생성
        MetaDelegator delegator = new MetaDelegator();
        MetadiumWallet wallet = MetadiumWallet.createDid(delegator, new MetadiumKey(keyPair));

        // did 와 mnemonic 저장
        String did = wallet.getDid();
        
        // did 와 mnemonic 으로 wallet 재생성
        ECKeyPair newKeyPair = Bip32ECKeyPair.deriveKeyPair(Bip32ECKeyPair.generateKeyPair(MnemonicUtils.generateSeed(mnemonic, null)), /*KeyManager.BIP44_META_PATH*/new int[] {44 | 0x80000000, 916 | 0x80000000, 0x80000000, 0, 0});
        MetadiumWallet newWallet = new MetadiumWallet(did, new MetadiumKey(newKeyPair));
        
        assertEquals(wallet.getDid(), newWallet.getDid());
        assertEquals(wallet.getKey().getPrivateKey(), newWallet.getKey().getPrivateKey());
	}
}
