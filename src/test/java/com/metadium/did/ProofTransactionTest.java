package com.metadium.did;

import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.net.URI;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Test;

import com.iitp.verifiable.VerifiableCredential;
import com.iitp.verifiable.signer.MetadiumSigner;
import com.iitp.verifiable.verifier.MetadiumVerifier;
import com.metadium.did.crypto.MetadiumKey;
import com.metadium.did.protocol.MetaDelegator;
import com.nimbusds.jwt.SignedJWT;

public class ProofTransactionTest {

	@SuppressWarnings({ "unchecked", "deprecation" })
	@Test
	public void proofTxVcTest() throws Exception {
		MetaDelegator delegator = new MetaDelegator("https://testdelegator.metadium.com", "https://api.metadium.com/dev");
		// 판매자 DID 생성
		MetadiumWallet sellerWallet = MetadiumWallet.createDid(delegator);
		
		// 구매자 DID 생성
		MetadiumWallet buyerWallet = MetadiumWallet.createDid(delegator);
		
		// 거래_1 에 대한 판매자가 거래증명 VC 생성
		String signedProductVC1 = makeTxProofVC(sellerWallet, buyerWallet.getDid(), BigInteger.valueOf(16000), delegator.currentBlockNumber(), null);
		System.out.println("TxProofVC #1 ="+signedProductVC1);
		
		// 거래_1 에 대한 판매자 키 변경
		sellerWallet.updateKeyOfDid(delegator, new MetadiumKey());
		
		// 거래_2 에 대한 판매자가 거래증명 VC 생성
		MetadiumWallet buyer2Wallet = MetadiumWallet.createDid(delegator);
		String signedProductVC2 = makeTxProofVC(buyerWallet, buyer2Wallet.getDid(), BigInteger.valueOf(20000), delegator.currentBlockNumber(), signedProductVC1);
		System.out.println("TxProofVC #2 ="+signedProductVC2);
		
		// 거래_2 에 대한 판매자 키 변경
		buyerWallet.updateKeyOfDid(delegator, new MetadiumKey());
		
		// 거래_3 에 대한 판매자가 거래증명 VC 생성
		MetadiumWallet buyer3Wallet = MetadiumWallet.createDid(delegator);
		String signedProductVC3 = makeTxProofVC(buyer2Wallet, buyer3Wallet.getDid(), BigInteger.valueOf(30000), delegator.currentBlockNumber(), signedProductVC2);
		System.out.println("TxProofVC #3 ="+signedProductVC3);
		
		// 거래_3에 대한 판매자 키 변경
		buyer2Wallet.updateKeyOfDid(delegator, new MetadiumKey());
		
		
		// 거래_3에 대한 거래증명VC 와 이전 모든 거래증명VC 를 검증한다.
		String vcToVerify = signedProductVC3;
		do {
			VerifiableCredential vc = verifyTxProofVC(delegator, vcToVerify);
			
			assertTrue(vc != null);
			
			vcToVerify = ((Map<String, String>)vc.getCredentialSubject()).get("OldProductProofCredential");
		} while (vcToVerify != null);
	}	
	
	/**
	 * 거래증명 VC 검증
	 * @param delegator public key 를 확인할 delegator
	 * @param signedVc  거래증명 VC
	 * @return 검증 실패 시 null
	 * @throws Exception 서명한 key 가 did document 에 없음
	 */
	@SuppressWarnings("unchecked")
	private VerifiableCredential verifyTxProofVC(MetaDelegator delegator, String signedVc) throws Exception {
		MetadiumVerifier verifier = new MetadiumVerifier();
		
		// VC 에서 blockNumber, issuer 를 먼저 가져온다.
		VerifiableCredential vc = verifier.toCredential(SignedJWT.parse(signedVc).getJWTClaimsSet());
		BigInteger blockNumber = new BigInteger(((Map<String, String>)vc.getCredentialSubject()).get("BlockNumber"));
		String issuerDid = vc.getIssuer().toString();
		
		// VC 생성할 당시의 public key 를 얻는다.
		BigInteger publicKey = delegator.getPublicKey(issuerDid, blockNumber);
		verifier.setPublicKey(com.iitp.verifiable.util.ECKeyUtils.toECPublicKey(publicKey, "secp256k1"));
		
		// VC 를 검증한다.
		return (VerifiableCredential)verifier.verify(signedVc, null);
	}
	
	/**
	 * 거래증명 VC 생성
	 * @param sellerWallet   판매자
	 * @param buyerDid       구매자
	 * @param price          가격
	 * @param blockNumber    현재 블럭번호
	 * @param beforeSignedVC 이전 거래증명 VC
	 * @return 서명된 VC
	 * @throws Exception
	 */
	private String makeTxProofVC(MetadiumWallet sellerWallet, String buyerDid, BigInteger price, BigInteger blockNumber, String beforeSignedVC) throws Exception {
		Map<String, String> claims = Stream.of(new String[][] {
			{ "ProductCredential_id", "did:meta:testnet:0000000000000000000000000000000000000000000000000000000000001eee" },	// 테스트로 상품 DID 임의로 고정
			{ "seller_id", sellerWallet.getDid() },
			{ "buyer_id", buyerDid },
			{ "BlockNumber", blockNumber.toString() },
			{ "price", price.toString() },
			{ "sell_date", new SimpleDateFormat("yyyy-MM-dd").format(new Date()) }
		}).collect(Collectors.toMap(data -> data[0], data -> data[1]));
		if (beforeSignedVC != null) {
			claims.put("OldProductProofCredential", beforeSignedVC);
		}
		
		VerifiableCredential productVC = new VerifiableCredential();
		productVC.setIssuer(URI.create(sellerWallet.getDid()));
		productVC.addTypes(Collections.singletonList("ProductCredential"));
		productVC.setIssuanceDate(new Date());
		productVC.setId(URI.create(UUID.randomUUID().toString()));
		productVC.setCredentialSubject(claims);
		
		MetadiumSigner signer = new MetadiumSigner(sellerWallet.getDid(), sellerWallet.getKid(), sellerWallet.getKey().getECPrivateKey());
		return signer.sign(productVC);
	}
}
