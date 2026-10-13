package com.metadium.did;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import com.metadium.did.exception.DidException;
import com.metadium.did.protocol.MetaDelegator;
import com.metadium.did.verifiable.Verifier;
import com.metadium.vc.VerifiableCredential;
import com.metadium.vc.VerifiablePresentation;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;

public class WorkflowTest {

	@Test
	public void testWorkflow() throws DidException, JOSEException, IOException, ParseException {
		// 네트워크 설정. Metadium Mainnet
		MetaDelegator delegator = new MetaDelegator();

		// 1. 발급자, 사용자 DID 생성
		MetadiumWallet issuerWallet = MetadiumWallet.createDid(delegator);
		MetadiumWallet userWallet = MetadiumWallet.createDid(delegator);

		
		// 2. 사용자가 발급자에게 credential 발급 요청
		String vpForIssueCredential = userWallet.issuePresentation(
				Collections.emptyList(),
				null,
				new Date(),
				null,
				Collections.emptyList()
		).serialize();
		
		
		// 사용자가 발급자에게 vpForIssueCredential 제출
		
		
		// 3. 발급자가 DID 검증
		Verifier verifier = new Verifier();
		if (!verifier.verify(SignedJWT.parse(vpForIssueCredential))) {
		    // 검증 실패
			assertTrue("vpForIssueCredential 검증실패", false);
		}
		// 사용자의 DID
		String holderDid = new VerifiablePresentation(SignedJWT.parse(vpForIssueCredential)).getHolder().toString();

		
		// 4. 발급자가 credential 발급
		Map<String, Object> claims = new HashMap<>();
		claims.put("name", "YoungBaeJeon");
		claims.put("birth", "19800101");
		claims.put("id", "800101xxxxxxxx");
		String personalIdVC = issuerWallet.issueCredential(
		        Collections.singletonList("PersonalIdCredential"),
		        URI.create("http://aa.metadium.com/credential/name/343"),
		        new Date(),
		        new Date(System.currentTimeMillis()*2*365*24*60*60*1000),
		        holderDid,
		        claims
		).serialize();

		
		// 발급자가 사용자에게 personalIdVC 전달
		
		
		// 사용자가 안전한 공간에 credential 저장
		List<String> userVcList = Arrays.asList(personalIdVC);
		
		
		// 5. 사용자가 발급자에게 presentation 제출
		// 검증자 요구하는 정보. presentation name, types
		String requirePresentationName = "TestPresentation";
		List<String> requireCredentialTypes = Arrays.asList("PersonalIdCredential");
		
		// 제출해야할 credential 조회
		List<String> foundVcList = findVC(userVcList, Arrays.asList(requireCredentialTypes));
		
		// presentation 발급
		String vpForVerify = userWallet.issuePresentation(
		        Collections.singletonList(requirePresentationName),
		        null,
		        new Date(),
		        new Date(System.currentTimeMillis()*60*1000),
		        foundVcList
		).serialize();
		
		
		// 사용자가 검증자에게 vpForVerify 제출
		
		
		// 6. 검증자가 presentation 검증
		// presentation 검증
		SignedJWT vp = SignedJWT.parse(vpForVerify);
		if (!verifier.verify(vp)) {
			assertTrue("vpForVerify 검증실패", false);
		}
		else if (vp.getJWTClaimsSet().getExpirationTime() != null && vp.getJWTClaimsSet().getExpirationTime().getTime() < new Date().getTime()) {
			assertTrue("vpForVerify 만료", false);
		}
		
		VerifiablePresentation vpObj = new VerifiablePresentation(vp);
		String presentorDid = vpObj.getHolder().toString();
		
		// credential 목록 확인 및 검증
		for (Object vc : vpObj.getVerifiableCredentials()) {
			// credential 검증
			SignedJWT signedVc = SignedJWT.parse((String)vc);
			if (!verifier.verify(signedVc)) {
				assertTrue(false);
			}
			else if (signedVc.getJWTClaimsSet().getExpirationTime() != null && signedVc.getJWTClaimsSet().getExpirationTime().getTime() < new Date().getTime()) {
				assertTrue(false);
			}

			// credential 소유자 확인
			if (!signedVc.getJWTClaimsSet().getSubject().equals(userWallet.getDid()) || !presentorDid.equals(userWallet.getDid())) {
				assertTrue(false);
			}

			// 요구하는 발급자가 발급한 credential 인지 확인
			VerifiableCredential credential = new VerifiableCredential(signedVc);
			if (!credential.getIssuer().toString().equals(issuerWallet.getDid())) {
				assertTrue(false);
			}
			
			// claim 정보 확인
			Map<String, String> subjects = credential.getCredentialSubject();
			for (Map.Entry<String, String> entry : subjects.entrySet()) {
			    String claimName = entry.getKey();
			    String claimValue = entry.getValue();
			    System.out.println(claimName+"="+claimValue);
			}
		}
	}
	
	
	/**
	 * @param holderVcList 사용자 credential 목록
	 * @param typesOfRequireVcs 검증자가 요구하는 credential types 목록
	 * @throws ParseException 
	 */
	private List<String> findVC(List<String> holderVcList, List<List<String>> typesOfRequireVcs) throws ParseException {
	    List<String> ret = new ArrayList<>();
	    
	    for (String serializedVc : holderVcList) {
	        VerifiableCredential credential = new VerifiableCredential(SignedJWT.parse(serializedVc));
	        for (List<String> types : typesOfRequireVcs) {
	            if (credential.getTypes().containsAll(types)) {
	                ret.add(serializedVc);
	            }
	        }
	    }
	    return ret;
	}
}
