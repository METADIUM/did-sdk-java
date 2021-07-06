package com.metadium.did;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

import org.junit.Test;

import com.metadium.did.exception.DidException;
import com.metadium.did.protocol.MetaDelegator;
import com.metadium.did.verifiable.Verifier;
import com.metadium.vc.VerifiableCredential;
import com.metadium.vc.VerifiablePresentation;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;

public class VerifiableTest {
	
	@Test
	public void testVerifing() throws DidException, JOSEException, IOException, ParseException {
		MetaDelegator delegator = new MetaDelegator();

		Verifier verifier = new Verifier();

		// Create did of issuer
		MetadiumWallet issuerWallet = MetadiumWallet.createDid(delegator);
		
		// Create did of user
		MetadiumWallet userWallet = MetadiumWallet.createDid(delegator);


		Calendar issued = Calendar.getInstance();
		Calendar expire = Calendar.getInstance();
		expire.setTime(issued.getTime());
		expire.add(Calendar.DAY_OF_YEAR, 100);

		// Issuer issue credential of user : name
		String signedNameVC = issuerWallet.issueCredential(
				Collections.singletonList("NameCredential"),
				URI.create("http://aa.metadium.com/credential/name/343"),
				issued.getTime(),
				expire.getTime(),
				userWallet.getDid(),
				Collections.singletonMap("name", "mansud")
		).serialize();
		System.out.println("vc : "+signedNameVC);
		
		// User verify nameVC
		SignedJWT nameJWT = SignedJWT.parse(signedNameVC);
		assertTrue(verifier.verify(nameJWT));
		
		// Check expire nameVC
		VerifiableCredential receivedNameVC = new VerifiableCredential(nameJWT);
		assertNotNull(receivedNameVC.getExpriationDate());
		assertTrue(receivedNameVC.getExpriationDate().getTime() > new Date().getTime());
		assertEquals(issuerWallet.getDid(), receivedNameVC.getIssuer().toString());
		assertEquals("http://aa.metadium.com/credential/name/343", receivedNameVC.getId().toString());
		assertTrue(receivedNameVC.getTypes().contains("NameCredential"));
		Map<String, String> claims = receivedNameVC.getCredentialSubject();
		assertEquals(userWallet.getDid(), claims.get("id"));
		assertEquals("mansud", claims.get("name"));
		
		
		// Issuer issue credential of user : birth
		String signedBirthVC = issuerWallet.issueCredential(
				Collections.singletonList("BirthCredential"),
				URI.create("http://aa.metadium.com/credential/birth/84934"),
				issued.getTime(),
				expire.getTime(),
				userWallet.getDid(),
				Collections.singletonMap("birth", "19770206")
		).serialize();
		System.out.println("vc : "+signedBirthVC);
		
		// User verify nameVC
		SignedJWT birthJWT = SignedJWT.parse(signedBirthVC);
		assertTrue(verifier.verify(birthJWT));
		// Check expire nameVC
		VerifiableCredential receivedBirthVC = new VerifiableCredential(birthJWT);
		assertNotNull(receivedBirthVC.getExpriationDate());
		assertTrue(receivedBirthVC.getExpriationDate().getTime() > new Date().getTime());
		
		// User issue verifiable presentation
		String signedVp = userWallet.issuePresentation(
				Collections.singletonList("TestPresentation"),
				URI.create("http://aa.metadium.com/presentation/343"),
				issued.getTime(),
				expire.getTime(),
				Arrays.asList(signedNameVC, signedBirthVC)
		).serialize();
		System.out.println("vp : "+signedVp);
		
		// Verifier verify VP
		SignedJWT vpJWT = SignedJWT.parse(signedVp);
		assertTrue(verifier.verify(vpJWT));
		assertNotNull(vpJWT.getJWTClaimsSet().getExpirationTime());
		assertTrue(vpJWT.getJWTClaimsSet().getExpirationTime().getTime() > new Date().getTime());

		// Retrieve VC
		VerifiablePresentation receivedVp = new VerifiablePresentation(vpJWT);
		assertEquals(userWallet.getDid(), receivedVp.getHolder().toString());
		for (Object vc : receivedVp.getVerifiableCredentials()) {
			SignedJWT vcJwt = SignedJWT.parse((String)vc);
			
			assertTrue(verifier.verify(vcJwt));
			VerifiableCredential credential = new VerifiableCredential(vcJwt);
			assertNotNull(credential.getExpriationDate());
			assertTrue(credential.getExpriationDate().getTime() > new Date().getTime());

			System.out.println(credential.getTypes().toString());
			Map<String, String> subjects = credential.getCredentialSubject();
			for (Map.Entry<String, String> entry : subjects.entrySet()) {
				System.out.println(entry.getKey()+":"+entry.getValue());
			}
		}
	}
}
