package com.metadium.did.smoke;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.Assume;
import org.junit.Test;

import com.metadium.did.MetadiumWallet;
import com.metadium.did.crypto.DigestSigner;
import com.metadium.did.crypto.ExternalMetadiumKey;
import com.metadium.did.exception.DidException;
import com.metadium.did.exception.DidPartialFailureException;
import com.metadium.did.protocol.MetaDelegator;
import com.metadium.did.verifiable.Verifier;
import com.metaidum.did.resolver.client.DIDResolverAPI;
import com.nimbusds.jwt.SignedJWT;

/**
 * Smoke test of the external key store support in a real environment (delegator, node, resolver).
 *
 * <p>Two tests. Both are skipped unless {@code smoke.delegator} is set.
 * <ul>
 * <li>{@link #readOnlyDryRun()} does <b>not</b> write to the chain: the delegator and the node answer, and a signature of another key is refused
 *     before a transaction is sent. Run it first.</li>
 * <li>{@link #externalKeyStoreLifecycle()} <b>WRITES to the chain</b>: it creates two DIDs, updates the key of one, and deletes both.
 *     It fails unless {@code smoke.confirm=yes} is also set.</li>
 * </ul>
 *
 * <pre>
 * mvn test -Dtest=RealEnvironmentSmokeTest#readOnlyDryRun \
 *   -Dsmoke.delegator=https://delegator.example.com \
 *   -Dsmoke.node=https://node.example.com \
 *   -Dsmoke.resolver=https://resolver.example.com/1.0/ \
 *   -Dsmoke.prefix=did:meta:gov
 *
 * add these to run the lifecycle:
 *   -Dtest=RealEnvironmentSmokeTest#externalKeyStoreLifecycle -Dsmoke.confirm=yes
 *   -Dsmoke.apiKey=...                          (if the delegator needs one)
 *   -Dsmoke.keystore=com.example.MyKeyStore      (default: keys in memory, see {@link SmokeKeyStore})
 * </pre>
 *
 * <p>The lifecycle: create the DIDs of a student and an issuer, check them with the node and the resolver, issue a VC and a VP and verify them,
 * update the key of the student and verify a VP signed by the new key, delete both DIDs. It prints the time of every step and how many times
 * each key was asked to sign. Keep the DIDs it prints (also when a step fails) in the PR comment of the run, so that they can be checked afterwards.
 */
public class RealEnvironmentSmokeTest {

	/** counts the calls and the time of a key */
	private static class CountingSigner implements DigestSigner {
		final String name;
		final DigestSigner delegate;
		final AtomicInteger calls = new AtomicInteger();
		final AtomicLong millis = new AtomicLong();

		CountingSigner(String name, DigestSigner delegate) {
			this.name = name;
			this.delegate = delegate;
		}

		@Override
		public byte[] signDigest(byte[] digest) throws Exception {
			long start = System.currentTimeMillis();
			try {
				return delegate.signDigest(digest);
			}
			finally {
				calls.incrementAndGet();
				millis.addAndGet(System.currentTimeMillis() - start);
			}
		}

		@Override
		public String toString() {
			return String.format("%-12s %3d signatures, %6d ms in the key store", name, calls.get(), millis.get());
		}
	}

	private static void log(String message) {
		System.out.println("[smoke " + new Date() + "] " + message);
	}

	private static String required(String name) {
		String value = System.getProperty(name);
		if (value == null || value.trim().isEmpty()) {
			fail("-D" + name + " is required");
		}
		return value.trim();
	}

	private static boolean enabled() {
		String delegatorUrl = System.getProperty("smoke.delegator");
		return delegatorUrl != null && !delegatorUrl.trim().isEmpty();
	}

	private static SmokeKeyStore newKeyStore() throws Exception {
		String className = System.getProperty("smoke.keystore");
		if (className == null || className.trim().isEmpty()) {
			log("keys: in memory (SoftwareKeyStore). Use -Dsmoke.keystore=<class> for the real key store");
			return new SoftwareKeyStore();
		}
		log("keys: " + className);
		return (SmokeKeyStore)Class.forName(className.trim()).newInstance();
	}

	private static MetaDelegator newDelegator() {
		String apiKey = System.getProperty("smoke.apiKey");
		String delegatorUrl = required("smoke.delegator");
		String nodeUrl = required("smoke.node");
		String prefix = required("smoke.prefix");
		MetaDelegator delegator = (apiKey == null || apiKey.trim().isEmpty())
				? new MetaDelegator(delegatorUrl, nodeUrl, prefix)
				: new MetaDelegator(delegatorUrl, nodeUrl, prefix, apiKey.trim());
		DIDResolverAPI.getInstance().setResolverUrl(required("smoke.resolver"));
		return delegator;
	}

	/** A key store that signs with another key is refused before anything is sent (nothing is written) */
	private static void assertSignerOfAnotherKeyIsRefused(MetaDelegator delegator, SmokeKeyStore.Key key) throws Exception {
		log("a signer of another key is refused, before a transaction is sent");
		try {
			MetadiumWallet.createDid(delegator, ExternalMetadiumKey.fromPublicKeyBytes(key.publicKey, new SoftwareKeyStore().key("wrong").signer));
			fail("a signature of another key must be refused");
		}
		catch (DidException expected) {
			// not any DidException: an unreachable delegator, or a request that went to the delegator and was refused there, would also be one
			assertTrue("refused for another reason: " + expected, expected.getCause() instanceof IllegalStateException);
			assertTrue("refused for another reason: " + expected.getCause(), String.valueOf(expected.getCause().getMessage()).contains("Signature does not match the public key"));
			log("refused: " + expected.getMessage());
		}
	}

	/**
	 * What is left on-chain after a deleteDid that ended half way: which transactions were done and which step is still to do or to check.
	 * Without it the operator would only read "delete it by hand".
	 */
	private static void logPartial(String did, DidPartialFailureException e) {
		log("PARTIAL " + did + ": " + e.getMessage());
		log("  completed   = " + e.getCompletedSteps());
		log("  unrecovered = " + e.getUnrecoveredSteps());
		log("  steps       = " + e.getSteps());
		log("  cause       = " + e.getCause());
	}

	/**
	 * createDid ended half way. If something is left on-chain (the unrecovered steps are not empty) and the DID is known, the cleanup deletes it
	 * with the key. Otherwise nothing is left, or the DID is not known and has to be looked up by hand.
	 */
	private static MetadiumWallet walletToClean(DidPartialFailureException e, ExternalMetadiumKey key) {
		logPartial(String.valueOf(e.getDid()), e);
		if (e.getDid() != null && !e.getUnrecoveredSteps().isEmpty()) {
			return new MetadiumWallet(e.getDid(), key);
		}
		log("nothing to clean up by the test" + (e.getDid() == null ? " (the DID is not known: look it up with the transactions above)" : ""));
		return null;
	}

	/** The resolver may keep a DID document for some time (cache), so the verification is tried again for a while */
	private static void assertVerifiesEventually(String jwt) throws Exception {
		Exception last = null;
		for (int i = 1; i <= 30; i++) {
			try {
				// a new Verifier: it keeps the documents it has read
				if (new Verifier().verify(SignedJWT.parse(jwt))) {
					log("verified (attempt " + i + ")");
					return;
				}
			}
			catch (DidException e) {
				last = e;
			}
			log("not verified yet (attempt " + i + "). The resolver cache may hold the old DID document");
			Thread.sleep(5000);
		}
		if (last != null) {
			throw last;
		}
		fail("not verified");
	}

	/**
	 * Dry run that does NOT write to the chain (it does not need smoke.confirm): the delegator answers, the node answers,
	 * and a signature of another key is refused before a transaction is sent. Run it first.
	 */
	@Test
	public void readOnlyDryRun() throws Exception {
		Assume.assumeTrue("smoke.delegator is not set: the smoke test is skipped", enabled());

		MetaDelegator delegator = newDelegator();
		assertNotNull("the delegator did not answer get_all_service_addresses", delegator.getAllServiceAddress());
		assertNotNull(delegator.getAllServiceAddress().identityRegistry);
		log("delegator answers. identity registry=" + delegator.getAllServiceAddress().identityRegistry
				+ " providers=" + delegator.getAllServiceAddress().providers);
		log("node answers. block number=" + delegator.getWeb3j().ethBlockNumber().send().getBlockNumber());
		assertSignerOfAnotherKeyIsRefused(delegator, newKeyStore().key("student"));
	}

	@Test
	public void externalKeyStoreLifecycle() throws Exception {
		Assume.assumeTrue("smoke.delegator is not set: the smoke test is skipped", enabled());
		assertEquals("This test WRITES to the chain (two DIDs are created, one key is updated, both DIDs are deleted). Set -Dsmoke.confirm=yes to run it.",
				"yes", System.getProperty("smoke.confirm"));

		MetaDelegator delegator = newDelegator();
		log("delegator=" + required("smoke.delegator") + " node=" + required("smoke.node") + " resolver=" + required("smoke.resolver") + " prefix=" + required("smoke.prefix"));

		SmokeKeyStore keyStore = newKeyStore();
		SmokeKeyStore.Key studentKey = keyStore.key("student");
		SmokeKeyStore.Key newStudentKey = keyStore.key("student-new");
		SmokeKeyStore.Key issuerKey = keyStore.key("issuer");
		CountingSigner studentSigner = new CountingSigner("student", studentKey.signer);
		CountingSigner newStudentSigner = new CountingSigner("student-new", newStudentKey.signer);
		CountingSigner issuerSigner = new CountingSigner("issuer", issuerKey.signer);
		long begin = System.currentTimeMillis();

		// 0. a key store that signs with another key is refused
		assertSignerOfAnotherKeyIsRefused(delegator, studentKey);

		MetadiumWallet student = null;
		MetadiumWallet issuer = null;
		try {
			// 1. create the DIDs
			log("step 1: create the DIDs");
			long t = System.currentTimeMillis();
			ExternalMetadiumKey studentExternalKey = ExternalMetadiumKey.fromPublicKeyBytes(studentKey.publicKey, studentSigner);
			ExternalMetadiumKey issuerExternalKey = ExternalMetadiumKey.fromPublicKeyBytes(issuerKey.publicKey, issuerSigner);
			try {
				student = MetadiumWallet.createDid(delegator, studentExternalKey);
			}
			catch (DidPartialFailureException e) {
				student = walletToClean(e, studentExternalKey);
				throw e;
			}
			try {
				issuer = MetadiumWallet.createDid(delegator, issuerExternalKey);
			}
			catch (DidPartialFailureException e) {
				issuer = walletToClean(e, issuerExternalKey);
				throw e;
			}
			log("created student=" + student.getDid() + " issuer=" + issuer.getDid() + " (" + (System.currentTimeMillis() - t) + " ms)");
			assertNotNull(student.getDid());
			assertNotNull(issuer.getDid());
			assertTrue(student.existsDid(delegator));
			assertTrue(issuer.existsDid(delegator));

			// 2. the resolver has the DID documents
			log("step 2: the resolver has the DID documents");
			assertNotNull(student.getDidDocument());
			assertNotNull(issuer.getDidDocument());

			// 3. VC of the issuer, VP of the student
			log("step 3: issue and verify a VC and a VP");
			Date now = new Date();
			String vc = issuer.issueCredential(
					Collections.singletonList("SmokeCredential"),
					URI.create("urn:smoke:" + UUID.randomUUID()),
					now, new Date(now.getTime() + 24L * 3600 * 1000),
					student.getDid(),
					Collections.<String, Object>singletonMap("name", "smoke")).serialize();
			assertVerifiesEventually(vc);
			String vp = student.issuePresentation(
					Collections.singletonList("SmokePresentation"), null,
					now, new Date(now.getTime() + 3600L * 1000),
					Collections.singletonList(vc)).serialize();
			assertVerifiesEventually(vp);

			// 4. update the key of the student
			log("step 4: update the key of the student");
			t = System.currentTimeMillis();
			student.updateKeyOfDid(delegator, ExternalMetadiumKey.fromPublicKeyBytes(newStudentKey.publicKey, newStudentSigner));
			log("key updated (" + (System.currentTimeMillis() - t) + " ms)");
			String vp2 = student.issuePresentation(
					Collections.singletonList("SmokePresentation"), null,
					now, new Date(now.getTime() + 3600L * 1000),
					Collections.singletonList(vc)).serialize();
			assertVerifiesEventually(vp2);

			// 5. delete the DIDs
			log("step 5: delete the DIDs");
			try {
				student.deleteDid(delegator);
			}
			catch (DidPartialFailureException e) {
				// the finally block calls deleteDid once more: removing a public key that is already removed is not expected to revert
				// (the delegator does not check that the key exists, and PublicKeyResolver only deletes the mapping), so it removes the associated address that is left
				logPartial(student.getDid(), e);
				throw e;
			}
			assertFalse(student.existsDid(delegator));
			student = null;
			try {
				issuer.deleteDid(delegator);
			}
			catch (DidPartialFailureException e) {
				logPartial(issuer.getDid(), e);
				throw e;
			}
			assertFalse(issuer.existsDid(delegator));
			issuer = null;
			log("deleted");
		}
		finally {
			// best effort, so that a failed run does not leave identities behind
			for (MetadiumWallet wallet : new MetadiumWallet[] {student, issuer}) {
				if (wallet != null) {
					try {
						wallet.deleteDid(delegator);
						log("cleanup: deleted " + wallet.getDid());
					}
					catch (DidPartialFailureException e) {
						// deleteDid was already tried once more: this is what is left
						logPartial(wallet.getDid(), e);
					}
					catch (Exception e) {
						log("cleanup FAILED for " + wallet.getDid() + ": " + e + ". Delete it by hand");
					}
				}
			}
			log("summary (" + (System.currentTimeMillis() - begin) + " ms):");
			log("  " + studentSigner);
			log("  " + newStudentSigner);
			log("  " + issuerSigner);
		}
	}
}
