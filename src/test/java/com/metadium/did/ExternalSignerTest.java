package com.metadium.did;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;
import java.util.Map;

import org.junit.Test;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;
import org.web3j.crypto.Sign.SignatureData;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.response.EthGetTransactionReceipt;
import org.web3j.protocol.core.methods.response.Log;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.utils.Numeric;

import com.metadium.did.crypto.DigestSigner;
import com.metadium.did.crypto.ECKeyUtils;
import com.metadium.did.crypto.ExternalJWSSigner;
import com.metadium.did.crypto.ExternalMetadiumKey;
import com.metadium.did.crypto.ExternalSignatureUtils;
import com.metadium.did.crypto.MetadiumKey;
import com.metadium.did.crypto.MetadiumKeyImpl;
import com.metadium.did.exception.DidException;
import com.metadium.did.exception.DidPartialFailureException;
import com.metadium.did.exception.DidStep;
import com.metadium.did.protocol.MetaDelegator;
import com.metadium.did.protocol.data.RegistryAddress;
import com.nimbusds.jose.JOSEException;
import com.metadium.vc.VerifiableCredential;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.SignedJWT;

/**
 * Offline tests. A local key plays the role of the external key store; no network is used.
 */
public class ExternalSignerTest {
	/** key store simulator. mode: 0=r||s, 1=r||s||v(0/1), 2=r||s||v(27/28), 3=high-s r||s, 4=DER */
	private static DigestSigner keyStore(final ECKeyPair keyPair, final int mode) {
		return new DigestSigner() {
			@Override
			public byte[] signDigest(byte[] digest) {
				ECDSASignature sig = keyPair.sign(digest); // canonical (low-s)
				BigInteger r = sig.r;
				BigInteger s = sig.s;
				if (mode == 3) {
					s = Sign.CURVE_PARAMS.getN().subtract(s);
				}
				byte[] rs = new byte[64];
				System.arraycopy(Numeric.toBytesPadded(r, 32), 0, rs, 0, 32);
				System.arraycopy(Numeric.toBytesPadded(s, 32), 0, rs, 32, 32);
				if (mode == 4) {
					return der(r, s);
				}
				if (mode == 1 || mode == 2) {
					byte[] out = new byte[65];
					System.arraycopy(rs, 0, out, 0, 64);
					out[64] = (byte)(mode == 1 ? 0 : 27);
					return out;
				}
				return rs;
			}
		};
	}

	/** ASN.1 DER encoding of an ECDSA signature, as returned by AWS KMS / Google Cloud KMS */
	private static byte[] der(BigInteger r, BigInteger s) {
		byte[] rb = r.toByteArray();
		byte[] sb = s.toByteArray();
		byte[] out = new byte[6 + rb.length + sb.length];
		out[0] = 0x30;
		out[1] = (byte)(4 + rb.length + sb.length);
		out[2] = 0x02;
		out[3] = (byte)rb.length;
		System.arraycopy(rb, 0, out, 4, rb.length);
		out[4 + rb.length] = 0x02;
		out[5 + rb.length] = (byte)sb.length;
		System.arraycopy(sb, 0, out, 6 + rb.length, sb.length);
		return out;
	}

	private static ECKeyPair newKeyPair() throws Exception {
		return ECKeyUtils.generateSecp256k1ECKeyPair();
	}

	@Test
	public void signsLikeLocalKeyForAllSignerOutputForms() throws Exception {
		ECKeyPair pair = newKeyPair();
		MetadiumKey local = new MetadiumKey(pair);
		byte[] message = "I authorize the creation of an Identity on my behalf.".getBytes();
		SignatureData expected = local.sign(message);

		for (int mode = 0; mode <= 4; mode++) {
			ExternalMetadiumKey external = new ExternalMetadiumKey(pair.getPublicKey(), keyStore(pair, mode));
			SignatureData actual = external.sign(message);
			assertEquals("mode " + mode, expected.getV()[0], actual.getV()[0]);
			assertArrayEquals("mode " + mode, expected.getR(), actual.getR());
			assertArrayEquals("mode " + mode, expected.getS(), actual.getS());
			assertTrue(external.verify(message, actual));
			assertEquals(local.getAddress(), external.getAddress());
			assertEquals(local.getPublicKey(), external.getPublicKey());
		}
	}

	@Test
	public void rejectsSignatureOfOtherKey() throws Exception {
		ECKeyPair pair = newKeyPair();
		ECKeyPair other = newKeyPair();
		ExternalMetadiumKey external = new ExternalMetadiumKey(pair.getPublicKey(), keyStore(other, 0));
		try {
			external.sign("message".getBytes());
			fail();
		}
		catch (IllegalStateException expected) {
		}
	}

	@Test
	public void rejectsUnsupportedSignatureForm() throws Exception {
		ECKeyPair pair = newKeyPair();
		DigestSigner bad = new DigestSigner() {
			@Override
			public byte[] signDigest(byte[] digest) {
				return new byte[10];
			}
		};
		try {
			new ExternalMetadiumKey(pair.getPublicKey(), bad).sign("message".getBytes());
			fail();
		}
		catch (IllegalStateException expected) {
		}
	}

	@Test
	public void jwsSignerAcceptsDerAndRejectsOtherKey() throws Exception {
		ECKeyPair pair = newKeyPair();
		ECKeyPair other = newKeyPair();
		MetadiumWallet wallet = new MetadiumWallet("did:meta:test:0000000000000000000000000000000000000000000000000000000000000001",
				new ExternalMetadiumKey(pair.getPublicKey(), keyStore(pair, 4)));
		Map<String, Object> claims = Collections.<String, Object>singletonMap("name", "x");
		String holder = "did:meta:test:0000000000000000000000000000000000000000000000000000000000000002";

		// DER signature of the right key
		ExternalMetadiumKey good = new ExternalMetadiumKey(pair.getPublicKey(), keyStore(pair, 4));
		SignedJWT jwt = wallet.issueCredential(Collections.singletonList("NameCredential"), null, null, null, holder, claims, good.getJWSSigner());
		ECDSAVerifier verifier = new ECDSAVerifier(ECKeyUtils.getPublicKey("04" + Numeric.toHexStringNoPrefixZeroPadded(pair.getPublicKey(), 128)));
		verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		assertTrue(jwt.verify(verifier));

		// a wrong key in the key store is detected when signing, not at the verifier
		ExternalMetadiumKey wrong = new ExternalMetadiumKey(pair.getPublicKey(), keyStore(other, 0));
		try {
			wallet.issueCredential(Collections.singletonList("NameCredential"), null, null, null, holder, claims, wrong.getJWSSigner());
			fail();
		}
		catch (JOSEException expected) {
		}
	}

	/** records the key given to the service key operations and stops before any network call */
	private static class SpyDelegator extends MetaDelegator {
		MetadiumKeyImpl received;

		@Override
		public String addKeyDelegated(MetadiumKeyImpl key, String serviceId, String serviceKeyAddress) {
			received = key;
			throw new IllegalStateException("stop");
		}

		@Override
		public String removeKeyDelegated(MetadiumKeyImpl key, String serviceId, String serviceKeyAddress) {
			received = key;
			throw new IllegalStateException("stop");
		}

		@Override
		public String removeKeysDelegated(MetadiumKeyImpl key) {
			received = key;
			throw new IllegalStateException("stop");
		}
	}

	@Test
	public void serviceKeyOperationsUseTheExternalKey() throws Exception {
		ECKeyPair pair = newKeyPair();
		MetadiumWallet wallet = new MetadiumWallet("did:meta:test:0000000000000000000000000000000000000000000000000000000000000001",
				new ExternalMetadiumKey(pair.getPublicKey(), keyStore(pair, 0)));
		String address = "0x0000000000000000000000000000000000000001";

		for (int i = 0; i < 3; i++) {
			SpyDelegator delegator = new SpyDelegator();
			try {
				if (i == 0) {
					wallet.addServiceKey(delegator, "service", address);
				}
				else if (i == 1) {
					wallet.removeServiceKey(delegator, "service", address);
				}
				else {
					wallet.removeAllServiceKey(delegator);
				}
				fail();
			}
			catch (DidException expected) {
				// not UnsupportedOperationException: the external key reached the delegator call
				assertTrue(expected.getCause() instanceof IllegalStateException);
			}
			assertSame(wallet.getKeyImpl(), delegator.received);
		}
	}

	@Test
	public void credentialSignedByExternalSignerIsVerifiable() throws Exception {
		ECKeyPair pair = newKeyPair();
		ExternalMetadiumKey external = new ExternalMetadiumKey(pair.getPublicKey(), keyStore(pair, 3));
		MetadiumWallet wallet = new MetadiumWallet("did:meta:test:0000000000000000000000000000000000000000000000000000000000000001", external);

		String vc = wallet.issueCredential(
				Collections.singletonList("StudentCredential"),
				URI.create("http://example.com/credential/1"),
				null, null, "did:meta:test:0000000000000000000000000000000000000000000000000000000000000002",
				Collections.<String, Object>singletonMap("name", "student"),
				external.getJWSSigner()).serialize();

		SignedJWT jwt = SignedJWT.parse(vc);
		ECDSAVerifier verifier = new ECDSAVerifier(ECKeyUtils.getPublicKey("04" + Numeric.toHexStringNoPrefixZeroPadded(pair.getPublicKey(), 128)));
		verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		assertTrue(jwt.verify(verifier));
		assertEquals(wallet.getKid(), jwt.getHeader().getKeyID());
		assertEquals(wallet.getDid(), new VerifiableCredential(jwt).getIssuer().toString());
	}

	@Test
	public void localKeyPathIsUnchanged() throws Exception {
		ECKeyPair pair = newKeyPair();
		MetadiumWallet wallet = new MetadiumWallet("did:meta:test:0000000000000000000000000000000000000000000000000000000000000001", new MetadiumKey(pair));

		SignedJWT jwt = wallet.issueCredential(
				Collections.singletonList("NameCredential"), null, null, null,
				"did:meta:test:0000000000000000000000000000000000000000000000000000000000000002",
				Collections.<String, Object>singletonMap("name", "x"));

		ECDSAVerifier verifier = new ECDSAVerifier(ECKeyUtils.getPublicKey("04" + Numeric.toHexStringNoPrefixZeroPadded(pair.getPublicKey(), 128)));
		verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		assertTrue(jwt.verify(verifier));
		assertEquals("ES256K", jwt.getHeader().getAlgorithm().getName());

		// toJson / fromJson / getKey keep working for local keys
		MetadiumWallet restored = MetadiumWallet.fromJson(wallet.toJson());
		assertEquals(wallet.getDid(), restored.getDid());
		assertEquals(pair.getPrivateKey(), restored.getKey().getPrivateKey());
	}

	@Test
	public void externalWalletHidesPrivateKeyApis() throws Exception {
		ECKeyPair pair = newKeyPair();
		MetadiumWallet wallet = new MetadiumWallet("did:meta:test:0000000000000000000000000000000000000000000000000000000000000001",
				new ExternalMetadiumKey(pair.getPublicKey(), keyStore(pair, 0)));
		try {
			wallet.getKey();
			fail();
		}
		catch (UnsupportedOperationException expected) {
		}
		try {
			wallet.toJson();
			fail();
		}
		catch (UnsupportedOperationException expected) {
		}
	}

	// ---- review: range check, public key check, wallet key check ----

	private static byte[] rs(BigInteger r, BigInteger s) {
		byte[] out = new byte[64];
		System.arraycopy(Numeric.toBytesPadded(r, 32), 0, out, 0, 32);
		System.arraycopy(Numeric.toBytesPadded(s, 32), 0, out, 32, 32);
		return out;
	}

	@Test
	public void rejectsOutOfRangeRandS() throws Exception {
		ECKeyPair pair = newKeyPair();
		BigInteger n = Sign.CURVE_PARAMS.getN();
		BigInteger max = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);
		BigInteger one = BigInteger.ONE;
		BigInteger[][] bad = {
			{BigInteger.ZERO, one}, {one, BigInteger.ZERO}, {n, one}, {one, n},
			{one, n.add(one)}, {max, one}, {one, max}
		};
		for (final BigInteger[] b : bad) {
			DigestSigner signer = new DigestSigner() {
				@Override
				public byte[] signDigest(byte[] digest) {
					return rs(b[0], b[1]);
				}
			};
			try {
				new ExternalMetadiumKey(pair.getPublicKey(), signer).sign("message".getBytes());
				fail("DID path " + b[0] + "," + b[1]);
			}
			catch (IllegalStateException expected) {
			}
			// a JWS signer without public key must not issue a wrong signature silently either
			try {
				new ExternalJWSSigner(signer).sign(new com.nimbusds.jose.JWSHeader(com.nimbusds.jose.JWSAlgorithm.ES256K), "a.b".getBytes());
				fail("JWS path " + b[0] + "," + b[1]);
			}
			catch (JOSEException expected) {
			}
		}
	}

	@Test
	public void validatesPublicKey() throws Exception {
		ECKeyPair pair = newKeyPair();
		DigestSigner signer = keyStore(pair, 0);
		byte[] xy = Numeric.toBytesPadded(pair.getPublicKey(), 64);
		byte[] withPrefix = new byte[65];
		withPrefix[0] = 0x04;
		System.arraycopy(xy, 0, withPrefix, 1, 64);
		byte[] compressed = Sign.CURVE_PARAMS.getCurve().decodePoint(withPrefix).getEncoded(true);
		// SubjectPublicKeyInfo DER of a secp256k1 key
		byte[] spkiHeader = Numeric.hexStringToByteArray("3056301006072a8648ce3d020106052b8104000a034200");
		byte[] spki = new byte[spkiHeader.length + 65];
		System.arraycopy(spkiHeader, 0, spki, 0, spkiHeader.length);
		System.arraycopy(withPrefix, 0, spki, spkiHeader.length, 65);

		byte[][] good = {xy, withPrefix, compressed, spki};
		for (byte[] g : good) {
			assertEquals(pair.getPublicKey(), ExternalMetadiumKey.fromPublicKeyBytes(g, signer).getPublicKey());
		}

		byte[] offCurve = xy.clone();
		offCurve[63] ^= 0x01;
		try {
			ExternalMetadiumKey.fromPublicKeyBytes(offCurve, signer);
			fail();
		}
		catch (IllegalArgumentException expected) {
		}
		for (BigInteger bad : new BigInteger[] {BigInteger.ZERO, BigInteger.valueOf(-1), BigInteger.ONE.shiftLeft(520), new BigInteger(1, withPrefix)}) {
			try {
				new ExternalMetadiumKey(bad, signer);
				fail("" + bad);
			}
			catch (IllegalArgumentException expected) {
			}
		}
		try {
			ExternalMetadiumKey.fromPublicKeyBytes(new byte[10], signer);
			fail();
		}
		catch (IllegalArgumentException expected) {
		}
		try {
			new ExternalMetadiumKey(pair.getPublicKey(), signer).signDigest(new byte[31]);
			fail();
		}
		catch (IllegalArgumentException expected) {
		}
	}

	@Test
	public void walletRejectsSignerOfAnotherKey() throws Exception {
		ECKeyPair pair = newKeyPair();
		ECKeyPair other = newKeyPair();
		MetadiumWallet wallet = new MetadiumWallet("did:meta:test:0000000000000000000000000000000000000000000000000000000000000001",
				new ExternalMetadiumKey(pair.getPublicKey(), keyStore(pair, 0)));
		// a perfectly valid signer, but of another key: kid points to the key of the wallet
		ExternalJWSSigner another = new ExternalMetadiumKey(other.getPublicKey(), keyStore(other, 0)).getJWSSigner();
		try {
			wallet.issueCredential(Collections.singletonList("NameCredential"), null, null, null,
					"did:meta:test:0000000000000000000000000000000000000000000000000000000000000002",
					Collections.<String, Object>singletonMap("name", "x"), another);
			fail();
		}
		catch (JOSEException expected) {
		}
	}

	@Test
	public void externalWalletSignsWithoutExplicitSigner() throws Exception {
		ECKeyPair pair = newKeyPair();
		MetadiumWallet wallet = new MetadiumWallet("did:meta:test:0000000000000000000000000000000000000000000000000000000000000001",
				new ExternalMetadiumKey(pair.getPublicKey(), keyStore(pair, 4)));

		SignedJWT jwt = wallet.issueCredential(Collections.singletonList("NameCredential"), null, null, null,
				"did:meta:test:0000000000000000000000000000000000000000000000000000000000000002",
				Collections.<String, Object>singletonMap("name", "x"));

		ECDSAVerifier verifier = new ECDSAVerifier(ECKeyUtils.getPublicKey("04" + Numeric.toHexStringNoPrefixZeroPadded(pair.getPublicKey(), 128)));
		verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		assertTrue(jwt.verify(verifier));
	}

	@Test
	public void getKeyReturnsNullWithoutKey() throws Exception {
		assertEquals(null, new MetadiumWallet("did:meta:test:1", (MetadiumKeyImpl)null).getKey());
	}

	// ---- review: signer failures in multi step operations ----

	private static final String DID = "did:meta:test:0000000000000000000000000000000000000000000000000000000000000001";

	/**
	 * web3j whose transactions succeed, except the ones listed: a receipt of a reverted transaction (status 0x0),
	 * and a receipt that cannot be read (IOException, like a timeout)
	 */
	private static Web3j scriptedWeb3j(final Set<String> unconfirmed, final Set<String> reverted) {
		return scriptedWeb3j(unconfirmed, reverted, false);
	}

	/** @param nodeError the unconfirmed receipt request is answered with an error object instead of failing with an IOException */
	private static Web3j scriptedWeb3j(final Set<String> unconfirmed, final Set<String> reverted, final boolean nodeError) {
		return (Web3j)Proxy.newProxyInstance(Web3j.class.getClassLoader(), new Class<?>[] {Web3j.class}, new InvocationHandler() {
			@Override
			public Object invoke(Object proxy, Method method, Object[] args) {
				if (!method.getName().equals("ethGetTransactionReceipt")) {
					throw new UnsupportedOperationException(method.getName());
				}
				if (unconfirmed.contains(args[0]) && nodeError) {
					final EthGetTransactionReceipt error = new EthGetTransactionReceipt();
					error.setError(new org.web3j.protocol.core.Response.Error(-32000, "node error"));
					return new Request<String, EthGetTransactionReceipt>() {
						@Override
						public EthGetTransactionReceipt send() {
							return error;
						}
					};
				}
				if (unconfirmed.contains(args[0])) {
					return new Request<String, EthGetTransactionReceipt>() {
						@Override
						public EthGetTransactionReceipt send() throws IOException {
							throw new IOException("timeout");
						}
					};
				}
				final TransactionReceipt receipt = new TransactionReceipt();
				receipt.setStatus(reverted.contains(args[0]) ? "0x0" : "0x1");
				receipt.setTransactionHash((String)args[0]);
				receipt.setBlockNumber("0x7");
				// a receipt of a real transaction has a (possibly empty) list of logs
				receipt.setLogs(Collections.<Log>emptyList());
				final EthGetTransactionReceipt response = new EthGetTransactionReceipt();
				response.setResult(receipt);
				return new Request<String, EthGetTransactionReceipt>() {
					@Override
					public EthGetTransactionReceipt send() {
						return response;
					}
				};
			}
		});
	}

	/** delegator without network. A call whose label is in {@code failing} throws like a signer that failed. */
	private static class ScriptedDelegator extends MetaDelegator {
		final List<String> calls = new ArrayList<String>();
		final List<String> failing = new ArrayList<String>();
		/** calls whose transaction is submitted but whose receipt cannot be read */
		final List<String> unconfirming = new ArrayList<String>();
		/** calls whose transaction reverts */
		final List<String> reverting = new ArrayList<String>();
		final Set<String> unconfirmedHashes = new HashSet<String>();
		final Set<String> revertedHashes = new HashSet<String>();
		final IdentityHashMap<MetadiumKeyImpl, String> names = new IdentityHashMap<MetadiumKeyImpl, String>();
		/** the receipt request of an unconfirmed call is answered with an error object */
		boolean nodeError;
		Web3j web3j;

		ScriptedDelegator() {
			this(false);
		}

		ScriptedDelegator(boolean nodeError) {
			this.nodeError = nodeError;
			this.web3j = scriptedWeb3j(unconfirmedHashes, revertedHashes, nodeError);
		}

		@Override
		public Web3j getWeb3j() {
			return web3j;
		}

		@Override
		public RegistryAddress getAllServiceAddress() {
			RegistryAddress address = new RegistryAddress();
			address.identityRegistry = "0x0000000000000000000000000000000000000001";
			return address;
		}

		private String call(String operation, MetadiumKeyImpl key) {
			String label = operation + "(" + names.get(key) + ")";
			calls.add(label);
			if (failing.contains(label)) {
				throw new IllegalStateException("signer failed at " + label);
			}
			String hash = "0x" + calls.size();
			if (unconfirming.contains(label)) {
				unconfirmedHashes.add(hash);
			}
			if (reverting.contains(label)) {
				revertedHashes.add(hash);
			}
			return hash;
		}

		@Override
		public String createIdentityDelegated(MetadiumKeyImpl key) {
			return call("createIdentity", key);
		}

		@Override
		public String addAssociatedAddressDelegated(MetadiumKeyImpl key, MetadiumKeyImpl addKey) {
			return call("addAssociated", addKey);
		}

		@Override
		public String addPublicKeyDelegated(MetadiumKeyImpl key, BigInteger publicKey) {
			return call("addPublicKey", key);
		}

		@Override
		public String removePublicKeyDelegated(MetadiumKeyImpl key) {
			return call("removePublicKey", key);
		}

		@Override
		public String removeAssociatedAddressDelegated(MetadiumKeyImpl key) {
			return call("removeAssociated", key);
		}
	}

	private static ExternalMetadiumKey newExternalKey() throws Exception {
		ECKeyPair pair = newKeyPair();
		return new ExternalMetadiumKey(pair.getPublicKey(), keyStore(pair, 0));
	}

	private static ScriptedDelegator scripted(ExternalMetadiumKey oldKey, ExternalMetadiumKey newKey) {
		return scripted(oldKey, newKey, false);
	}

	private static ScriptedDelegator scripted(ExternalMetadiumKey oldKey, ExternalMetadiumKey newKey, boolean nodeError) {
		ScriptedDelegator delegator = new ScriptedDelegator(nodeError);
		delegator.names.put(oldKey, "old");
		delegator.names.put(newKey, "new");
		return delegator;
	}

	@Test
	public void createDidWrapsSignerFailureInDidException() throws Exception {
		ExternalMetadiumKey key = newExternalKey();
		ScriptedDelegator delegator = scripted(key, newExternalKey());
		delegator.failing.add("createIdentity(old)");
		try {
			MetadiumWallet.createDid(delegator, key);
			fail();
		}
		catch (DidException expected) {
			assertTrue(expected.getCause() instanceof IllegalStateException);
		}
	}

	@Test
	public void updateKeyOfDidSucceedsAndSwitchesKey() throws Exception {
		ExternalMetadiumKey oldKey = newExternalKey();
		ExternalMetadiumKey newKey = newExternalKey();
		ScriptedDelegator delegator = scripted(oldKey, newKey);
		MetadiumWallet wallet = new MetadiumWallet(DID, oldKey);

		assertEquals(BigInteger.valueOf(7), wallet.updateKeyOfDid(delegator, newKey));
		assertSame(newKey, wallet.getKeyImpl());
		assertEquals(java.util.Arrays.asList("addAssociated(new)", "addPublicKey(new)", "removePublicKey(old)", "removeAssociated(old)"), delegator.calls);
	}

	@Test
	public void updateKeyOfDidRollsBackWhenSignerFails() throws Exception {
		ExternalMetadiumKey oldKey = newExternalKey();
		ExternalMetadiumKey newKey = newExternalKey();
		ScriptedDelegator delegator = scripted(oldKey, newKey);
		delegator.failing.add("removePublicKey(old)");
		MetadiumWallet wallet = new MetadiumWallet(DID, oldKey);

		try {
			wallet.updateKeyOfDid(delegator, newKey);
			fail();
		}
		catch (DidPartialFailureException e) {
			assertEquals(DID, e.getDid());
			assertEquals(2, e.getCompletedSteps().size());
			assertTrue(e.getUnrecoveredSteps().isEmpty());
			assertTrue(e.getCause() instanceof IllegalStateException);
		}
		// the compensation ran although the signer failed, and the wallet still has the old key
		assertEquals(java.util.Arrays.asList("addAssociated(new)", "addPublicKey(new)", "removePublicKey(old)", "removePublicKey(new)", "removeAssociated(new)"), delegator.calls);
		assertSame(oldKey, wallet.getKeyImpl());
	}

	@Test
	public void updateKeyOfDidKeepsRollingBackAndReportsUnrecoveredSteps() throws Exception {
		ExternalMetadiumKey oldKey = newExternalKey();
		ExternalMetadiumKey newKey = newExternalKey();
		ScriptedDelegator delegator = scripted(oldKey, newKey);
		// the old key was removed from the DID, then the signer fails for the old key: restoring it fails too
		delegator.failing.add("removeAssociated(old)");
		delegator.failing.add("addPublicKey(old)");
		MetadiumWallet wallet = new MetadiumWallet(DID, oldKey);

		try {
			wallet.updateKeyOfDid(delegator, newKey);
			fail();
		}
		catch (DidPartialFailureException e) {
			assertEquals(java.util.Arrays.asList("restore public_key of old key"), e.getUnrecoveredSteps());
			assertEquals(1, e.getCause().getSuppressed().length);
		}
		// later compensation steps are still tried after a failed one
		assertTrue(delegator.calls.contains("removePublicKey(new)"));
		assertTrue(delegator.calls.contains("removeAssociated(new)"));
	}

	@Test
	public void deleteDidKeepsTheCause() throws Exception {
		ExternalMetadiumKey key = newExternalKey();

		ScriptedDelegator first = scripted(key, newExternalKey());
		first.failing.add("removePublicKey(old)");
		try {
			new MetadiumWallet(DID, key).deleteDid(first);
			fail();
		}
		catch (DidException e) {
			assertTrue(!(e instanceof DidPartialFailureException));
			assertTrue(e.getCause() instanceof IllegalStateException);
		}

		ScriptedDelegator second = scripted(key, newExternalKey());
		second.failing.add("removeAssociated(old)");
		try {
			new MetadiumWallet(DID, key).deleteDid(second);
			fail();
		}
		catch (DidPartialFailureException e) {
			assertEquals(1, e.getCompletedSteps().size());
			assertEquals(java.util.Arrays.asList("remove associated_key"), e.getUnrecoveredSteps());
			assertTrue(e.getCause() instanceof IllegalStateException);
		}
	}

	// ---- follow-up of the review ----

	@Test
	public void createDidReportsPartialFailureWhenTheEventIsMissing() throws Exception {
		// create_identity succeeded but the receipt has no IdentityCreated event: the identity exists without a known DID
		ExternalMetadiumKey key = newExternalKey();
		ScriptedDelegator delegator = scripted(key, newExternalKey());
		try {
			MetadiumWallet.createDid(delegator, key);
			fail();
		}
		catch (DidPartialFailureException e) {
			assertEquals(1, e.getCompletedSteps().size());
			assertTrue(e.getCompletedSteps().get(0).startsWith("create_identity"));
			assertEquals(null, e.getDid());
			assertTrue(e.getUnrecoveredSteps().isEmpty());
			assertTrue(e.getMessage().contains("associated address was removed"));
			// the branch of a receipt without the IdentityCreated event, not an error while reading the logs
			assertTrue(String.valueOf(e.getCause()), e.getCause() instanceof DidException);
			assertTrue(e.getCause().getMessage().contains("bad event"));
		}
		// the compensation ran
		assertEquals(java.util.Arrays.asList("createIdentity(old)", "removeAssociated(old)"), delegator.calls);
	}

	@Test
	public void signingWithoutKeyThrowsJoseException() throws Exception {
		ECKeyPair pair = newKeyPair();
		MetadiumWallet keyless = new MetadiumWallet("did:meta:test:1", (MetadiumKeyImpl)null);
		String holder = "did:meta:test:0000000000000000000000000000000000000000000000000000000000000002";
		Map<String, Object> claims = Collections.<String, Object>singletonMap("name", "x");
		try {
			keyless.issueCredential(Collections.singletonList("NameCredential"), null, null, null, holder, claims);
			fail();
		}
		catch (JOSEException expected) {
		}
		try {
			keyless.issueCredential(Collections.singletonList("NameCredential"), null, null, null, holder, claims,
					new ExternalMetadiumKey(pair.getPublicKey(), keyStore(pair, 0)).getJWSSigner());
			fail();
		}
		catch (JOSEException expected) {
		}
	}

	// ---- structured steps of DidPartialFailureException ----

	private static void assertStep(DidStep step, DidStep.Operation operation, DidStep.Target target, DidStep.Status status) {
		assertEquals(operation, step.getOperation());
		assertEquals(target, step.getTarget());
		assertEquals(status, step.getStatus());
		assertTrue(step.getTxHash() != null && step.getTxHash().startsWith("0x"));
	}

	@Test
	public void stepsOfARevertedTransactionAndOfItsCompensation() throws Exception {
		ExternalMetadiumKey oldKey = newExternalKey();
		ExternalMetadiumKey newKey = newExternalKey();
		ScriptedDelegator delegator = scripted(oldKey, newKey);
		delegator.reverting.add("removePublicKey(old)");
		MetadiumWallet wallet = new MetadiumWallet(DID, oldKey);

		try {
			wallet.updateKeyOfDid(delegator, newKey);
			fail();
		}
		catch (DidPartialFailureException e) {
			List<DidStep> steps = e.getSteps();
			assertEquals(3, steps.size());
			assertStep(steps.get(0), DidStep.Operation.ADD_ASSOCIATED_ADDRESS, DidStep.Target.NEW_KEY, DidStep.Status.CONFIRMED);
			assertStep(steps.get(1), DidStep.Operation.ADD_PUBLIC_KEY, DidStep.Target.NEW_KEY, DidStep.Status.CONFIRMED);
			assertStep(steps.get(2), DidStep.Operation.REMOVE_PUBLIC_KEY, DidStep.Target.CURRENT_KEY, DidStep.Status.FAILED);
			assertEquals("0x3", steps.get(2).getTxHash());

			List<DidStep> compensation = e.getCompensationSteps();
			assertEquals(2, compensation.size());
			assertStep(compensation.get(0), DidStep.Operation.REMOVE_PUBLIC_KEY, DidStep.Target.NEW_KEY, DidStep.Status.CONFIRMED);
			assertStep(compensation.get(1), DidStep.Operation.REMOVE_ASSOCIATED_ADDRESS, DidStep.Target.NEW_KEY, DidStep.Status.CONFIRMED);
			assertTrue(e.getUnrecoveredSteps().isEmpty());
			// the text form is unchanged
			assertEquals(2, e.getCompletedSteps().size());
		}
		assertSame(oldKey, wallet.getKeyImpl());
	}

	@Test
	public void unconfirmedTransactionIsNotRolledBack() throws Exception {
		ExternalMetadiumKey oldKey = newExternalKey();
		ExternalMetadiumKey newKey = newExternalKey();
		ScriptedDelegator delegator = scripted(oldKey, newKey);
		delegator.unconfirming.add("removePublicKey(old)");
		MetadiumWallet wallet = new MetadiumWallet(DID, oldKey);

		try {
			wallet.updateKeyOfDid(delegator, newKey);
			fail();
		}
		catch (DidPartialFailureException e) {
			List<DidStep> steps = e.getSteps();
			assertEquals(3, steps.size());
			assertStep(steps.get(2), DidStep.Operation.REMOVE_PUBLIC_KEY, DidStep.Target.CURRENT_KEY, DidStep.Status.SUBMITTED_UNCONFIRMED);
			// it may still be mined: the other steps are not undone
			assertTrue(e.getCompensationSteps().isEmpty());
			assertEquals(1, e.getUnrecoveredSteps().size());
			assertTrue(e.getUnrecoveredSteps().get(0).startsWith("check REMOVE_PUBLIC_KEY"));
			assertTrue(e.getMessage().contains("nothing was rolled back"));
			assertTrue(e.getCause() instanceof DidException);
			assertTrue(e.getCause().getCause() instanceof IOException);
		}
		assertEquals(java.util.Arrays.asList("addAssociated(new)", "addPublicKey(new)", "removePublicKey(old)"), delegator.calls);
		assertSame(oldKey, wallet.getKeyImpl());
	}

	@Test
	public void nodeErrorOnTheReceiptRequestIsUnconfirmedToo() throws Exception {
		ExternalMetadiumKey oldKey = newExternalKey();
		ExternalMetadiumKey newKey = newExternalKey();
		ScriptedDelegator delegator = scripted(oldKey, newKey, true);
		delegator.unconfirming.add("addPublicKey(new)");
		MetadiumWallet wallet = new MetadiumWallet(DID, oldKey);

		try {
			wallet.updateKeyOfDid(delegator, newKey);
			fail();
		}
		catch (DidPartialFailureException e) {
			assertEquals(2, e.getSteps().size());
			assertStep(e.getSteps().get(1), DidStep.Operation.ADD_PUBLIC_KEY, DidStep.Target.NEW_KEY, DidStep.Status.SUBMITTED_UNCONFIRMED);
			assertTrue(e.getCompensationSteps().isEmpty());
			assertTrue(e.getUnrecoveredSteps().get(0).startsWith("check ADD_PUBLIC_KEY"));
		}
		// not rolled back: only the two submitted transactions
		assertEquals(java.util.Arrays.asList("addAssociated(new)", "addPublicKey(new)"), delegator.calls);
	}

	@Test
	public void createDidWithUnconfirmedFirstTransaction() throws Exception {
		ExternalMetadiumKey key = newExternalKey();
		ScriptedDelegator delegator = scripted(key, newExternalKey());
		delegator.unconfirming.add("createIdentity(old)");
		try {
			MetadiumWallet.createDid(delegator, key);
			fail();
		}
		catch (DidPartialFailureException e) {
			// the identity may exist although the DID is not known
			assertEquals(null, e.getDid());
			assertEquals(1, e.getSteps().size());
			assertStep(e.getSteps().get(0), DidStep.Operation.CREATE_IDENTITY, DidStep.Target.CURRENT_KEY, DidStep.Status.SUBMITTED_UNCONFIRMED);
			assertTrue(e.getCompensationSteps().isEmpty());
		}
		assertEquals(java.util.Arrays.asList("createIdentity(old)"), delegator.calls);
	}

	@Test
	public void createDidWithRevertedFirstTransactionIsAPlainFailure() throws Exception {
		ExternalMetadiumKey key = newExternalKey();
		ScriptedDelegator delegator = scripted(key, newExternalKey());
		delegator.reverting.add("createIdentity(old)");
		try {
			MetadiumWallet.createDid(delegator, key);
			fail();
		}
		catch (DidPartialFailureException e) {
			fail("a reverted create_identity changed nothing on-chain");
		}
		catch (DidException expected) {
			assertTrue(expected.getMessage().contains("Failed to create DID"));
		}
		// nothing to undo
		assertEquals(java.util.Arrays.asList("createIdentity(old)"), delegator.calls);
	}

	@Test
	public void deleteDidWithUnconfirmedTransactions() throws Exception {
		ExternalMetadiumKey key = newExternalKey();

		ScriptedDelegator first = scripted(key, newExternalKey());
		first.unconfirming.add("removePublicKey(old)");
		try {
			new MetadiumWallet(DID, key).deleteDid(first);
			fail();
		}
		catch (DidPartialFailureException e) {
			// the public key may be removed although no step is completed
			assertTrue(e.getCompletedSteps().isEmpty());
			assertStep(e.getSteps().get(0), DidStep.Operation.REMOVE_PUBLIC_KEY, DidStep.Target.CURRENT_KEY, DidStep.Status.SUBMITTED_UNCONFIRMED);
		}
		assertEquals(java.util.Arrays.asList("removePublicKey(old)"), first.calls);

		ScriptedDelegator second = scripted(key, newExternalKey());
		second.unconfirming.add("removeAssociated(old)");
		try {
			new MetadiumWallet(DID, key).deleteDid(second);
			fail();
		}
		catch (DidPartialFailureException e) {
			assertEquals(1, e.getCompletedSteps().size());
			assertEquals(2, e.getSteps().size());
			assertStep(e.getSteps().get(1), DidStep.Operation.REMOVE_ASSOCIATED_ADDRESS, DidStep.Target.CURRENT_KEY, DidStep.Status.SUBMITTED_UNCONFIRMED);
			assertTrue(e.getUnrecoveredSteps().get(0).startsWith("check REMOVE_ASSOCIATED_ADDRESS"));
		}
	}

	@Test
	public void partialFailureExceptionWithoutStepsKeepsWorking() {
		DidPartialFailureException e = new DidPartialFailureException("m", null, DID, java.util.Arrays.asList("a"), java.util.Arrays.asList("b"));
		assertEquals(java.util.Arrays.asList("a"), e.getCompletedSteps());
		assertTrue(e.getSteps().isEmpty());
		assertTrue(e.getCompensationSteps().isEmpty());
	}

	@Test
	public void unconfirmedCompensationStopsTheRestOfTheCompensation() throws Exception {
		ExternalMetadiumKey oldKey = newExternalKey();
		ExternalMetadiumKey newKey = newExternalKey();
		ScriptedDelegator delegator = scripted(oldKey, newKey);
		delegator.reverting.add("removeAssociated(old)");     // step 4 reverts, so the compensation starts
		delegator.unconfirming.add("addPublicKey(old)");      // the first compensation step (restore the old public key) is not confirmed
		MetadiumWallet wallet = new MetadiumWallet(DID, oldKey);

		try {
			wallet.updateKeyOfDid(delegator, newKey);
			fail();
		}
		catch (DidPartialFailureException e) {
			assertEquals(4, e.getSteps().size());
			assertStep(e.getSteps().get(3), DidStep.Operation.REMOVE_ASSOCIATED_ADDRESS, DidStep.Target.CURRENT_KEY, DidStep.Status.FAILED);
			assertEquals(1, e.getCompensationSteps().size());
			assertStep(e.getCompensationSteps().get(0), DidStep.Operation.ADD_PUBLIC_KEY, DidStep.Target.CURRENT_KEY, DidStep.Status.SUBMITTED_UNCONFIRMED);
			// the unconfirmed step is to be checked, and the steps that were not run are listed
			assertEquals(3, e.getUnrecoveredSteps().size());
			assertTrue(e.getUnrecoveredSteps().get(0).startsWith("check ADD_PUBLIC_KEY(CURRENT_KEY)"));
			assertEquals("remove public_key of new key (not run)", e.getUnrecoveredSteps().get(1));
			assertEquals("remove associated_key of new key (not run)", e.getUnrecoveredSteps().get(2));
			assertTrue(e.getMessage().contains("remaining compensation was not run"));
		}
		// removing the new key could leave the DID without any public key if the restore is never mined
		assertEquals(java.util.Arrays.asList("addAssociated(new)", "addPublicKey(new)", "removePublicKey(old)", "removeAssociated(old)", "addPublicKey(old)"), delegator.calls);
		assertSame(oldKey, wallet.getKeyImpl());
	}

	@Test
	public void unconfirmedCompensationOfCreateDidIsNotReportedAsRemaining() throws Exception {
		ExternalMetadiumKey key = newExternalKey();
		ScriptedDelegator delegator = scripted(key, newExternalKey());
		delegator.unconfirming.add("removeAssociated(old)");
		try {
			MetadiumWallet.createDid(delegator, key);
			fail();
		}
		catch (DidPartialFailureException e) {
			assertEquals(1, e.getCompensationSteps().size());
			assertStep(e.getCompensationSteps().get(0), DidStep.Operation.REMOVE_ASSOCIATED_ADDRESS, DidStep.Target.CURRENT_KEY, DidStep.Status.SUBMITTED_UNCONFIRMED);
			assertEquals(1, e.getUnrecoveredSteps().size());
			assertTrue(e.getUnrecoveredSteps().get(0).startsWith("check REMOVE_ASSOCIATED_ADDRESS"));
			// not "with its associated address": it is not known
			assertTrue(e.getMessage().contains("effect is unknown"));
			assertFalse(e.getMessage().contains("and with its associated address"));
		}
	}
}
