# Metadium DID SDK for Java

English | [한국어](README.ko.md)

A Java / Android SDK for creating and managing DIDs, and for signing and verifying [Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) and Verifiable Presentations on the Metadium network.

## Terminology

- **DID (Decentralized Identifier)**
    - A concept that makes personal data verifiable without going through a centralized authority.
    - [W3C DID Spec](https://www.w3.org/TR/did-core/)
- **Claim**
    - A single unit of data, for example a name or a date of birth together with its value.
    - [W3C VC Claims](https://www.w3.org/TR/vc-data-model/#claims)
- **Verifiable Credential (VC)**
    - A tamper-proof credential that contains the issuer, an expiration date, a set of claims and the issuer's signature. Examples are mobile-phone identity verification or a digital ID.
    - The issuer verifies the user's information, issues the credential and hands it to the user.
    - [W3C VC Credential](https://www.w3.org/TR/vc-data-model/#credentials)
- **Verifiable Presentation (VP)**
    - A tamper-proof presentation that contains one or more Verifiable Credentials and the owner's signature. The owner uses it to submit credentials to a verifier.
    - [W3C VC Presentation](https://www.w3.org/TR/vc-data-model/#presentations)

## DID Workflow

![Workflow](images/DIDWorkflow.jpg)

1. The issuer and the holder create DIDs beforehand so that they can issue credentials and presentations.
    - [Create DID](#create-did)
2. The holder requests a credential from the issuer and sends the DID to prove who the credential owner is.
    - If the DID itself must be verified, the holder sends a presentation that contains no credential.
    - [Issue presentation](#issue-presentation)
3. The issuer checks the holder's DID. If it was submitted as a presentation, the issuer verifies the presentation.
    - [Verify credential or presentation](#verify-credential-or-presentation)
4. The issuer issues a credential that contains the confirmed claims. The holder keeps it in a safe storage.
    - [Issue credential](#issue-credential)
5. The holder finds the credentials the verifier requires and submits them as a presentation.
    - [Issue presentation](#issue-presentation)
6. The verifier checks that the presentation was sent by the holder and that the credentials come from the required issuers.
    - [Verify credential or presentation](#verify-credential-or-presentation)

[Full test code](src/test/java/com/metadium/did/WorkflowTest.java)

## SDK Setup

Java 1.8 is required.

Maven:

```xml
<properties>
	<maven.compiler.target>1.8</maven.compiler.target>
	<maven.compiler.source>1.8</maven.compiler.source>
</properties>

<!-- Use the JitPack repository -->
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>

<dependency>
    <groupId>com.github.METADIUM</groupId>
    <artifactId>did-sdk-java</artifactId>
    <version>0.3.3</version>
    <!-- <version>0.3.3-android</version> --> <!-- Use this version for Android -->
</dependency>
```

Gradle:

```gradle
android {
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_1_8
        targetCompatibility JavaVersion.VERSION_1_8
    }

    dependencies {
        implementation 'com.github.METADIUM:did-sdk-java:0.3.3'
        //implementation 'com.github.METADIUM:did-sdk-java:0.3.3-android' // Use this version for Android
    }
}

allprojects {
    repositories {
        google()
        jcenter()
        maven { url "https://jitpack.io" }  // Use the JitPack repository
    }
}
```

> The [external key store support](#external-key-store) is not part of release 0.3.3. Use a release that includes it.

If you get ``java.lang.NoSuchMethodError: okhttp3.RequestBody.create(Ljava/lang/String;Lokhttp3/MediaType;)Lokhttp3/RequestBody;`` at runtime, add okhttp3:

```xml
<dependency>
	<groupId>com.squareup.okhttp3</groupId>
	<artifactId>okhttp</artifactId>
	<version>4.9.0</version>
</dependency>
```

## Usage

* [Setup network](#setup-network)
* [DID operations](#did-operation)
    * [Create DID](#create-did)
    * [Delete DID](#delete-did)
    * [Get DID document](#get-did-document)
    * [Check DID](#check-did)
    * [Save wallet](#save-wallet)
    * [Load wallet](#load-wallet)
    * [Signing](#signing)
* [External key store](#external-key-store)
    * [Create DID with an external key](#create-did-with-an-external-key)
    * [Issue credential or presentation with an external key](#issue-credential-or-presentation-with-an-external-key)
    * [Signature format](#signature-format)
* [Verifiable Credential](#verifiable-credential)
    * [Issue credential](#issue-credential)
    * [Issue presentation](#issue-presentation)
    * [Verify credential or presentation](#verify-credential-or-presentation)
    * [Get verifiable credentials from presentation](#get-verifiable-credentials-from-presentation)
    * [Get claims from credential](#get-claims-from-credential)

### Setup Network

Configure the network used to create and use DIDs: the end-points of the delegator, the node and the resolver, and the DID prefix.

To use the Metadium mainnet or testnet, you need an API key issued by Metadium.

```java
String apiKey = "......"; // must be issued

// Metadium mainnet
MetaDelegator delegator = new MetaDelegator(apiKey);

// Metadium testnet
MetaDelegator delegator = new MetaDelegator("https://testdelegator.metadium.com", "https://api.metadium.com/dev", "did:meta:testnet", apiKey);
DIDResolverAPI.getInstance().setResolverUrl("https://testnetresolver.metadium.com/1.0/");

// Custom (private) network: set each end-point of that network
MetaDelegator delegator = new MetaDelegator("https://custom.delegator.metadium.com", "https://custom.api.metadium.com", "did:meta:custom");
DIDResolverAPI.getInstance().setResolverUrl("https://custom.resolver.metadium.com/1.0/");
```

### DID Operation

#### Create DID

Generates a secp256k1 key pair and creates a DID with that key.

```java
// Create a DID with a random key
MetadiumWallet wallet = MetadiumWallet.createDid(delegator);

// Read the created DID information from the wallet
MetadiumKey key = wallet.getKey();                             // The private key that created the DID
String did = wallet.getDid();                                  // ex) did:meta:00000000000000000000000000000000000000000000000000000000000432a0
String kid = wallet.getKid();                                  // key id. ex) did:meta:00000000000000000000000000000000000000000000000000000000000432a0#MetaManagementKey#234f9445cd405a2a454245b94f7bc5e9286912eb
BigInteger privateKey = wallet.getKey().getPrivateKey();       // EC private key as BigInteger
ECPrivateKey ecPrivateKey = wallet.getKey().getECPrivateKey(); // EC private key as ECPrivateKey
```

To create a DID with a key that is kept in an external key store, see [External key store](#external-key-store).

#### Delete DID

```java
wallet.deleteDid(delegator);
```

#### Get DID document

```java
DidDocument didDocument = wallet.getDidDocument();
```

##### Check DID

Checks that the DID exists on the blockchain.

```java
wallet.existsDid(delegator);
```

##### Save wallet

```java
// serialize
String walletJson = wallet.toJson();

// Java    : encrypt the wallet JSON and save it to a file.
//
// Android : encrypt the wallet JSON with the Android Keystore and save it to a file or SharedPreferences.
//           See https://developer.android.com/reference/androidx/security/crypto/package-summary
```

`toJson()` serializes the private key. It throws `UnsupportedOperationException` for a wallet whose key is held by an [external key store](#external-key-store).

##### Load wallet

```java
// Java    : decrypt the file
//
// Android : decrypt the file or SharedPreferences
//           See https://developer.android.com/reference/androidx/security/crypto/package-summary

// deserialize
MetadiumWallet newWallet = MetadiumWallet.fromJson(walletJson);
```

#### Signing

Signs with the DID's key using [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm).

```java
byte[] message = "message".getBytes();
SignatureData signature = wallet.getKeyImpl().sign(message); // wallet.getKey().sign(message) also works for a local key
```

Example that converts the signature to a hex string:

```java
public static String signatureDataToString(Sign.SignatureData signatureData) {
    ByteBuffer buffer = ByteBuffer.allocate(65);
    buffer.put(signatureData.getR());
    buffer.put(signatureData.getS());
    buffer.put(signatureData.getV());
    return Numeric.toHexString(buffer.array());
}
```

### External key store

The private key can stay in an external key store (HSM, KMS or a wallet service) and never be given to the SDK. The SDK only needs the public key and a callback that signs a 32-byte digest.

#### Create DID with an external key

Implement `DigestSigner` with a call to your key store, then pass an `ExternalMetadiumKey` to `MetadiumWallet.createDid`.

```java
// Signs the digest as-is with the secp256k1 private key held by the key store.
// Return r||s (64 bytes), r||s||v (65 bytes) or ASN.1 DER (as AWS KMS and Google Cloud KMS return).
DigestSigner signer = digest -> keyStoreClient.signDigest(keyId, digest);

// The public key bytes as the key store returns them: X||Y (64 bytes), 0x04||X||Y (65 bytes),
// compressed (33 bytes) or X.509 SubjectPublicKeyInfo DER (AWS KMS, Google Cloud KMS GetPublicKey).
// The point must be on the secp256k1 curve, otherwise IllegalArgumentException is thrown.
ExternalMetadiumKey key = ExternalMetadiumKey.fromPublicKeyBytes(keyStoreClient.getPublicKey(keyId), signer);

MetadiumWallet wallet = MetadiumWallet.createDid(delegator, key);   // registers the DID through the delegator
String did = wallet.getDid();
```

Notes:

* The key store does not have to return `v`. The SDK recovers it from the public key, and also converts a high `s` to the canonical (low-s) form.
* DER signatures (AWS KMS, Google Cloud KMS) are accepted as they are; no conversion is needed.
* The signature is checked against the public key. If the key store signs with a different key, signing fails right away instead of producing a credential that only fails at the verifier: `DidException` (with `IllegalStateException` as the cause) when it happens inside a wallet operation such as `createDid`, `IllegalStateException` when you call `ExternalMetadiumKey#sign` yourself, and `JOSEException` for VC / VP.
* `wallet.getKey()` and `wallet.toJson()` throw `UnsupportedOperationException` because there is no private key. Use `wallet.getKeyImpl()`.
* `updateKeyOfDid`, `deleteDid`, `addServiceKey` and the other wallet operations work the same way with an external key. `MetaDelegator` methods accept `MetadiumKeyImpl`.
* To restore a wallet later, create it with the stored DID and the key: `new MetadiumWallet(did, key)`.
* `DigestSigner` is called synchronously on the calling thread and is usually a network call. Do not call it from the UI thread (Android).
* Use a key that is dedicated to DID. The key store signs arbitrary 32-byte digests, so the same key must not also sign blockchain transactions.

##### Failures
Signing with an external key store can fail at any step of an operation made of several transactions (create DID, update key, delete DID). The SDK throws `DidException` for every failure, with the original failure as the cause. If some transactions were already done, it throws `DidPartialFailureException`:

* `getDid()`, `getCompletedSteps()` (with transaction hashes) and `getUnrecoveredSteps()`.
* `createDid` and `updateKeyOfDid` try to undo the completed steps. Every compensation step is tried even if a previous one failed; their errors are attached to the cause as suppressed exceptions. `getUnrecoveredSteps()` is empty when everything was rolled back, and lists the steps that still have to be done otherwise.
* `deleteDid` does not roll back. If only the public key was removed, `getUnrecoveredSteps()` contains `remove associated_key`.
* Compensation also runs when the external signer throws, not only when a transaction fails.

#### Issue credential or presentation with an external key

`ExternalMetadiumKey#getJWSSigner()` returns an ES256K `JWSSigner` that uses the same `DigestSigner` and checks the signature against the public key.

```java
JWSSigner jwsSigner = key.getJWSSigner();

SignedJWT vc = wallet.issueCredential(
        Collections.singletonList("StudentCredential"),
        URI.create("http://aa.metadium.com/credential/student/1"),
        issuanceDate,
        expirationDate,
        holderDid,
        claims,
        jwsSigner                       // signer of the external key store
);

SignedJWT vp = wallet.issuePresentation(types, id, issuanceDate, expirationDate, vcList, jwsSigner);

// Any Verifiable can be signed directly
SignedJWT jwt = wallet.sign(verifiable, claimsSet, jwsSigner);
```

The `JWSSigner` you pass is checked against the key of the wallet: the signature must verify with the public key of the wallet, otherwise `JOSEException` is thrown, because the `kid` of the credential points to that key.

The methods without a signer sign with the local private key, and with the key store when the wallet holds an `ExternalMetadiumKey`.

`new ExternalJWSSigner(DigestSigner)` (without a public key) is deprecated because it cannot detect a key store that signs with another key; use `ExternalMetadiumKey#getJWSSigner()`.

#### Smoke test in a real environment

[`RealEnvironmentSmokeTest`](src/test/java/com/metadium/did/smoke/RealEnvironmentSmokeTest.java) checks the external key store support against a real delegator, node and resolver. It is skipped unless `smoke.delegator` is set.

1. **Dry run (does not write to the chain).** The delegator and the node answer, and a signature of another key is refused before a transaction is sent:

```bash
mvn test -Dtest='RealEnvironmentSmokeTest#readOnlyDryRun' \
  -Dsmoke.delegator=https://delegator.example.com \
  -Dsmoke.node=https://node.example.com \
  -Dsmoke.resolver=https://resolver.example.com/1.0/ \
  -Dsmoke.prefix=did:meta:gov
```

2. **Lifecycle (WRITES to the chain).** It creates two DIDs (a student and an issuer), checks them with the node and the resolver, issues a VC and a VP and verifies them, updates the key of the student and verifies a VP signed by the new key, then deletes both DIDs (also after a failure, best effort). It prints the time of every step and how many times each key was asked to sign. It fails unless you confirm:

```bash
mvn test -Dtest='RealEnvironmentSmokeTest#externalKeyStoreLifecycle' \
  -Dsmoke.delegator=... -Dsmoke.node=... -Dsmoke.resolver=... -Dsmoke.prefix=... \
  -Dsmoke.apiKey=...          `# if the delegator needs one` \
  -Dsmoke.confirm=yes
```

By default the keys are in memory, so the path to the delegator, the node and the resolver can be checked before the real key store is available. To use the real key store, write a class that implements [`SmokeKeyStore`](src/test/java/com/metadium/did/smoke/SmokeKeyStore.java) (it returns the public key and a `DigestSigner` for the keys `student`, `student-new` and `issuer`) and add `-Dsmoke.keystore=com.example.MyKeyStore`. Use keys that are dedicated to the test.

#### Signature format

| Use | What is signed | Hash | Result |
|---|---|---|---|
| Delegator requests (create DID, add / remove key, ...) | The request message, `keccak256(0x19 ‖ 0x00 ‖ ...)` | keccak256, calculated by the SDK | `DigestSigner` receives the 32-byte keccak256 digest. The SDK builds `r`, `s`, `v` (27 or 28). |
| VC / VP (JWS, `ES256K`) | The JWS signing input | SHA-256, calculated by the SDK | `DigestSigner` receives the 32-byte SHA-256 digest. The SDK uses `r‖s` (64 bytes, low-s). |

The `DigestSigner` always receives the final digest and must sign it as-is, with no additional hashing.

The Metadium delegator server accepts a signature over the digest itself, and also a signature over the digest with the `\x19Ethereum Signed Message:\n32` prefix (`verifySignature` in `metaresolver/util.go` of [METADIUM/go-delegator](https://github.com/METADIUM/go-delegator/blob/64ac5a93485556ed59872e215dc9f2602d35d7eb/metaresolver/util.go#L15-L32) tries both). This was read from the delegator source; the SDK was not run against a delegator with an external key store. This SDK signs the digest itself (same as `MetadiumKey#sign`). did-sdk-swift signs the prefixed personal-message hash instead, so a key store used from both SDKs receives a different digest in each, and both are accepted by the delegator.

[Tests that use a simulated key store](src/test/java/com/metadium/did/ExternalSignerTest.java)

### Verifiable Credential

How to issue and verify verifiable credentials and verifiable presentations.

#### Issue credential

The issuer must have a DID. The credential name (types), the holder's DID and the content (claims) are required.

Example of a credential that contains several claims:

```java
// set claims
Map<String, Object> claims = new HashMap<>();
claims.put("name", "YoungBaeJeon");
claims.put("birth", "19800101");
claims.put("id", "800101xxxxxxxx");

SignedJWT vc = wallet.issueCredential(
        Collections.singletonList("PersonalIdCredential"),         // types : name of the credential. Must end with "Credential".
        URI.create("http://aa.metadium.com/credential/name/343"),  // id : unique URL to verify the credential. Optional.
        issuanceDate,                                              // issuance date
        expirationDate,                                            // expiration date
        "did:meta:0000000...00001345",                             // ownerDid (the holder's DID)
        claims                                                     // claims
);
String personalIdVC = vc.serialize();
```

The credential has to be submitted to the verifier as it is, so the holder cannot send only some claims or hide unnecessary ones.

To let the verifier ask for particular claims, the issuer has to issue one credential per claim:

```java
SignedJWT vc = wallet.issueCredential(
        Arrays.asList("PersonalIdCredential", "NameCredential"),   // NameCredential of PersonalIdCredential
        URI.create("http://aa.metadium.com/credential/name/343"),
        issuanceDate,
        expirationDate,
        "did:meta:0000000...00001345",
        Collections.singletonMap("name", "YoungBaeJeon")
);
String nameVC = vc.serialize();

SignedJWT vc = wallet.issueCredential(
        Arrays.asList("PersonalIdCredential", "BirthCredential"),  // BirthCredential of PersonalIdCredential
        URI.create("http://aa.metadium.com/credential/name/343"),
        issuanceDate,
        expirationDate,
        "did:meta:0000000...00001345",
        Collections.singletonMap("birth", "19800101")
);
String birthVC = vc.serialize();

SignedJWT vc = wallet.issueCredential(
        Arrays.asList("PersonalIdCredential", "IdCredential"),     // IdCredential of PersonalIdCredential
        URI.create("http://aa.metadium.com/credential/name/343"),
        issuanceDate,
        expirationDate,
        "did:meta:0000000...00001345",
        Collections.singletonMap("id", "800101xxxxxxxx")
);
String idVC = vc.serialize();
```

#### Issue presentation

Issues a presentation that contains the list of credentials to submit. The verifier tells the holder which credential types are required, the holder submits the matching credentials as a presentation, and the verifier verifies it.

A verifier requests two credentials (an ID card and a driver license) and the holder issues a presentation:

```java
// Verifier request example: {"types":["TestPresentation"], "vc":[["PersonalIdCredential"], ["DriverLicenseCredential"]]}
List<String> holderAllVc = ..; // all credentials of the holder

List<String> foundVcList = findVC(holderAllVc, Arrays.asList(Arrays.asList("PersonalIdCredential"), Arrays.asList("DriverLicenseCredential")));

SignedJWT vp = userWallet.issuePresentation(
        Collections.singletonList("TestPresentation"),          // name of the presentation. Must end with "Presentation"; the verifier specifies it.
        URI.create("http://aa.metadium.com/presentation/343"),  // id : unique URL to verify the presentation. Optional.
        issuanceDate,                                           // issuance date
        expirationDate,                                         // expiration date
        foundVcList                                             // credentials to submit
);
String serializedVP = vp.serialize();
```

If one credential contains several claims, the verifier cannot ask for a particular claim. When credentials are issued per claim, only the name and id of an ID card can be requested like this:

```java
// Verifier request example: {"types":["TestPresentation"], "vc":[["PersonalIdCredential", "NameCredential"], ["PersonalIdCredential", "IdCredential"]]}
List<String> holderAllVc = ..; // all credentials of the holder

List<String> foundVcList = findVC(holderAllVc, Arrays.asList(Arrays.asList("PersonalIdCredential", "NameCredential"), Arrays.asList("PersonalIdCredential", "IdCredential")));

SignedJWT vp = userWallet.issuePresentation(
        Collections.singletonList("TestPresentation"),
        URI.create("http://aa.metadium.com/presentation/343"),
        issuanceDate,
        expirationDate,
        foundVcList
);
String serializedVP = vp.serialize();
```

Example that finds the credentials the verifier requires:

```java
/**
 * @param holderVcList      credentials of the holder
 * @param typesOfRequireVcs credential types required by the verifier
 */
public List<String> findVC(List<String> holderVcList, List<List<String>> typesOfRequireVcs) throws ParseException {
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
```

#### Verify credential or presentation

If the network is not the mainnet, set the resolver URL before verifying. See [Setup network](#setup-network).

```java
Verifier verifier = new Verifier();

// Parse the received signed credential
SignedJWT vc = SignedJWT.parse(serializedVC);

// Verify the credential
if (!verifier.verify(vc)) {
    // verification failed
}
else if (vc.getJWTClaimsSet().getExpirationTime() != null && vc.getJWTClaimsSet().getExpirationTime().getTime() < new Date().getTime()) {
    // expired
}
```

#### Get verifiable credentials from presentation

```java
VerifiablePresentation vpObj = new VerifiablePresentation(SignedJWT.parse(serializedVp));
String holderDid = vpObj.getHolder().toString();    // the holder who submitted the presentation
URI vpId = vpObj.getId();                           // presentation ID
for (Object o : vpObj.getVerifiableCredentials()) {
    String serializedVc = (String)o;
}
```

#### Get claims from credential

```java
VerifiableCredential credential = new VerifiableCredential(SignedJWT.parse(serializedVc));
Map<String, String> subjects = credential.getCredentialSubject();
for (Map.Entry<String, String> entry : subjects.entrySet()) {
    String claimName = entry.getKey();
    String claimValue = entry.getValue();
}
```
