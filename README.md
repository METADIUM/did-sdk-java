# Metadium DID SDK for Java

## Get it

Require Java 1.8

### Maven
Add the JitPack repository to build file

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>
```

Add dependency

```xml
<dependency>
    <groupId>com.github.METADIUM</groupId>
    <artifactId>did-sdk-java</artifactId>
    <version>0.3.0</version>
    <!-- <version>0.3.0-android</version> --> <!-- android -->
</dependency>
```
### Gradle
Add root build.gradle

```gradle
allprojects {
    repositories {
        maven { url 'https://jitpack.io' }
    }
}
```
Add dependency

```gradle
dependencies {
    implementation 'com.github.METADIUM:did-sdk-java:0.3.0'
    //implementation 'com.github.METADIUM:did-sdk-java:0.3.0-android' // android
}
```


## Use it

* [Setup Network](#setup-network)
* DID
    * [Create DID](#create-did)
    * [Update DID](#update-did)
    * [Delete DID](#delete-did)
    * [Service Key](#service-key)
        * [Add](#add-service-key)
        * [Remove](#remove-service-key)
* [Verifiable Credential](#verifiable-credential)
    * [Issue credential](#issue-credential)
    * [Issue presentation](#issue-presentation)
    * [Verify credential / presentation](#verify-credential-or-presentation)
    * [Get Verifiable credentials from presentation](#get-verifiable-credentials-from-presentation)
    * [Get claim set from credential](#get-claim-set-from-credential)


### Setup Network

Delegator, Node, Resolver 의 end-point 와 did prefix 를 설정한다.

```java
// Metadium Mainnet. default
MetaDelegator delegator = new MetaDelegator();

// Metadium Testnet. 
MetaDelegator delegator = new MetaDelegator("https://testdelegator.metadium.com", "https://api.metadium.com/dev", "did:meta:testnet");
DIDResolverAPI.getInstance().setResolverUrl("https://testnetresolver.metadium.com/1.0/");

// Custom network.
MetaDelegator delegator = new MetaDelegator("https://custom.delegator.metadium.com", "https://custom.api.metadium.com", "did:meta:custom");
DIDResolverAPI.getInstance().setResolverUrl("https://custom.resolver.metadium.com/1.0/");
```

### Create DID

Secp256k1 key pair 를 생성하고 해당 키로 DID 를 생성한다.

```java
// Create DID
MetaDelegator delegator = new MetaDelegator();
MetadiumWallet wallet = MetadiumWallet.createDid(delegator);

// Getter
String did = wallet.getDid();                                  // Getting did
String kid = wallet.getKid();                                  // Getting key id
MetadiumKey key = wallet.getKey();                             // Getting key
BigInteger privateKey = wallet.getKey().getPrivateKey();       // Getting EC private key. bigint
ECPrivateKey ecPrivateKey = wallet.getKey().getECPrivateKey(); // Getting EC private key. ECPrivateKey

// serialize / deserialize
String walletJson = wallet.toJson();
MetadiumWallet newWallet = MetadiumWallet.fromJson(walletJson);
```

### Update DID

해당 DID 의 키를 변경한다. (associated_key, public_key)

```java
wallet.updateKeyOfDid(delegator, new MetadiumKey());
```

### Service Key

Service key 를 추가하거나 삭제할 수 있다.

##### Add Service key

```java
MetadiumKey serviceKey1 = new MetadiumKey();
wallet.addServiceKey(delegator, "serviceKey1", serviceKey1.getAddress());
```

##### Remove Service key

```java
wallet.removeServiceKey(delegator, "serviceKey1", serviceKey1.getAddress())
```


### Delete DID

DID 를 삭제

```java
wallet.deleteDid(delegator);
```

### Read DID

##### DID Document 정보를 얻는다.

```java
DidDocument didDocument = wallet.getDidDocument();
```

##### DID가 체인상에 존재하는지 확인

```java
wallet.existsDid(delegator);
```

### Verifiable Credential

Verifiable credential, Verifiable presentation 을 발급 및 검증을 한다.

##### Issue credential

verifiable credential 을 발급한다.

```java
SignedJWT vc = wallet.issueCredential(
        Collections.singletonList("NameCredential"),               // types
        URI.create("http://aa.metadium.com/credential/name/343"),  // credential identifier
        issuanceDate,                                              // issuance date. nullable
        expirationDate,                                            // expiration date. nullable
        "did:meta:0000000...00001345",                             // did of holder 
        Collections.singletonMap("name", "YoungBaeJeon")           // claims
);
String serializedVC = vc.serialize();
```

##### issue presentation

verifiable presentation 을 발급한다.

```java
SignedJWT vp = userWallet.issuePresentation(
        Collections.singletonList("TestPresentation"),          // types
        URI.create("http://aa.metadium.com/presentation/343"),  // presentation identifier
        issuanceDate,                                           // issuance date. nullable
        expirationDate,                                         // expiration date. nullable
        Arrays.asList(serializedVC)                             // VC list
);
String serializedVP = vp.serialize();
```

##### Verify Credential or Presentation

네트워크가 메인넷이 안닌 경우 검증 전에 resolver URL 이 설정되어 있어야 정상적이 검증이 가능하다.

```java
Verifier verifier = new Verifier();

// verify signature of JWT
SignedJWT vc = SignedJWT.parse(serializedVC);
if (!verifier.verify(vc)) {
    // signature 검증 실패
}
else if (vc.getJWTClaimsSet().getExpirationTime() != null && vc.getJWTClaimsSet().getExpirationTime().getTime() > new Date().getTime()) {
    // 유효기간 초과
}
```

##### Get Verifiable credentials from presentation

verifiable presentation 에 나열되어 있는 verifiable credential 내역을 가져온다.

```java
VerifiablePresentation vpObj = new VerifiablePresentation(vp);
String holderDid = vpObj.getHolder().toString();    // did of holder
URI vpId = vpObj.getId();                           // identifier of presentation
for (Object o : vpId.getVerifiableCredentials()) {
    String serializedVc = (String)o;
}
```

##### Get claim set from credential

verifiable credential 에 나열되어 있는 claim 의 내역을 가져온다.

```java
VerifiableCredential credential = new VerifiableCredential(vc);
Map<String, String> subjects = vc.getCredentialSubject();
for (Map.Entry<String, String> entry : subjects.entrySet()) {
    String claimName = entry.getKey();
    String claimValue = entry.getValue();
}
```




