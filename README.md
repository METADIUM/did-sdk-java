# Metadium DID SDK for Java

DID 생성 및 키 관리 기능과 [Verifiable Credential](https://www.w3.org/TR/vc-data-model/) 의 서명과 검증에 대한 기능을 제공한다.

## Setup

SDK 는 필수사항으로 Java 1.8 을 요구한다.

Use Maven:

```xml
<properties>
	<maven.compiler.target>1.8</maven.compiler.target>
	<maven.compiler.source>1.8</maven.compiler.source>
</properties>

<!-- Add JitPack repository -->
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>

<dependency>
    <groupId>com.github.METADIUM</groupId>
    <artifactId>did-sdk-java</artifactId>
    <version>0.3.1</version>
    <!-- <version>0.3.1-android</version> --> <!-- android -->
</dependency>
```

Use Gradle:

```gradle
android {
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_1_8
        targetCompatibility JavaVersion.VERSION_1_8
    }

    dependencies {
        implementation 'com.github.METADIUM:did-sdk-java:0.3.1'
        //implementation 'com.github.METADIUM:did-sdk-java:0.3.1-android' // android
    }
}

allprojects {
    repositories {
        google()
        jcenter()
        maven { url "https://jitpack.io" }
    }
}
```

## Use it

* [Setup Network](#setup-network)
* [DID Operation](#did-operation)
    * [Create DID](#create-did)
    * [Update DID](#update-did)
    * [Delete DID](#delete-did)
    * [Add service key](#add-service-key)
    * [Remove service key](#remove-service-key)
    * [Get DID document](#get-did-document)
    * [Check DID](#check-did)
    * [Save wallet](#save-wallet)
    * [Load wallet](#load-wallet)
    
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

### DID Operation

DID 생성, 삭제, 키변경 과 service key 의 등록/삭제 기능을 제공한다.

#### Create DID

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
```

#### Update DID

DID 의 키를 새로운 키로 변경한다.

```java
wallet.updateKeyOfDid(delegator, new MetadiumKey());
```

#### Delete DID

DID 를 삭제한다.

```java
wallet.deleteDid(delegator);
```

#### Add service Key

Service key 를 추가한다.

```java
MetadiumKey serviceKey1 = new MetadiumKey();
wallet.addServiceKey(delegator, "serviceKey1", serviceKey1.getAddress());
```

#### Remove Service key

Service key 를 삭제한다.

```java
wallet.removeServiceKey(delegator, "serviceKey1", serviceKey1.getAddress())
```


#### Get DID document

DID Document 정보를 얻는다.

```java
DidDocument didDocument = wallet.getDidDocument();
```

##### Check DID

DID 가 블록체인에 존재하는지 확인한다.

```java
wallet.existsDid(delegator);
```

##### Save wallet

```java
// serialize
String walletJson = wallet.toJson();

// Java : wallet json 을 파일을 암호화 하여 저장한다.
//
// Android : wallet json 을 AndroidKeystore 로 암호화 하여 파일 또는 SharedPreference 에 저장한다.
//           https://developer.android.com/reference/androidx/security/crypto/package-summary 참조

```

##### Load wallet

```java
// Java : 파일 복호화
//
// Android : 파일 또는 SharedPreference 에서 복호화
//           https://developer.android.com/reference/androidx/security/crypto/package-summary 참조

// deserialize
MetadiumWallet newWallet = MetadiumWallet.fromJson(walletJson);
```

### Verifiable Credential

Verifiable credential, Verifiable presentation 을 발급 및 검증 하는 방법을 설명합니다.

#### Issue credential

verifiable credential 을 발급한다.  
발급자(issuer)는 DID 가 생성되어 있어야 하며 credential 의 이름(types), 사용자(holder)의 DID, 발급할 내용(claims) 가 필수로 필요하다.

```java
SignedJWT vc = wallet.issueCredential(
        Collections.singletonList("NameCredential"),               // types
        URI.create("http://aa.metadium.com/credential/name/343"),  // credential identifier. nullable
        issuanceDate,                                              // issuance date. nullable
        expirationDate,                                            // expiration date. nullable
        "did:meta:0000000...00001345",                             // did of holder 
        Collections.singletonMap("name", "YoungBaeJeon")           // claims
);
String serializedVC = vc.serialize();
```

#### Issue presentation

verifiable presentation 을 발급한다.  
사용자(holder)는 DID 가 생성되어 있어야 하며 검증자(verifier)에게 전달할 발급받은 credential 을 포함해야 한다.

```java
SignedJWT vp = userWallet.issuePresentation(
        Collections.singletonList("TestPresentation"),          // types
        URI.create("http://aa.metadium.com/presentation/343"),  // presentation identifier. nullable
        issuanceDate,                                           // issuance date. nullable
        expirationDate,                                         // expiration date. nullable
        Arrays.asList(serializedVC)                             // VC list
);
String serializedVP = vp.serialize();
```

#### Verify Credential or Presentation

네트워크가 메인넷이 안닌 경우 검증 전에 resolver URL 이 설정되어 있어야 정상적이 검증이 가능하다. [Setup Network 참조](#setup-network)  

사용자 또는 검증자가 credential 또는 presentation 을 검증을 한다.

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

#### Get Verifiable credentials from presentation

presentation 에 나열되어 있는 credential 내역을 가져온다. 

```java
VerifiablePresentation vpObj = new VerifiablePresentation(vp);
String holderDid = vpObj.getHolder().toString();    // did of holder
URI vpId = vpObj.getId();                           // identifier of presentation
for (Object o : vpId.getVerifiableCredentials()) {
    String serializedVc = (String)o;
}
```

#### Get claim set from credential

verifiable credential 에 나열되어 있는 claim 의 내역을 가져온다.

```java
VerifiableCredential credential = new VerifiableCredential(vc);
Map<String, String> subjects = vc.getCredentialSubject();
for (Map.Entry<String, String> entry : subjects.entrySet()) {
    String claimName = entry.getKey();
    String claimValue = entry.getValue();
}
```




