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
    <version>0.1.3</version>
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
    implementation 'com.github.METADIUM:did-sdk-java:0.1.3'
}
```


## Use it

### Create DID

```java
// Create DID
MetaDelegator delegator = new MetaDelegator(); // default mainnet
MetadiumWallet wallet = MetadiumWallet.createDid(delegator);

// Getter
String did = wallet.getDid();	// Getting did
String kid = wallet.getKid();  // Getting key id
MetadiumKey key = wallet.getKey(); // Getting key
BigInteger privateKey = wallet.getKey().getPrivateKey(); // Getting ec private key. bigint
ECPrivateKey ecPrivateKey = wallet.getKey().getECPrivateKey(); // Getting ec private key. ECPrivateKey

// serialize / deserialize
String walletJson = wallet.toJson();
MetadiumWallet newWallet = MetadiumWallet.fromJson(walletJson);
```

### Update Key

##### DID 키 변경

```java
wallet.updateKeyOfDid(delegator, new MetadiumKey());
```


##### DID 소유권 변경

```java
// Set verifier
VerifiableVerifier.register("did:meta:", MetadiumVerifier.class);	// META
VerifiableVerifier.register("did:icon:", IconVerifier.class);		// ICON
VerifiableVerifier.setResolverUrl("http://129.254.194.103:9000"); // UNIVERSIAL : http://129.254.194.103:9000, META : http://129.254.194.113

MetaDelegator delegator = new MetaDelegator("https://testdelegator.metadium.com", "https://testdelegator.metadium.com");

// Metadium DID 생성
MetadiumWallet wallet = MetadiumWallet.createDid(delegator);

// 변경할 키 생성 및 소유자에게 보낼 서명 값 생성. DID 는 알고 있어야 함
MetadiumKey newKey = new MetadiumKey();
String signature = delegator.signAddAssocatedKeyDelegate(did, newKey);
BigInteger publicKey = newKey.getPublicKey();

// 소유자에게 변경할 키의 공개키와 서명값을 전달하여 키 변경
wallet.updateKeyOfDid(delegator, publicKey, signature);

// 소유자 키 변경이 완료되면 새로운 Wallet 생성
MetadiumWallet newWallet = new MetadiumWallet(did, newKey);
```


### Delete DID

```java
wallet.deleteDid(delegator);
```

### Get Did Document

[Did-Resolver](https://github.com/METADIUM/did-resolver-java-client)

