# Metadium DID SDK for Java

## Get it
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
    <version>0.1.0</version>
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
    implementation 'com.github.METADIUM:did-sdk-java:0.1.0'
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
BigInteger privateKey = wallet..getKey().getPrivateKey(); // Getting ec private key

// serialize / deserialize
String walletJson = wallet.toJson();
MetadiumWallet newWallet = MetadiumWallet.fromJson(walletJson);
```

### update Key

```java
wallet.updateKeyOfDid(delegator, new MetadiumKey());
```

### Delete DID

```java
wallet.deleteDid(delegator);
```

### Get Did Document

[Did-Resolver](https://github.com/METADIUM/did-resolver-java-client)