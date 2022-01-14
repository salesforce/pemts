# PEMTS

## Introduction

A Java trust store is an instance of KeyStore which only contains certificates. There are various 
types of [KeyStore](https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#keystore-types) 
implementations. For example JCEKS, JKS, PKCS11 implementations are bundled with JDK. Unfortunately 
neither one is FIPS compliant and you have to use a thirdparty implementation such as BCFKS to be 
FIPS compliant. Depending on your environment you might end up having to configure your JVM with 
different format files for various environments.

## Solution

Instead of relying on the native formats we implemented a trust store that is backed by the KeyStore API that 
allows you to create a trust store using a PEM file. All the pem entries from the supplied file are used
for initializing the key store which in turn can be used for initializing TrustManagerFactory.

## Features

- This is a read only keystore implementation so all calls to modify entries would fail with runtime exceptions.
- You are not expected to supply a password when initializing the store
- StandardMBeans that expose metadata about the certificates loaded into the trust store for runtime monitoring.


## Sample code
```java
try (InputStream in = new BufferedInputStream(new FileInputStream("src/test/resources/single.pem"))) {
    KeyStore store = KeyStore.getInstance();
    KeyStore store = KeyStore.getInstance(ReadOnlyPEMTrustStore.NAME, TrustStoreProvider.NAME);
    store.load(in, null);
    TrustManagerFactory factory = TrustManagerFactory.getInstance("PKIX");
    factory.init(store);
}
```




