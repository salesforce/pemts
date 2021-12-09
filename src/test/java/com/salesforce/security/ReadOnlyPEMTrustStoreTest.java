package com.salesforce.security;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.Assert;
import org.junit.Test;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class ReadOnlyPEMTrustStoreTest {

    private static final String TRUST_STORE = "javax.net.ssl.trustStore";
    private static final String TRUST_STORE_TYPE = "javax.net.ssl.trustStoreType";
    private static final String RESPONSE_FMT = "%s says hello";
    private static final X500Name CN = new X500Name("CN=I am TheRoot");
    private static final X500Name LH_CN = new X500Name("CN=localhost");
    private static final DERSequence SANS = new DERSequence(new ASN1Encodable[] {
            new GeneralName(GeneralName.dNSName, "localhost"), new GeneralName(GeneralName.dNSName, "127.0.0.1") });

    static {
        Provider provider = new TrustStoreProvider();
        Security.addProvider(provider);
    }

    @Test
    public void testProvider() throws Exception {
        KeyStore store = KeyStore.getInstance(ReadOnlyPEMTrustStore.NAME, TrustStoreProvider.NAME);
        Assert.assertNotNull(store);
        store.load(null, null);
        Assert.assertEquals(0, store.size());
        Assert.assertNull(store.getCertificate("bogus"));
        Assert.assertNull(store.getCertificateChain("bogus"));
        Assert.assertNull(store.aliases());
        Assert.assertFalse(store.containsAlias("bogus"));
        Assert.assertNull(store.getCreationDate("alias"));
        Assert.assertNull(store.getCertificateAlias(null));
    }

    @Test(expected = IOException.class)
    public void testInvalidPassword() throws Exception {
        KeyStore store = KeyStore.getInstance(ReadOnlyPEMTrustStore.NAME, TrustStoreProvider.NAME);
        Assert.assertNotNull(store);
        store.load(null, "invalid".toCharArray());
    }

    @Test
    public void testPemFileLoading() throws Exception {
        InputStream in = new FileInputStream(new File("src/test/resources/certs.pem"));
        Assert.assertNotNull(in);
        KeyStore store = KeyStore.getInstance(ReadOnlyPEMTrustStore.NAME, TrustStoreProvider.NAME);
        store.load(in, null);
        Assert.assertTrue(store.size() > 0);
        Assert.assertNull(store.getCertificate("bogus"));
        Assert.assertNull(store.getCertificateChain("bogus"));
        Assert.assertFalse(store.isCertificateEntry("alias"));
        Assert.assertFalse(store.isKeyEntry("alias"));
    }

    @Test(expected = IOException.class)
    public void testStore() throws Exception {
        InputStream in = new FileInputStream(new File("src/test/resources/certs.pem"));
        Assert.assertNotNull(in);
        KeyStore store = KeyStore.getInstance(ReadOnlyPEMTrustStore.NAME, TrustStoreProvider.NAME);
        store.load(in, null);
        store.store(null, null);
    }

    @Test
    public void testTrustStore() throws Exception {
        InputStream in = new FileInputStream(new File("src/test/resources/certs.pem"));
        Assert.assertNotNull(in);
        KeyStore store = KeyStore.getInstance(ReadOnlyPEMTrustStore.NAME, TrustStoreProvider.NAME);
        store.load(in, null);
        TrustManagerFactory factory = TrustManagerFactory.getInstance("PKIX");
        factory.init(store);
        TrustManager[] mgrs = factory.getTrustManagers();
        Assert.assertNotNull(mgrs);
        Assert.assertTrue(mgrs.length > 0);
    }

    @Test(expected = IllegalStateException.class)
    public void testDuplicateEntriesPemFile() throws Exception {
        InputStream in = new FileInputStream(new File("src/test/resources/dup.pem"));
        Assert.assertNotNull(in);
        KeyStore store = KeyStore.getInstance(ReadOnlyPEMTrustStore.NAME, TrustStoreProvider.NAME);
        store.load(in, null);
    }

    @Test(expected = UnrecoverableEntryException.class)
    public void testKeyEntry() throws Exception {
        KeyStore store = KeyStore.getInstance(ReadOnlyPEMTrustStore.NAME, TrustStoreProvider.NAME);
        store.load(null, null);
        store.getKey("alias", null);
    }

    @Test
    public void testIsKeyEntry() throws Exception {
        KeyStore store = KeyStore.getInstance(ReadOnlyPEMTrustStore.NAME, TrustStoreProvider.NAME);
        store.load(null, null);
        Assert.assertFalse(store.isKeyEntry("alias"));
    }

    @Test
    public void testSinglePem() throws Exception {
        InputStream in = new FileInputStream(new File("src/test/resources/single.pem"));
        Assert.assertNotNull(in);
        KeyStore store = KeyStore.getInstance(ReadOnlyPEMTrustStore.NAME, TrustStoreProvider.NAME);
        store.load(in, null);
        Enumeration<String> aliases = store.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Assert.assertTrue(store.containsAlias(alias));
            Assert.assertNotNull(store.getCertificate(alias));
            Assert.assertNotNull(store.getCertificateChain(alias));
            Assert.assertNotNull(store.getCreationDate(alias));
            Assert.assertTrue(store.isCertificateEntry(alias));
            Assert.assertFalse(store.isKeyEntry(alias));
        }
        Assert.assertFalse(store.isCertificateEntry("nonexistent"));
        Assert.assertNull(store.getCreationDate("nonexistent"));
    }

    @Test(expected = KeyStoreException.class)
    public void testAlias() throws Exception {
        byte[] certAsByteArray = String
                .join(System.lineSeparator(), "-----BEGIN CERTIFICATE-----",
                        "MIIFuzCCA6OgAwIBAgIIVwoRl0LE48wwDQYJKoZIhvcNAQELBQAwazELMAkGA1UE",
                        "BhMCSVQxDjAMBgNVBAcMBU1pbGFuMSMwIQYDVQQKDBpBY3RhbGlzIFMucC5BLi8w",
                        "MzM1ODUyMDk2NzEnMCUGA1UEAwweQWN0YWxpcyBBdXRoZW50aWNhdGlvbiBSb290",
                        "IENBMB4XDTExMDkyMjExMjIwMloXDTMwMDkyMjExMjIwMlowazELMAkGA1UEBhMC",
                        "SVQxDjAMBgNVBAcMBU1pbGFuMSMwIQYDVQQKDBpBY3RhbGlzIFMucC5BLi8wMzM1",
                        "ODUyMDk2NzEnMCUGA1UEAwweQWN0YWxpcyBBdXRoZW50aWNhdGlvbiBSb290IENB",
                        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAp8bEpSmkLO/lGMWwUKNv",
                        "UTufClrJwkg4CsIcoBh/kbWHuUA/3R1oHwiD1S0eiKD4j1aPbZkCkpAW1V8IbInX",
                        "4ay8IMKx4INRimlNAJZaby/ARH6jDuSRzVju3PvHHkVH3Se5CAGfpiEd9UEtL0z9",
                        "KK3giq0itFZljoZUj5NDKd45RnijMCO6zfB9E1fAXdKDa0hMxKufgFpbOr3JpyI/",
                        "gCczWw63igxdBzcIy2zSekciRDXFzMwujt0q7bd9Zg1fYVEiVRvjRuPjPdA1Yprb",
                        "rxTIW6HMiRvhMCb8oJsfgadHHwTrozmSBp+Z07/T6k9QnBn+locePGX2oxgkg4YQ",
                        "51Q+qDp2JE+BIcXjDwL4k5RHILv+1A7TaLndxHqEguNTVHnd25zS8gebLra8Pu2F",
                        "be8lEfKXGkJh90qX6IuxEAf6ZYGyojnP9zz/GPvG8VqLWeICrHuS0E4UT1lF9gxe",
                        "KF+w6D9Fz8+vm2/7hNN3WpVvrJSEnu68wEqPSpP4RCHiMUVhUE4Q2OM1fEwZtN4F",
                        "v6MGn8i1zeQf1xcGDXqVdFUNaBr8EBtiZJ1t4JWgw5QHVw0U5r0F+7if5t+L4sbn",
                        "fpb2U8WANFAoWPASUHEXMLrmeGO89LKtmyuy/uE5jF66CyCU3nuDuP/jVo23Eek7",
                        "jPKxwV2dpAtMK9myGPW1n0sCAwEAAaNjMGEwHQYDVR0OBBYEFFLYiDrIn3hm7Ynz",
                        "ezhwlMkCAjbQMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUUtiIOsifeGbt",
                        "ifN7OHCUyQICNtAwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBCwUAA4ICAQAL",
                        "e3KHwGCmSUyIWOYdiPcUZEim2FgKDk8TNd81HdTtBjHIgT5q1d07GjLukD0R0i70",
                        "jsNjLiNmsGe+b7bAEzlgqqI0JZN1Ut6nna0Oh4lScWoWPBkdg/iaKWW+9D+a2fDz",
                        "WochcYBNy+A4mz+7+uAwTc+G02UQGRjRlwKxK3JCaKygvU5a2hi/a5iB0P2avl4V",
                        "SM0RFbnAKVy06Ij3Pjaut2L9HmLecHgQHEhb2rykOLpn7VU+Xlff1ANATIGk0k9j",
                        "pwlCCRT8AKnCgHNPLsBA2RF7SOp6AsDT6ygBJlh0wcBzIm2Tlf05fbsq4/aC4yyX",
                        "X04fkZT6/iyj2HYauE2yOE+b+h1IYHkm4vP9qdCa6HCPSXrW5b0KDtst842/6+Ok",
                        "fcvHlXHo2qN8xcL4dJIEG4aspCJTQLas/kx2z/uUMsA1n3Y/buWQbqCmJqK4LL7R",
                        "K4X9p2jIugErsWx0Hbhzlefut8cl8ABMALJ+tguLHPPAUJ4lueAI3jZm/zel0btU",
                        "ZCzJJ7VLkn5l/9Mt4blOvH+kQSGQQXemOR/qnuOf0GZvBeyqdn6/axag67XH/JJU",
                        "LysRJyU3eExRarDzzFhdFPFqSBX/wge2sY0PjlxQRrM9vwGYT7JZVEc+NHt4bVaT",
                        "LnPqZih4zR0Uv6CPLy64Lo7yFIrM6bV8+2ydDKXhlg==", "-----END CERTIFICATE-----")
                .getBytes(StandardCharsets.UTF_8);
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        Certificate cert = factory.generateCertificate(new ByteArrayInputStream(certAsByteArray));
        KeyStore store = KeyStore.getInstance(ReadOnlyPEMTrustStore.NAME, TrustStoreProvider.NAME);
        store.load(null, null);
        String alias = store.getCertificateAlias(cert);
        Assert.assertNotNull(alias);
        // This should be last line as it throws exception
        store.setCertificateEntry(alias, cert);
    }

    @Test(expected = KeyStoreException.class)
    public void testDeleteEntry() throws Exception {
        KeyStore store = KeyStore.getInstance(ReadOnlyPEMTrustStore.NAME, TrustStoreProvider.NAME);
        store.load(null, null);
        store.deleteEntry(null);
    }

    @Test(expected = KeyStoreException.class)
    public void testSetPrivateKeyEntry() throws Exception {
        KeyStore store = KeyStore.getInstance(ReadOnlyPEMTrustStore.NAME, TrustStoreProvider.NAME);
        store.load(null, null);
        store.setKeyEntry(null, null, null);
    }

    @Test(expected = KeyStoreException.class)
    public void testSetKeyEntry() throws Exception {
        KeyStore store = KeyStore.getInstance(ReadOnlyPEMTrustStore.NAME, TrustStoreProvider.NAME);
        store.load(null, null);
        store.setKeyEntry(null, null, null, null);
    }

    @Test
    public void testEndToEndTLS() throws Exception {
        String password = createPassword();
        ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(spec);
        KeyPair root = kpg.generateKeyPair();
        File dir = new File(System.getProperty("java.io.tmpdir"), String.valueOf(System.nanoTime()));
        dir.mkdir();
        File file = new File(dir, "root.der");
        System.setProperty(TRUST_STORE_TYPE, ReadOnlyPEMTrustStore.NAME);
        System.setProperty(TRUST_STORE, file.getAbsolutePath());
        try {
            X509Certificate rootCert = createRoot(file, root, kpg.getProvider());
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            X509Certificate[] certificates = new X509Certificate[2];
            KeyPair pair = kpg.generateKeyPair();
            certificates[0] = sign(root.getPrivate(), root.getPublic(), pair, kpg.getProvider());
            certificates[1] = rootCert;
            keyStore.setKeyEntry("TLS", pair.getPrivate(), password.toCharArray(), certificates);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, password.toCharArray());
            SSLContext serverCtx = SSLContext.getInstance("TLSv1.2");
            serverCtx.init(kmf.getKeyManagers(), null, null);
            serverCtx.getSupportedSSLParameters().setProtocols(new String[] { "TLSv1.2" });
            SslContextFactory sslContextFactory = new SslContextFactory.Server();
            sslContextFactory.setKeyStore(keyStore);
            sslContextFactory.setKeyStorePassword(password);
            HttpConfiguration httpConfig = new HttpConfiguration();
            httpConfig.setSecureScheme("https");
            int securePort = 8086;
            httpConfig.setSecurePort(securePort);
            HttpConfiguration httpsConfig = new HttpConfiguration(httpConfig);
            SecureRequestCustomizer src = new SecureRequestCustomizer();
            src.setStsMaxAge(2000);
            httpsConfig.addCustomizer(src);
            final Server server = new Server();
            ServerConnector https = new ServerConnector(server,
                    new SslConnectionFactory(sslContextFactory, HttpVersion.HTTP_1_1.asString()),
                    new HttpConnectionFactory(httpsConfig));
            https.setPort(securePort);
            server.setConnectors(new Connector[] { https });
            Handler handler = new TestHandler();
            // Set a handler
            server.setHandler(handler);
            server.start();
            ExecutorService service = Executors.newFixedThreadPool(1);
            service.execute(() -> {
                try {
                    server.join();
                } catch (InterruptedException e) {

                }
            });
            SSLContext clientCtx = SSLContext.getInstance("TLSv1.2");
            clientCtx.init(null, null, null);
            HttpClient client = HttpClient.newBuilder().sslContext(clientCtx).version(HttpClient.Version.HTTP_1_1)
                    .build();
            HttpRequest request = HttpRequest.newBuilder().uri(URI.create("https://localhost:" + securePort + "/"))
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            Assert.assertEquals(HttpURLConnection.HTTP_OK, response.statusCode());
            Assert.assertEquals(String.format(RESPONSE_FMT, "TLSv1.2"), response.body());
            service.shutdown();
            server.stop();
        } finally {
            file.delete();
            dir.delete();
            System.getProperties().remove(TRUST_STORE);
            System.getProperties().remove(TRUST_STORE_TYPE);
        }

    }

    @Test(expected = IOException.class)
    public void testEndToEndTLSWithoutROTKS() throws Exception {
        String password = createPassword();
        ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(spec);
        KeyPair root = kpg.generateKeyPair();
        File file = File.createTempFile(String.valueOf(System.nanoTime()), "der");
        ExecutorService service = Executors.newFixedThreadPool(1);
        final Server server = new Server();
        try {
            X509Certificate rootCert = createRoot(file, root, kpg.getProvider());
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            X509Certificate[] certificates = new X509Certificate[2];
            KeyPair pair = kpg.generateKeyPair();
            certificates[0] = sign(root.getPrivate(), root.getPublic(), pair, kpg.getProvider());
            certificates[1] = rootCert;
            keyStore.setKeyEntry("TLS", pair.getPrivate(), password.toCharArray(), certificates);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, password.toCharArray());
            SSLContext serverCtx = SSLContext.getInstance("TLSv1.2");
            serverCtx.init(kmf.getKeyManagers(), null, null);
            serverCtx.getSupportedSSLParameters().setProtocols(new String[] { "TLSv1.2" });
            SslContextFactory sslContextFactory = new SslContextFactory.Server();
            sslContextFactory.setKeyStore(keyStore);
            sslContextFactory.setKeyStorePassword(password);
            HttpConfiguration httpConfig = new HttpConfiguration();
            httpConfig.setSecureScheme("https");
            int securePort = 8086;
            httpConfig.setSecurePort(securePort);
            HttpConfiguration httpsConfig = new HttpConfiguration(httpConfig);
            SecureRequestCustomizer src = new SecureRequestCustomizer();
            src.setStsMaxAge(2000);
            httpsConfig.addCustomizer(src);
            ServerConnector https = new ServerConnector(server,
                    new SslConnectionFactory(sslContextFactory, HttpVersion.HTTP_1_1.asString()),
                    new HttpConnectionFactory(httpsConfig));
            https.setPort(securePort);
            server.setConnectors(new Connector[] { https });
            Handler handler = new TestHandler();
            // Set a handler
            server.setHandler(handler);
            server.start();
            service.execute(() -> {
                try {
                    server.join();
                } catch (InterruptedException e) {

                }
            });
            SSLContext clientCtx = SSLContext.getInstance("TLSv1.2");
            clientCtx.init(null, null, null);
            HttpClient client = HttpClient.newBuilder().sslContext(clientCtx).version(HttpClient.Version.HTTP_1_1)
                    .build();
            HttpRequest request = HttpRequest.newBuilder().uri(URI.create("https://localhost:" + securePort + "/"))
                    .build();
            client.send(request, HttpResponse.BodyHandlers.ofString());
            service.shutdown();
            server.stop();
        } finally {
            service.shutdown();
            server.stop();
            file.delete();
        }

    }

    private static X509Certificate createRoot(File root, KeyPair pair, Provider provider) throws Exception {
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());
        BigInteger serialNumber = new BigInteger(32, new SecureRandom());
        Calendar cal = Calendar.getInstance();
        Date start = cal.getTime();
        cal.add(Calendar.DATE, 1);
        Date end = cal.getTime();
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(CN, serialNumber, start, end, CN,
                publicKeyInfo);
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256WithECDSA").setProvider(provider);
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                new BcX509ExtensionUtils().createSubjectKeyIdentifier(publicKeyInfo));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                new BcX509ExtensionUtils().createAuthorityKeyIdentifier(publicKeyInfo));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(2));
        byte[] cert = builder.build(signerBuilder.build(pair.getPrivate())).getEncoded();
        try (FileOutputStream out = new FileOutputStream(root)) {
            out.write(cert);
        }
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        return (X509Certificate)factory.generateCertificate(new ByteArrayInputStream(cert));

    }

    private X509Certificate sign(PrivateKey rootPrivateKey, PublicKey rootPublicKey, KeyPair pair, Provider provider)
            throws Exception {
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());
        BigInteger serialNumber = new BigInteger(32, new SecureRandom());
        Calendar cal = Calendar.getInstance();
        Date start = cal.getTime();
        cal.add(Calendar.DATE, 1);
        Date end = cal.getTime();
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(CN, serialNumber, start, end, LH_CN,
                publicKeyInfo);
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                new BcX509ExtensionUtils().createSubjectKeyIdentifier(publicKeyInfo));
        builder.addExtension(Extension.authorityKeyIdentifier, false, new BcX509ExtensionUtils()
                .createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(rootPublicKey.getEncoded())));
        builder.addExtension(Extension.subjectAlternativeName, false, SANS);
        builder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));
        ASN1EncodableVector purposes = new ASN1EncodableVector();
        purposes.add(KeyPurposeId.id_kp_serverAuth);
        builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256WithECDSA").setProvider(provider);
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        return (X509Certificate)factory.generateCertificate(
                new ByteArrayInputStream(builder.build(signerBuilder.build(rootPrivateKey)).getEncoded()));

    }

    private static String createPassword() {
        byte[] data = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(data);
        return Base64.getEncoder().encodeToString(data);
    }

    private static class TestHandler extends AbstractHandler {
        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response)
                throws IOException, ServletException {
            // Declare response encoding and types
            response.setContentType("text/plain; charset=utf-8");
            // Declare response status code
            response.setStatus(HttpServletResponse.SC_OK);
            // Write back response
            response.getWriter().print(String.format(RESPONSE_FMT, "TLSv1.2"));
            // Inform jetty that this request has now been handled
            baseRequest.setHandled(true);
        }

    }

}
