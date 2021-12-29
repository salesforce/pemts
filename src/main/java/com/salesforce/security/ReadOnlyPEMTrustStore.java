package com.salesforce.security;

import javax.management.*;
import java.io.*;
import java.lang.management.ManagementFactory;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * A read only trust store that accepts a pem file as input stream.
 * 
 * @author ppeddada
 */
public final class ReadOnlyPEMTrustStore extends KeyStoreSpi implements ReadOnlyPEMTrustStoreMBean {

    public static final String NAME = "ROTKS";
    public static final String DOMAIN_NAME = System.getProperty("rotks.jmx.domain", "sfdc.security");

    private Map<String, Certificate> entries;
    private String digest;
    private final Date creationTime = new Date();
    private final ObjectName objectName = createObjectName();

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        throw new UnrecoverableKeyException("This is a trust store with no keys");
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        if (entries != null && entries.containsKey(alias)) { return new Certificate[] { entries.get(alias) }; }
        return null;
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        if (entries != null) { return entries.get(alias); }
        return null;
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        if (entries == null || !entries.containsKey(alias)) { return null; }
        return creationTime;
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
            throws KeyStoreException {
        throw new KeyStoreException("Keys cannot be stored in trust store");
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        throw new KeyStoreException("Keys cannot be stored in trust store");
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        throw new KeyStoreException("Read only trust store");
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        throw new KeyStoreException("This is a read only trust store");
    }

    @Override
    public Enumeration<String> engineAliases() {
        if (entries != null) {
            Vector<String> aliases = new Vector<>();
            for (String key : entries.keySet()) {
                aliases.add(key);
            }
            return aliases.elements();
        }
        return null;
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        if (entries != null) { return entries.containsKey(alias); }
        return false;
    }

    @Override
    public int engineSize() {
        if (entries != null) { return entries.size(); }
        return 0;
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        return false;
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        if (entries != null && entries.containsKey(alias)) { return true; }
        return false;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        if (cert != null) { return createAlias(cert); }
        return null;
    }

    @Override
    public void engineStore(OutputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        throw new IOException("This store cannot be persisted");

    }

    @Override
    public void engineLoad(InputStream stream, char[] password)
            throws IOException, CertificateException {
        if (password != null) { throw new IOException("Password shouldn't be set for trust store"); }
        if (stream == null) return;
        Map<String, Certificate> map = new HashMap<>();
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        SHA3512HashingInputStream in = new SHA3512HashingInputStream(stream);
        Collection<? extends Certificate> certificates = factory.generateCertificates(in);
        for (Certificate certificate : certificates) {
            if (map.put(createAlias(certificate), certificate) != null) {
                throw new IllegalStateException("Duplicate entry " + certificate);
            }
        }
        MBeanServer server = ManagementFactory.getPlatformMBeanServer();
        certificates.forEach(e -> registerMBean(server, (X509Certificate) e));
        this.entries = Collections.unmodifiableMap(map);
        this.digest = in.digest();
        try {
            server.registerMBean(this, objectName);
        } catch (InstanceAlreadyExistsException ignored) {
            
        } catch (MBeanRegistrationException | NotCompliantMBeanException unlikelyException) {
            throw new IllegalStateException(unlikelyException);
        }
    }

    @Override
    public String getDigest() {
        return this.digest;
    }

    private static String createAlias(Certificate certificate) {
        X509Certificate x509 = (X509Certificate)certificate;
        return x509.getSubjectX500Principal().getName();
    }

    private void registerMBean(MBeanServer server, X509Certificate cert) {
        try {
            ObjectName name = new ObjectName(DOMAIN_NAME + ":Type=RootCertInfo,Name=" + cert.getSerialNumber().toString());
            server.registerMBean(new RootCertInfo(cert), name);
        } catch (InstanceAlreadyExistsException ignored) {
            //update the the existing value?
        } catch (MBeanRegistrationException | NotCompliantMBeanException | MalformedObjectNameException unlikelyException) {
            throw new IllegalStateException(unlikelyException);
        }
    }

     /* package */ static ObjectName createObjectName() {
        String name = "localhost";
        try {
            name = System.getProperty("jvm.identity", InetAddress.getLocalHost().getHostName());
        } catch (UnknownHostException uhe) {
        }
        try {
            return new ObjectName(DOMAIN_NAME + ":Type=ReadOnlyPEMTrustStore,Name=" + name + ",PID=" + ProcessHandle.current().pid());
        } catch (MalformedObjectNameException unlikelyException) {
            throw new IllegalStateException(unlikelyException);
        }
    }

    private static final class SHA3512HashingInputStream extends FilterInputStream {

        private final MessageDigest messageDigest = createMessageDigest();

        protected SHA3512HashingInputStream(InputStream in) {
            super(in);
        }

        @Override
        public int read() throws IOException {
            int b = in.read();
            if (b != -1) {
                messageDigest.update((byte)b);
            }
            return b;
        }

        @Override
        public int read(byte[] bytes, int off, int len) throws IOException {
            int numOfBytesRead = in.read(bytes, off, len);
            if (numOfBytesRead != -1) {
                messageDigest.update(bytes, off, numOfBytesRead);
            }
            return numOfBytesRead;
        }

        @Override
        public boolean markSupported() {
            return false;
        }

        @Override
        public void reset() {
            throw new IllegalStateException("Unsupported operation");
        }

        @Override
        public void mark(int limit) {
            throw new IllegalStateException("Unsupported operation");
        }

        String digest() {
            return RootCertInfo.toHex(messageDigest.digest());
        }

        private MessageDigest createMessageDigest() {
            try {
                return MessageDigest.getInstance("SHA3-512");
            } catch (NoSuchAlgorithmException unlikelyException) {
                throw new IllegalStateException(unlikelyException);
            }
        }
    }
}
