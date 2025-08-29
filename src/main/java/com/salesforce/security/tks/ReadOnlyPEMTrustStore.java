package com.salesforce.security.tks;

import javax.management.*;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.*;
import java.lang.management.ManagementFactory;
import java.math.BigInteger;
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
    public static final String OBJECT_NAME_PREFIX = System.getProperty("rotks.jmx.prefix", "SFDC:type=Logging,name1=InfraSec,name2=");

    private Map<String, Certificate> entries;
    private String digest;
    private final Date creationTime = new Date();
    private final ObjectName objectName = createObjectName();

    @Override
    public Key engineGetKey(String alias, char[] password) throws UnrecoverableKeyException {
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
            return new Vector<>(entries.keySet()).elements();
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
        if (entries == null) {
            return false;
        }
        return entries.containsKey(alias);
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        if (cert != null) { return identifier((X509Certificate) cert); }
        return null;
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException {
        throw new IOException("This store cannot be persisted");

    }

    @Override
    public void engineLoad(InputStream stream, char[] password)
            throws IOException, CertificateException {
        if (password != null && password.length > 0) { throw new IOException("Password shouldn't be set for trust store"); }
        if (stream == null) return;
        Date now = new Date();
        Map<String, Certificate> map = new HashMap<>();
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        SHA3512HashingInputStream in = new SHA3512HashingInputStream(stream);
        Collection<? extends Certificate> certificates = factory.generateCertificates(in);
        for (Certificate certificate : certificates) {
            X509Certificate x509Certificate = (X509Certificate) certificate;
            if (x509Certificate.getNotAfter().before(now)) {
                continue;
            }
            if (map.put(identifier(x509Certificate), x509Certificate) != null) {
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

    private void registerMBean(MBeanServer server, X509Certificate cert) {
        try {
            ObjectName name = new ObjectName(OBJECT_NAME_PREFIX + identifier(cert));
            server.registerMBean(new RootCertInfo(cert), name);
        } catch (InstanceAlreadyExistsException ignored) {
        } catch (MBeanRegistrationException | NotCompliantMBeanException | MalformedObjectNameException unlikelyException) {
            //If the bean already exists ignore
            throw new IllegalStateException(unlikelyException);
        }
    }

     /* package */ static ObjectName createObjectName() {
        try {
            return new ObjectName(OBJECT_NAME_PREFIX + "SystemRoot");
        } catch (MalformedObjectNameException unlikelyException) {
            throw new IllegalStateException(unlikelyException);
        }
    }

    static String identifier(X509Certificate cert) {
        StringBuilder builder = new StringBuilder();
        try {
            List<Rdn> rdns = new LdapName(cert.getSubjectX500Principal().getName()).getRdns();
            String name = extractValue(rdns, "CN");
            if (name == null) {
                name = extractValue(rdns, "OU");
            }
            if (name != null) {
                builder.append(name);
                builder.append('_');
            }
        } catch (InvalidNameException ignored) {
            builder = new StringBuilder("INVALID_");
        }
        builder.append(new BigInteger(cert.getSignature()).toString(16));
        builder.append('_');
        builder.append(cert.getSerialNumber());
        return builder.toString().replace(',', ' ');
    }

    private static String extractValue(List<Rdn> rdns, String expectedType) {
        for (Rdn rdn : rdns) {
            String type = rdn.getType();
            if (type != null && Objects.equals(type.toUpperCase(), expectedType)) {
                return rdn.getValue().toString();
            }
        }
        return null;
    }

    private static final class SHA3512HashingInputStream extends FilterInputStream {

        private final MessageDigest messageDigest = createMessageDigest();

        private SHA3512HashingInputStream(InputStream in) {
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
