package com.salesforce.security;

import javax.management.*;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.management.ManagementFactory;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
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
public class ReadOnlyPEMTrustStore extends KeyStoreSpi {

    public static final String NAME = "ROTKS";

    private Map<String, Certificate> entries;
    private final Date creationTime = new Date();

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
        Collection<? extends Certificate> certificates = factory.generateCertificates(stream);
        for (Certificate certificate : certificates) {
            if (map.put(createAlias(certificate), certificate) != null) {
                throw new IllegalStateException("Duplicate entry " + certificate);
            }
        }
        MBeanServer server = ManagementFactory.getPlatformMBeanServer();
        certificates.forEach(e -> registerMBean(server, (X509Certificate) e));
        this.entries = Collections.unmodifiableMap(map);
    }

    private static String createAlias(Certificate certificate) {
        X509Certificate x509 = (X509Certificate)certificate;
        return x509.getSubjectX500Principal().getName();
    }

    private void registerMBean(MBeanServer server, X509Certificate cert) {
        try {
            ObjectName name = new ObjectName("sfdc.security:Type=RootCertInfo,Name=" + cert.getSerialNumber().toString());
            server.registerMBean(new RootCertInfo(cert), name);
        } catch (InstanceAlreadyExistsException ignored) {
            //update the the existing value?
        } catch (MBeanRegistrationException | NotCompliantMBeanException | MalformedObjectNameException unlikelyException) {
            throw new IllegalStateException(unlikelyException);
        }
    }
}
