package com.salesforce.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * @author ppeddada
 */
public final class RootCertInfo implements RootCertInfoMBean {

    private final String subjectPrincipal;
    private final String serialNumber;
    private final String sigAlgName;
    private final String signature;
    private final String thumbprint;
    private final String notBefore;
    private final String notAfter;


    RootCertInfo(X509Certificate cert) {
        this.subjectPrincipal = cert.getSubjectX500Principal().getName();
        this.serialNumber = cert.getSerialNumber().toString();
        this.sigAlgName = cert.getSigAlgName();
        this.signature = toHex(cert.getSignature());
        this.thumbprint = thumbprint(cert);
        this.notBefore = cert.getNotBefore().toString();
        this.notAfter = cert.getNotAfter().toString();
    }

    @Override
    public String getSubjectPrincipalName() {
        return subjectPrincipal;
    }

    @Override
    public String getSerialNumber() {
        return serialNumber;
    }

    @Override
    public String getSigAlgName() {
        return sigAlgName;
    }

    @Override
    public String getSignature() {
        return signature;
    }

    @Override
    public String getThumbprint() {
        return thumbprint;
    }

    @Override
    public String getNotBefore() {
        return notBefore;
    }

    @Override
    public String getNotAfter() {
        return notAfter;
    }

    static final String toHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            builder.append(String.format("%02X ", bytes[i]));
        }
        return builder.toString();
    }

    static final String thumbprint(X509Certificate cert) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            return toHex(messageDigest.digest(cert.getEncoded()));
        } catch (NoSuchAlgorithmException | CertificateEncodingException unlikelyException) {
            throw new IllegalStateException(unlikelyException);
        }
    }
}
