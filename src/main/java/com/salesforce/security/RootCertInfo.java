package com.salesforce.security;

import java.security.cert.X509Certificate;
import java.util.Arrays;

public final class RootCertInfo implements RootCertInfoMBean {

    private final String issuerPrincipal;
    private final String serialNumber;
    private final String sigAlgName;
    private final String signature;

    RootCertInfo(X509Certificate cert) {
        this.issuerPrincipal = cert.getIssuerX500Principal().getName();
        this.serialNumber = cert.getSerialNumber().toString();
        this.sigAlgName = cert.getSigAlgName();
        this.signature = Arrays.toString(cert.getSignature());
    }
    @Override
    public String getIssuerPrincipalName() {
        return issuerPrincipal;
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

}
