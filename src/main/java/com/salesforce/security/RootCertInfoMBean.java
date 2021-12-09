package com.salesforce.security;

/**
 * @author ppeddada
 */
public interface RootCertInfoMBean {

    String getIssuerPrincipalName();

    String getSerialNumber();

    String getSigAlgName();

    String getSignature();


}
