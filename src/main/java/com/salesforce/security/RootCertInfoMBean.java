package com.salesforce.security;

/**
 * @author ppeddada
 */
public interface RootCertInfoMBean {


    String getSubjectPrincipalName();

    String getSerialNumber();

    String getSigAlgName();

    String getSignature();

    String getNotBefore();

    String getNotAfter();

    String getThumbprint();


}
