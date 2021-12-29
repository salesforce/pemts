package com.salesforce.security;

/**
 * Expose each root certificate as a StandardMBean
 * @author ppeddada
 */
public interface RootCertInfoMBean {

    /**
     * @return root certificiate subject principal name
     */
    String getSubjectPrincipalName();

    /**
     * @return serial number of the root certificate
     */
    String getSerialNumber();

    /**
     * @return signature algorithm
     */
    String getSigAlgName();

    /**
     * @return signature
     */
    String getSignature();

    /**
     * @return certificate validity start date
     */
    String getNotBefore();

    /**
     * @return certificate validity end date
     */
    String getNotAfter();

    /**
     * @return certificate thumbprint
     */
    String getThumbprint();

}
