package com.salesforce.security.tks;

/**
 * Expose digest of the file loaded from the file system as a StandardMBean
 * @author ppeddada
 */
public interface ReadOnlyPEMTrustStoreMBean {

    /**
     * @return SHA3-512 digest of the trust store file
     */

    String getDigest();
}
