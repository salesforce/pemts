package com.salesforce.security;

/**
 *
 * @author ppeddada
 */
public interface ReadOnlyPEMTrustStoreMBean {

    /**
     * @return SHA3-512 digest of the trust store file
     */

    String getDigest();
}
