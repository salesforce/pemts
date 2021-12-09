package com.salesforce.security;

import java.security.Provider;

/**
 * @author ppeddada
 */

public class TrustStoreProvider extends Provider {

    private static final long serialVersionUID = 1L;
    public static final String NAME = "SFTSP";

    public TrustStoreProvider() {
        super(NAME, "1.0", "A PEM file backed trust store provider");
        put("KeyStore." + ReadOnlyPEMTrustStore.NAME, ReadOnlyPEMTrustStore.class.getName());
    }

}
