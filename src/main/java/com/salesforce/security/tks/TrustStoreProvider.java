package com.salesforce.security.tks;

import java.security.Provider;

/**
 * @author ppeddada
 */

public final class TrustStoreProvider extends Provider {

    private static final long serialVersionUID = 1L;
    public static final String NAME = "SalesforceTrustStoreProvider";

    public TrustStoreProvider() {
        super(NAME, "1.1", "A PEM file backed trust store provider");
        put("KeyStore." + ReadOnlyPEMTrustStore.NAME, ReadOnlyPEMTrustStore.class.getName());
    }

}
