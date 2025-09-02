package com.salesforce.security.tks;

import java.security.Provider;
import java.util.Collections;
import java.util.Set;

/**
 * @author ppeddada
 */

public final class TrustStoreProvider extends Provider {

    private static final long serialVersionUID = 1L;
    public static final String NAME = "SalesforceTrustStoreProvider";
    private static final String TYPE = "KeyStore";
    private final Service service;
    private final Set<Service> services;

    public TrustStoreProvider() {
        super(NAME, "1.5", "A PEM file backed trust store provider");
        this.service = new Service(this, TYPE, ReadOnlyPEMTrustStore.NAME, ReadOnlyPEMTrustStore.class.getName(),
                Collections.emptyList(), Collections.emptyMap());
        services = Set.of(service);
    }

    @Override
    public Service getService(String type, String algorithm) {
        if (ReadOnlyPEMTrustStore.NAME.equals(algorithm) && TYPE.equals(type)) {
            return this.service;
        }
        return null;
    }

    @Override
    public Set<Service> getServices() {
        return services;
    }

}
