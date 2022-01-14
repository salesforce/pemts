module com.salesforce.security.tks {
   provides java.security.Provider with com.salesforce.security.TrustStoreProvider;
   exports com.salesforce.security;
   requires java.management;
   requires java.naming;
   //Only used for testing.
   requires java.net.http;

}
