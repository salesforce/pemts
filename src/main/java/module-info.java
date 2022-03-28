import com.salesforce.security.tks.TrustStoreProvider;

module com.salesforce.security.tks {
   provides java.security.Provider with TrustStoreProvider;
   exports com.salesforce.security.tks;
   requires java.management;
   requires java.naming;
   //Only used for testing.
   requires java.net.http;

}
