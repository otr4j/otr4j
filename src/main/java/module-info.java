/**
 * Definition of the otr4j module.
 */
// TODO `require static` for automatic modules. Ideally, these dependencies define their own module.
module net.java.otr4j {
    requires static transitive jsr305;
    requires static transitive com.google.errorprone.annotations;

    requires transitive joldilocks;
    requires java.logging;
    requires org.bouncycastle.provider;
    
    exports net.java.otr4j.api;
    exports net.java.otr4j.crypto;
    exports net.java.otr4j.crypto.ed448;
    exports net.java.otr4j.io;
    exports net.java.otr4j.messages;
    exports net.java.otr4j.session;
    exports net.java.otr4j.util;
}
