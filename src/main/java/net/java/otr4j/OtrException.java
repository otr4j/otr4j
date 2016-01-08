
package net.java.otr4j;

public class OtrException extends Exception {
    private static final long serialVersionUID = -6327624437614707245L;

    public OtrException(Exception e) {
        super(e);
    }

    public OtrException(String message) {
        super(message);
    }
}
