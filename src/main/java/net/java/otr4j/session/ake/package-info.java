/**
 * Implementation of AKE following the state pattern.
 *
 * This implementation will throw unchecked exceptions in case support in the
 * JVM is lacking, such as for required hashing functions and ciphers.
 */
// TODO structurally handle verification/validation errors.
// TODO modify state implementations in such a way that it is impossible to use keys/random data without it being initialized.
// TODO verify that various message types do not allow invalid/illegal message contents.
// TODO need/required to clear temporary bytearray data containing key information? (AKE states)
package net.java.otr4j.session.ake;