/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
// TODO consider making classes final where obvious (OtrInputStream, OtrOutputStream, SM, ...)
// TODO remove traces of OTRv1 protocol, as this should not be supported anymore.
// FIXME don't forget to include license header in all new test-files too!
// TODO Outstanding issue: In several places arrays exposed as public fields/through accessor methods which allows code to modify its contents. (Fixed for crypto constants, not for AES keys + MAC keys + CTR values, TLV values, etc.) (Detected by FindBugs.)
/**
 * otr4j.
 */
package net.java.otr4j;
