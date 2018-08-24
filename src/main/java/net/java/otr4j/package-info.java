/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
// TODO verify that logging with parameters ('{}') works correctly.
// FIXME migrate to using SpotBugs annotations, instead of dormant JSR-305.
// FIXME use @CleanupObligation to verify correct clean-up of cryptographically sensitive material.
// TODO Verify rule exclusions for maven-compiler-plugin, SpotBugs, pmd, ...
// TODO Use maven-site-plugin (or similar) to generate a full report on the status of otr4j project.
// TODO Investigate use of SpotBugs and its annotation to manage "resources" and correct closing.
// TODO Upgrade to use of JUnit5 for unit tests. (May not be possible due to language level restrictions, Java 8+?)
// TODO consistent naming of constants used in OTRv4 parts of implementation. (Sometimes LENGTH is at the start of the constant, sometimes at the end.)
// TODO Verify that mitigation for OTRv2 MAC revalation bug is in place. (Refer to documentation about revealing MAC keys.)
// TODO remove OTRv2 support to comply with OTRv4 spec.
// TODO Verify that all files have the correct license header above the files.
// TODO analyze over-all package structure and see if we can reduce (the number of causes for) cyclic dependencies.
// TODO consider the effectiveness of clearing data as JVM might optimize the activity away due to data not being used afterwards.
// TODO OTRv4: Non-Interactive DAKE, Pre-Key Profile, KCI Attacks, full support for out-of-order messages
// FUTURE could we create some kind of basic client such that we can perform cross-implementation testing and fuzzing?
// FUTURE does it make sense to have some kind of plug-in system for OTR extensions?
// FUTURE consider if it makes sense to have some kind of SecurityManager rule/policy that prevents code from inspecting any otr4j instances. (This can also be tackled by using otr4j as module, as you have to explicitly allow "opening up" to reflection.)
// FUTURE what's the status on reproducible builds of Java programs?
// FUTURE investigate usefulness of Java 9 module, maybe just as an experiment ...
// FUTURE consider implementing OTRDATA (https://dev.guardianproject.info/projects/gibberbot/wiki/OTRDATA_Specifications)
// FUTURE do something fuzzing-like to thoroughly test receiving user messages with various characters. Especially normal user messages that are picked up as OTR-encoded but then crash/fail processing because it's only a partially-valid OTR encoded message.
// TODO General questions on way-of-working for OTRv4:
//  * After having successfully finished DAKE, should we forget about previously used QueryTag or remember it? Let's say that we initiate a OTRv4 session immediately (send Identity message), should we then reuse previous query tag, or start blank?
//  * In section "Extra Symmetric Key" already fixed ref `KDF_1(0x1A || 0xFF || chain_key)`?
//  * In section When receiving a Data Message: Derive the next receiving chain key: chain_key_r[i-1][k+1] = KDF_1(0x17 || chain_key_r[i-1][k], 64). (0x17 used in 2 locations)
//  * Error in: "Derive chain_key_r[i][k+1] = KDF_1(usageNextChainKey || chain_key_r[i][k], 64) and MKenc = KDF_1(usageMessageKey || chain_key_r[i][k], 32)" Should be 'i-1' instead of 'i'.
//  * "Set their_ecdh as the 'Public ECDH key' from the message. Set their_dh as the 'Public DH Key' from the message, if it is not empty." are duplicate. Already included as part of Rotation instructions.
//  * OTRv4 ClientProfile verification does not clearly state what to do if DSA public key *without* transitional signature is found. (Drop DSA Public Key or reject profile completely.)
//  * Consider making an exception for the Identity message.
//    "Discard the message and optionally pass a warning to the participant if:
//    The recipient's own instance tag does not match the listed receiver instance tag."
//  * "Discard the (illegal) fragment if:" is missing criteria for index and total <= 65535.
//  * Nothing is said about case where sender and receiver tags are different in OTR-encoded message. (Should we consider a case where there is a difference illegal?)
//  * What to do if DH-Commit message is received as response to other client instance's query tag? (no receiver instance tag specified yet)
//  * Allow accepting fragments that have 0 receiver tag? (For benefit of DH-Commit and Identity messages.)
//  * Spec does not go into case "What to do if message from next/other ratchet arrives, but with index other than 0." (i.e. cannot decrypt, must reject.)
//    This is part of section "When you receive a Data Message:".
//  * Spec does not go into case "What to do if message arrives with ratchetId < i and messageId == 0.". You can't blindly start processing this message as your would screw up your rotation.
//    This is part of section "When you receive a Data Message:".
//  * Are or aren't active attacks part of the scope of OTRv4?
//    Section "Deletion of Stored Message Keys" describes measures against active malicious participants.
/**
 * otr4j.
 */
package net.java.otr4j;
