/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */
/**
 * Package containing wrapper classes for the external Ed448-Goldilocks support.
 * <p>
 * Types in this package are fine-tuned to the definitions of OTRv4.
 */
@ParametersAreNonnullByDefault
package net.java.otr4j.crypto.ed448;
// TODO replace Joldilocks with BC 1.60+, then update import-control constraints. Requires:
// * 'Is identity' check
// * 'Is on curve' check
// * multiply-by-base operation
// * multiply-by-(arbitrary)-point operation.
// * addition-operation
// * negation-operation
// * point-comparison (greater-than-or-equal, at the very least)
// * OPTIONAL: access to base point, modulus, prime-order?
// TODO verify that new ed448 crypto implementations do not litter memory space with temporary data. Check cloned arrays, appropriate memory cleaning, etc.

import javax.annotation.ParametersAreNonnullByDefault;