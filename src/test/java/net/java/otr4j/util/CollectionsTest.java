/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.util;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.emptySet;
import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;
import static net.java.otr4j.util.Collections.requireAbsent;
import static net.java.otr4j.util.Collections.requireElements;
import static net.java.otr4j.util.Collections.requireMinElements;
import static org.junit.Assert.assertSame;

@SuppressWarnings("ConstantConditions")
public final class CollectionsTest {

    @Test(expected = NullPointerException.class)
    public void testRequireNoIllegalValuesNullList() {
        requireAbsent(null, emptyList());
    }

    @Test
    public void testRequireNoIllegalValuesNoIllegals() {
        final List<String> list = asList("a", "b", "c");
        assertSame(list, requireAbsent(java.util.Collections.emptyList(), list));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRequireNoIllegalValuesWithIllegalValue() {
        final List<String> list = asList("a", "b", "c");
        requireAbsent(list, singletonList("a"));
    }

    @Test
    public void testRequireNoIllegalValuesNonintersectingIllegals() {
        final List<String> list = asList("a", "b", "c");
        assertSame(list, requireAbsent(singletonList("d"), list));
    }

    @Test(expected = NullPointerException.class)
    public void testRequireMinElementsNullCollection() {
        requireMinElements(0, null);
    }

    @Test
    public void testRequireMinElementsEmptyCollection() {
        final List<Object> list = emptyList();
        assertSame(list, requireMinElements(0, list));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRequireMinElementsBelowMinimum() {
        requireMinElements(1, emptyList());
    }

    @Test
    public void testRequireMinElementsAtMinimum() {
        final List<String> list = singletonList("a");
        assertSame(list, requireMinElements(1, list));
    }

    @Test
    public void testRequireMinElementsAboveMinimum() {
        final List<String> list = asList("a", "b");
        assertSame(list, requireMinElements(1, list));
    }

    @Test(expected = NullPointerException.class)
    public void testRequireElementsNullElementsList() {
        requireElements(null, emptyList());
    }

    @Test(expected = NullPointerException.class)
    public void testRequireElementsNullCollection() {
        requireElements(emptySet(), null);
    }

    @Test
    public void testRequireElementsEmptyElementsList() {
        final ArrayList<Object> list = new ArrayList<>();
        assertSame(list, requireElements(emptySet(), list));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRequireElementsMissingElement() {
        final ArrayList<Object> list = new ArrayList<>();
        requireElements(singleton("Hello"), list);
    }

    @Test
    public void testRequireElementsElementsPresent() {
        final List<Object> list = asList(new Object(), "a", "b", 3);
        assertSame(list, requireElements(asList("a", "b"), list));
    }
}
