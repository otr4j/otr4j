/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.util;

import java.util.Collection;
import java.util.Iterator;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

import static java.util.Objects.requireNonNull;

/**
 * Blocking queue with additionally a precondition before elements are accepted.
 *
 * @param <E> Type of element contained in the queue.
 */
public final class ConditionalBlockingQueue<E> implements BlockingQueue<E> {

    private final BlockingQueue<E> queue;
    private final Predicate<E> condition;

    public ConditionalBlockingQueue(final Predicate<E> condition, final BlockingQueue<E> queue) {
        this.queue = requireNonNull(queue);
        this.condition = requireNonNull(condition);
    }

    @Override
    public boolean add(final E e) {
        verifyCondition(e);
        return this.queue.add(e);
    }

    @Override
    public boolean offer(final E e) {
        verifyCondition(e);
        return this.queue.offer(e);
    }

    @Override
    public E remove() {
        return this.queue.remove();
    }

    @Override
    public E poll() {
        return this.queue.poll();
    }

    @Override
    public E element() {
        return this.queue.element();
    }

    @Override
    public E peek() {
        return this.queue.peek();
    }

    @Override
    public void put(final E e) throws InterruptedException {
        verifyCondition(e);
        this.queue.put(e);
    }

    @Override
    public boolean offer(final E e, final long timeout, final TimeUnit unit) throws InterruptedException {
        verifyCondition(e);
        return this.queue.offer(e, timeout, unit);
    }

    @Override
    public E take() throws InterruptedException {
        return this.queue.take();
    }

    @Override
    public E poll(final long timeout, final TimeUnit unit) throws InterruptedException {
        return this.queue.poll(timeout, unit);
    }

    @Override
    public int remainingCapacity() {
        return this.queue.remainingCapacity();
    }

    @Override
    public boolean remove(final Object o) {
        return this.queue.remove(o);
    }

    @Override
    public boolean containsAll(final Collection<?> c) {
        return this.queue.containsAll(c);
    }

    @Override
    public boolean addAll(final Collection<? extends E> c) {
        verifyCondition(c);
        return this.queue.addAll(c);
    }

    @Override
    public boolean removeAll(final Collection<?> c) {
        return this.queue.removeAll(c);
    }

    @Override
    public boolean retainAll(final Collection<?> c) {
        return this.queue.retainAll(c);
    }

    @Override
    public void clear() {
        this.queue.clear();
    }

    @Override
    public int size() {
        return this.queue.size();
    }

    @Override
    public boolean isEmpty() {
        return this.queue.isEmpty();
    }

    @Override
    public boolean contains(final Object o) {
        return this.queue.contains(o);
    }

    @Override
    public Iterator<E> iterator() {
        return this.queue.iterator();
    }

    @Override
    public Object[] toArray() {
        return this.queue.toArray();
    }

    @Override
    public <T> T[] toArray(final T[] a) {
        return this.queue.toArray(a);
    }

    @Override
    public int drainTo(final Collection<? super E> c) {
        return this.queue.drainTo(c);
    }

    @Override
    public int drainTo(final Collection<? super E> c, final int maxElements) {
        return this.queue.drainTo(c, maxElements);
    }

    private void verifyCondition(final Iterable<? extends E> c) {
        for (final E e : c) {
            verifyCondition(e);
        }
    }

    private void verifyCondition(final E e) {
        if (!this.condition.test(e)) {
            throw new IllegalArgumentException("Illegal element. Element does not satisfy condition.");
        }
    }

    public interface Predicate<E> {
        boolean test(E e);
    }
}
