package ch.bfh.fpelib.test;

import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.Test;

import ch.bfh.fpelib.messageSpace.IntegerMessageSpace;
import ch.bfh.fpelib.messageSpace.OutsideMessageSpaceException;

public class IntegerMessageSpaceTest {
	
	private BigInteger i(long i) {
		return BigInteger.valueOf(i);
	}

	@Test
	public void testOrder() {
		IntegerMessageSpace x = new IntegerMessageSpace(i(100));
		BigInteger order = x.getOrder();
		assertEquals(i(101), order);
	}
	
	@Test
	public void testOrderOne() {
		IntegerMessageSpace x = new IntegerMessageSpace(i(0));
		BigInteger order = x.getOrder();
		assertEquals(BigInteger.ONE, order);
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void testNegative() {
		new IntegerMessageSpace(i(-100));
	}
	
	@Test
	public void testOrderBigNumber() {
		IntegerMessageSpace x = new IntegerMessageSpace(i(Long.MAX_VALUE).multiply(i(Long.MAX_VALUE)));
		BigInteger order = x.getOrder();
		BigInteger expected = i(Long.MAX_VALUE).multiply(i(Long.MAX_VALUE)).add(i(1));
		assertEquals(expected, order);
	}

	@Test
	public void testRank() {
		IntegerMessageSpace x = new IntegerMessageSpace(i(100));
		BigInteger rank = x.rank(i(20));
		assertEquals(i(20), rank);
	}

	@Test
	public void testUnrank() {
		IntegerMessageSpace x = new IntegerMessageSpace(i(100));
		BigInteger value = x.unrank(i(20));
		assertEquals(i(20), value);
	}
	
	@Test(expected=OutsideMessageSpaceException.class)
	public void testRankOutsideRange() {
		IntegerMessageSpace x = new IntegerMessageSpace(i(100));
		x.rank(i(-20));
	}
	
	@Test(expected=OutsideMessageSpaceException.class)
	public void testUnrankOutsideRange() {
		IntegerMessageSpace x = new IntegerMessageSpace(i(100));
		x.unrank(i(120));
	}

}
