package ch.bfh.fpelib.test;

import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.Test;

import ch.bfh.fpelib.messageSpace.IntegerRangeMessageSpace;
import ch.bfh.fpelib.messageSpace.OutsideMessageSpaceException;

public class IntegerRangeMessageSpaceTest {
	
	private BigInteger i(long i) {
		return BigInteger.valueOf(i);
	}

	@Test
	public void testSpaceOrder() {
		IntegerRangeMessageSpace x = new IntegerRangeMessageSpace(i(20), i(100));
		BigInteger order = x.getOrder();
		assertEquals(i(81), order);
	}
	
	@Test
	public void testOrderOne() {
		IntegerRangeMessageSpace x = new IntegerRangeMessageSpace(i(0), i(0));
		BigInteger order = x.getOrder();
		assertEquals(BigInteger.ONE, order);
	}
	
	@Test
	public void testOrderNegative() {
		IntegerRangeMessageSpace x = new IntegerRangeMessageSpace(i(-100), i(-20));
		BigInteger order = x.getOrder();
		assertEquals(i(81), order);
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void testSpaceInverted() {
		new IntegerRangeMessageSpace(i(-20), i(-100));
	}

	@Test
	public void testRank() {
		IntegerRangeMessageSpace x = new IntegerRangeMessageSpace(i(-100), i(100));
		BigInteger rank = x.rank(i(-20));
		assertEquals(i(80), rank);
	}
	
	@Test
	public void testUnrank() {
		IntegerRangeMessageSpace x = new IntegerRangeMessageSpace(i(-100), i(100));
		BigInteger value = x.unrank(i(80));
		assertEquals(i(-20), value);
	}
	
	@Test(expected=OutsideMessageSpaceException.class)
	public void testRankOutsideRange() {
		IntegerRangeMessageSpace x = new IntegerRangeMessageSpace(i(-100), i(100));
		x.rank(i(-120));
	}
	
	@Test(expected=OutsideMessageSpaceException.class)
	public void testUnrankOutsideRange() {
		IntegerRangeMessageSpace x = new IntegerRangeMessageSpace(i(-100), i(100));
		x.unrank(i(220));
	}

}
