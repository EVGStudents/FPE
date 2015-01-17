package ch.bfh.fpe.test;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import ch.bfh.fpe.messageSpace.EnumerationMessageSpace;
import ch.bfh.fpe.messageSpace.OutsideMessageSpaceException;

public class EnumerationMessageSpaceTest {
	
	@Test(expected=IllegalArgumentException.class)
	public void testEnumNull() {
		new EnumerationMessageSpace<String>(null);
	}

	@Test(expected=IllegalArgumentException.class)
	public void testEnumEmpty() {
		List<String> enumeration = new ArrayList<String>();
		new EnumerationMessageSpace<String>(enumeration);
	}
	
	@Test
	public void testOrder() {
		List<String> enumeration = new ArrayList<String>();
		String[] elements = new String[]{"Element1", "Element2", "Element3"};
		enumeration.addAll(Arrays.asList(elements));
		EnumerationMessageSpace<String> x = new EnumerationMessageSpace<String>(enumeration);
		BigInteger order = x.getOrder();
		assertEquals(BigInteger.valueOf(3), order);
	}
	
	@Test
	public void testDuplicates() {
		List<String> enumeration = new ArrayList<String>();
		String[] elements = new String[]{"Element1", "Element3", "Element2", "Element1", "Element3"};
		enumeration.addAll(Arrays.asList(elements));
		EnumerationMessageSpace<String> x = new EnumerationMessageSpace<String>(enumeration);
		BigInteger order = x.getOrder();
		assertEquals(BigInteger.valueOf(3), order);
	}
	
	@Test
	public void testRankString() {
		String[] elements = new String[]{"Element1", "Element2", "Element3"};
		List<String> enumeration = new ArrayList<String>(Arrays.asList(elements));
		EnumerationMessageSpace<String> x = new EnumerationMessageSpace<String>(enumeration);
		for (int i=0; i<elements.length; i++) {
			BigInteger rank = x.rank(elements[i]);
			assertEquals(BigInteger.valueOf(i), rank);
		}
	}
	
	@Test
	public void testUnrankString() {
		String[] elements = new String[]{"Element1", "Element2", "Element3"};
		List<String> enumeration = new ArrayList<String>(Arrays.asList(elements));
		EnumerationMessageSpace<String> x = new EnumerationMessageSpace<String>(enumeration);
		for (int i=0; i<elements.length; i++) {
			String value = x.unrank(BigInteger.valueOf(i));
			assertEquals(elements[i], value);
		}
	}
	
	@Test
	public void testRankInteger() {
		Integer[] primes = new Integer[]{2, 3, 5, 7, 11, 13, 17, 19, 23, 29};
		List<Integer> enumeration = new ArrayList<Integer>(Arrays.asList(primes));
		EnumerationMessageSpace<Integer> x = new EnumerationMessageSpace<Integer>(enumeration);
		for (int i=0; i<primes.length; i++) {
			BigInteger rank = x.rank(primes[i]);
			assertEquals(BigInteger.valueOf(i), rank);
		}
	}
	
	@Test(expected=OutsideMessageSpaceException.class)
	public void testRankOutsideMessageSpace() {
		String[] elements = new String[]{"Element1", "Element2", "Element3"};
		List<String> enumeration = new ArrayList<String>(Arrays.asList(elements));
		EnumerationMessageSpace<String> x = new EnumerationMessageSpace<String>(enumeration);
		x.rank("Element4");
	}
	
	@Test(expected=OutsideMessageSpaceException.class)
	public void testUnrankOutsideMessageSpace() {
		String[] elements = new String[]{"Element1", "Element2", "Element3"};
		List<String> enumeration = new ArrayList<String>(Arrays.asList(elements));
		EnumerationMessageSpace<String> x = new EnumerationMessageSpace<String>(enumeration);
		x.unrank(BigInteger.valueOf(3));
	}

}
