package ch.bfh.fpe.test;

import static org.junit.Assert.*;
import java.math.BigInteger;
import org.junit.Test;
import ch.bfh.fpe.messageSpace.StringMessageSpace;
import dk.brics.automaton.Automaton;
import dk.brics.automaton.Datatypes;

public class StringMessageSpaceTest {
	
	@Test(expected=IllegalArgumentException.class)
	public void testDFANull() {
		Automaton dfa = null;
		new StringMessageSpace(dfa);
	}

	@Test(expected=IllegalArgumentException.class)
	public void testDFAEmpty() {
		Automaton dfa = Automaton.makeEmpty();
		new StringMessageSpace(dfa);
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void testDFANonDeterministic() {
		Automaton nfa = new Automaton();
		nfa.setDeterministic(false);
		new StringMessageSpace(nfa);
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void testRegexEmpty() {
		new StringMessageSpace("");
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void testDFAOrderOne() {
		Automaton dfa = Automaton.makeEmptyString();
		new StringMessageSpace(dfa);
	}
	
	@Test
	public void testOrderFinite() {
		Automaton dfa = Automaton.makeInterval(20, 80, 2);
		StringMessageSpace x = new StringMessageSpace(dfa);
		BigInteger order = x.getOrder();
		assertTrue(x.isFinite());
		assertEquals(BigInteger.valueOf(61), order);
	}

	@Test
	public void testOrderNonFinite() {
		int maxWordLength = 15;
		String regex = "x*";
		StringMessageSpace x = new StringMessageSpace(regex, maxWordLength);
		BigInteger order = x.getOrder();
		assertFalse(x.isFinite());
		assertEquals(BigInteger.valueOf(maxWordLength), order);
	}
	
	@Test(expected=Exception.class)
	public void testRankOutsideMessageSpace() {
		Automaton dfa = Automaton.makeMaxInteger("1");
		StringMessageSpace x = new StringMessageSpace(dfa);
		x.rank("2");
	}
	
	@Test
	public void testRankMinValue() {
		Automaton dfa = Automaton.makeInterval(20, 80, 2);
		StringMessageSpace x = new StringMessageSpace(dfa);
		BigInteger rank = x.rank("20");
		assertEquals(BigInteger.ZERO, rank);
	}
	
	@Test
	public void testRankMaxValue() {
		Automaton dfa = Automaton.makeInterval(20, 80, 2);
		StringMessageSpace x = new StringMessageSpace(dfa);
		BigInteger rank = x.rank("80");
		assertEquals(BigInteger.valueOf(60), rank);
	}
	
	@Test
	public void testRankAll() {
		String[] exptected = new String[]{ "e", "ae", "be", "ce", "de", "aae", "abe", "ace", "ade", "aaae", "aabe", "aace", "aade" };
		String regexp = "a*[b-d]?e";
		StringMessageSpace x = new StringMessageSpace(regexp);
		for (int i=0; i<exptected.length; i++) {
			BigInteger rank = x.rank(exptected[i]);
			assertEquals(BigInteger.valueOf(i), rank);
		}
	}
	
	@Test
	public void testUnrankAll() {
		String[] exptected = new String[]{ "e", "ae", "be", "ce", "de", "aae", "abe", "ace", "ade", "aaae", "aabe", "aace", "aade" };
		String regexp = "a*[b-d]?e";
		StringMessageSpace x = new StringMessageSpace(regexp);
		for (int i=0; i<exptected.length; i++) {
			String value = x.unrank(BigInteger.valueOf(i));
			assertEquals(exptected[i], value);
		}
	}
	
	@Test
	public void testRankUnrankURI() {
		String uri = "http://ti.bfh.ch/";
		Automaton dfa = Datatypes.get("URI");
		StringMessageSpace x = new StringMessageSpace(dfa);
		BigInteger rank = x.rank(uri);
		String value = x.unrank(rank);
		assertEquals(uri, value);
	}
	
}
