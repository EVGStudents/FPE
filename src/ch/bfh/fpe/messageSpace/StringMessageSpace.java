package ch.bfh.fpe.messageSpace;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import dk.brics.automaton.Automaton;
import dk.brics.automaton.RegExp;
import dk.brics.automaton.State;
import dk.brics.automaton.Transition;

/**
 * Message space that is defined over a string. The domain of the string is defined
 * by an deterministic finite-state automata (DFA) or a regular expression.
 * This class implements the rank/unrank approach described in chapter 5 in
 * <a href="https://eprint.iacr.org/2009/251.pdf">https://eprint.iacr.org/2009/251.pdf</a>
 * (With the exception that the rank is not only defined over one slice but all.)<br/>
 * For the definition of the automaton, the regular expression and the conversion from
 * the regular expression to a DFA, the <a href="http://www.brics.dk/automaton">dk.brics.automaton library</a> is used.
 * The syntax of regular expressions that are supported are described <a href="http://www.brics.dk/automaton/doc/index.html?dk/brics/automaton/RegExp.html">here</a>.<br/><br/>
 * 
 * A messages space is finite but with regular expressions it is possible to define infinite languages. 
 * If the regular expression operation * or + is used or the word length is longer than the default of 128 characters,
 * the maxWordLength parameter of the constructor should be used to define the maximum length of the string.<br/><br/>
 * 
 * Example 1 (regular expression):<code><br/>
 * String swissZIPCode = "([1-468][0-9]|[57][0-7]|9[0-6])[0-9]{2}";<br/>
 * String validZIP = "3063";<br/>
 * String invalidZIP = "5802";<br/>
 * StringMessageSpace ms = new StringMessageSpace(swissZIPCode);<br/><br/>
 * 
 * //valid zip code<br/>
 * BigInteger order = ms.getOrder(); //Returns 8300<br/>
 * BigInteger rank = ms.rank(validZIP); //Returns 2063<br/>
 * String zip = ms.unrank(rank); //Returns "3063"<br/><br/>
 * 
 * //invalid zip code which is outside the message space<br/>
 * try {<br/>
 * 	  ms.rank(invalidZIP);<br/>
 * }<br/>
 * catch (OutsideMessageSpaceException ex) {<br/>
 * 	  //invalid zip code throws exception<br/>
 * }<br/>
 * </code><br/>
 * 
 * Example 2 (regular expression with *):<code><br>
 * //Binary string starting with 0 and maximal length of 3.<br>
 * //Thus the elements are {0, 00, 01, 000, 001, 010, 011}.<br>
 * StringMessageSpace ms = new StringMessageSpace("0[0-1]*", 3);</code>
 */
public class StringMessageSpace implements MessageSpace<String> {
	
	public static final int DEFAULT_MAX_WORD_LENGTH = 128;
	private Automaton dfa;
	private Map<State,Integer> states = new HashMap<State,Integer>();
	private List<Character> alphabet;
	private List<BigInteger[]> table = new ArrayList<BigInteger[]>();
	private BigInteger order = BigInteger.ZERO;
	
	/**
	 * Constructs a string message spaces defined by a regular expression.
	 * The default maximum word length of 128 characters is used.
	 * @param regexp the regular expression (<a href="http://www.brics.dk/automaton/doc/index.html?dk/brics/automaton/RegExp.html">Format</a>)
	 */
	public StringMessageSpace(String regexp) {
		this(new RegExp(regexp).toAutomaton());
	}
	
	/**
	 * Constructs a string message spaces defined by a regular expression.
	 * @param regexp the regular expression (<a href="http://www.brics.dk/automaton/doc/index.html?dk/brics/automaton/RegExp.html">Format</a>)
	 * @param maxWordLength defines the maximum word length
	 */
	public StringMessageSpace(String regexp, int maxWordLength) {
		this(new RegExp(regexp).toAutomaton(), maxWordLength);
	}
	
	/**
	 * Constructs a string message spaces defined by a DFA.
	 * The default maximum word length of 128 characters is used.
	 * @param dfa the DFA which defines the string format
	 */
	public StringMessageSpace(Automaton dfa) {
		this(dfa, DEFAULT_MAX_WORD_LENGTH);
	}
	
	/**
	 * Constructs a string message spaces defined by a DFA.
	 * @param dfa the DFA which defines the string format
	 * @param maxWordLength defines the maximum word length
	 */
	public StringMessageSpace(Automaton dfa, int maxWordLength) {
		this.dfa = dfa;
		if (dfa==null)
			throw new IllegalArgumentException("DFA must not be null.");
		if (!dfa.isDeterministic())
			throw new IllegalArgumentException("DFA must be deterministic.");
		setStates();
		setAlphabet();
		buildTable(maxWordLength);
		if (order.signum()==0)
			throw new IllegalArgumentException("Order must not be empty.");
	}
	
	/**
	 * Part of the initialization of the message space:
	 * Writes all states to a private instance variable. 
	 */
	private void setStates() {
		int i=0;
		for (State state : dfa.getStates()) {
			states.put(state, i++);
		}
	}
	
	/**
	 * Part of the initialization of the message space:
	 * Writes all characters of the alphabet to a private instance variable. 
	 */
	private void setAlphabet() {
		Set<Character> alphabet = new HashSet<Character>();
		//for each transition add characters to set
		for (State state : dfa.getStates()) {
			for (Transition transition : state.getTransitions()) {
				for (char i = transition.getMin(); i<=transition.getMax(); i++) {
					alphabet.add(i);
				}
			}
		}
		this.alphabet = new ArrayList<Character>(alphabet);
	}
	
	/**
	 * Part of the initialization of the message space:
	 * Precomputes a table which allows fast rank and unrank operations.
	 * @param maxWordLength defines the maximum word length
	 */
	private void buildTable(int maxWordLength) {
		BigInteger[] initRow = new BigInteger[states.size()];
		
		//build first row: final state = 1, otherwise = 0
		for (Entry<State,Integer> state : states.entrySet()) {
			if (state.getKey().isAccept())
				initRow[state.getValue()] = BigInteger.ONE;
			else
				initRow[state.getValue()] = BigInteger.ZERO;
		}
		table.add(initRow);
		
		//build remaining rows:
		//for each i with 1 <= i <= maxWordLength do:
		//for each transition do: Table[i,sourceState] += Table[i-1,destState] 
		for (int i=1; i<=maxWordLength; i++) {
			boolean maxLength = true;
			BigInteger[] row = new BigInteger[states.size()];
			for (Entry<State,Integer> state : states.entrySet()) {
				row[state.getValue()] = BigInteger.ZERO;
				for (char character : alphabet) {
					State destState = state.getKey().step(character);
					if (destState!=null)
						row[state.getValue()] = row[state.getValue()].add(table.get(i-1)[states.get(destState)]);
				}
				if (row[state.getValue()].signum() == 1) maxLength = false;
			}
			//if no final state reachable (row with zeros) stop, otherwise add row 
			if (!maxLength) table.add(row);
			else break;
		}
		
		//compute order
		for (int i=1; i<table.size(); i++) {
			order = order.add(table.get(i)[states.get(dfa.getInitialState())]);
		}
	}

	/**
	 * Returns the order of this message space,
	 * therefore the number of possible strings in the domain.
	 * @return the order of the message space
	 */
	@Override
	public BigInteger getOrder() {
		return order;
	}
	
	
	/**
	 * Returns the maximum possible value of this message space,
	 * therefore the number of elements in the domain minus one.
	 * @return the order of the message space
	 */
	@Override
	public BigInteger getMaxValue() {
		return order.subtract(BigInteger.ONE);
	}

	
	/**
	 * Returns true if the language of the automaton that defines this
	 * message space is finite.
	 * @return True if DFA is finite, otherwise false
	 */
	public boolean isFinite() {
		return dfa.isFinite();
	}

	/**
	 * Returns the position of an element inside the message space.
	 * The order of the elements is lexicographical.
	 * @param value is the string that should be ranked
	 * @return the position of the value inside the message space
	 * @throws OutsideMessageSpaceException if the value is outside the message space
	 */
	@Override
	public BigInteger rank(String value) {
		if (!dfa.run(value))
			throw new OutsideMessageSpaceException("Value " + value);
		State state = dfa.getInitialState();
		int length = value.length();
		
		//get global rank from slice-rank: add order of preceding slices
		BigInteger rank = BigInteger.ZERO;
		for (int i=1; i<length; i++) {
			rank = rank.add(table.get(i)[states.get(dfa.getInitialState())]);
		}
		
		//rank
		for (int i=0; i<length; i++) {
			for (int j=0; j<alphabet.indexOf(value.charAt(i)); j++) {
				State newState = state.step(alphabet.get(j));
				if (newState!=null) {
					rank = rank.add(table.get(length-(i+1))[states.get(newState)]);
				}
			}
			state = state.step(value.charAt(i));
		}
		return rank;
	}

	/**
	 * Inverse function of rank.
	 * Returns for a given position the corresponding element.
	 * @param rank position of an element
	 * @return the string element at the specified position
	 * @throws OutsideMessageSpaceException if the rank is outside the message space
	 */
	@Override
	public String unrank(BigInteger rank) {
		if (getOrder().compareTo(rank)<1 || rank.signum() == -1)
			throw new OutsideMessageSpaceException("Rank " + rank);
		StringBuilder value = new StringBuilder();
		State state = dfa.getInitialState();
		
		//get slice-rank from global rank: subtract order of preceding slices
		int n; //after loop n will be the length of the message
		for (n=1; rank.subtract(table.get(n)[states.get(dfa.getInitialState())]).signum() != -1; n++) {
			rank = rank.subtract(table.get(n)[states.get(dfa.getInitialState())]);
		}
		
		//unrank
		for (int i=1; i<=n; i++) {
			int j;
			for (j=0; j<alphabet.size(); j++) {
				State newState = state.step(alphabet.get(j));
				if (newState!=null) {
					BigInteger step = table.get(n-i)[states.get(newState)];
					if (rank.compareTo(step)>=0)
						rank = rank.subtract(step);
					else break;
				}
			}
			value.append(alphabet.get(j));
			state = state.step(alphabet.get(j));
		}
		return value.toString();
	}

}
