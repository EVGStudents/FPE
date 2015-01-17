package ch.bfh.fpe.messageSpace;

import java.math.BigInteger;

/**
 * IntegerMessageSpace with a fixed minimum at 0.
 * Because we start counting at 0 for both rank and value,
 * the rank corresponds always to the element itself.<br/><br/>
 * 
 * Example:<code><br/>
 * //Create message space with the elements {0,1,2,...,10}:<br/>
 * IntegerMessageSpace ms = new IntegerMessageSpace(BigInteger.TEN);<br/>
 * BigInteger orders = ms.getOrder(); //Returns 11<br/>
 * BigInteger rank = ms.rank(BigInteger.ONE); //Returns 1<br/>
 * BigInteger value = ms.unrank(rank); //Returns 1</code>
 */
public class IntegerMessageSpace extends IntegerRangeMessageSpace {

	/**
	 * Constructs a integer message space.
	 * @param max Upper limit of the message space. Must not be positive.
	 */
	public IntegerMessageSpace(BigInteger max) {
		super(BigInteger.ZERO, max);
		if (max.signum() == -1) throw new IllegalArgumentException("Max must me postive.");
	}

}
