package ch.bfh.fpe.messageSpace;

import java.math.BigInteger;

/**
 * Message space that is defined over an integer range. Negative values are allowed.
 * The type BigInteger is used which allows arbitrary-precision integers.
 * The range is defined with the lower- and upper limit in the constructor.<br/><br/>
 * 
 * Example:<code><br/>
 * BigInteger bigInt5 = BigInteger.valueOf(5);<br/>
 * //Create message space with the elements {5,6,7,8,9,10}:<br/>
 * IntegerRangeMessageSpace ms = new IntegerRangeMessageSpace(bigInt5, BigInteger.TEN);<br/>
 * BigInteger order = ms.getOrder();   //Returns 6<br/>
 * BigInteger rank = ms.rank(bigInt5); //Returns 0<br/>
 * BigInteger value = ms.unrank(rank); //Returns 5</code>
 */
public class IntegerRangeMessageSpace extends MessageSpace<BigInteger> {

	private final BigInteger min; //lower limit of message space
	private final BigInteger max; //upper limit of message space

	/**
	 * Constructs a integer range message space. 
	 * @param min Lower limit of the message space.
	 * @param max Upper limit of the message space. Must not be smaller than min.
	 */
	public IntegerRangeMessageSpace(BigInteger min, BigInteger max) {
		this.min = min;
		this.max = max;
		if ((min == null) || (max == null))
			throw new IllegalArgumentException("Min and max must not be null.");
		if (min.compareTo(max) > 0)
			throw new IllegalArgumentException("Min can't be greater than max.");
	}

	/**
	 * Returns the order of this message space,
	 * therefore the number of elements in the domain.
	 * It is given by the difference between min and max + 1.
	 * @return the order of the message space
	 */
	@Override
	public BigInteger getOrder() {
		return max.subtract(min).add(BigInteger.ONE);
	}	

	/**
	 * Returns the position of an element inside the message space.
	 * @param value is the integer that should be ranked
	 * @return the position of the value inside the message space
	 * @throws OutsideMessageSpaceException if the value is outside the message space
	 */
	@Override
	public BigInteger rank(BigInteger value) {
		if (((value.compareTo(max) > 0)) || (value.compareTo(min) < 0))
			throw new OutsideMessageSpaceException("Value " + value);
		return value.subtract(min);
	}

	/**
	 * Inverse function of rank.
	 * Returns for a given position the corresponding element.
	 * @param rank position of an element
	 * @return the integer element at the specified position
	 * @throws OutsideMessageSpaceException if the rank is outside the message space
	 */
	@Override
	public BigInteger unrank(BigInteger rank) {
		if ((rank.signum() == -1) || (rank.compareTo(getOrder()) >= 0))
			throw new OutsideMessageSpaceException("Rank " + rank);
		return rank.add(min);
	}

}
