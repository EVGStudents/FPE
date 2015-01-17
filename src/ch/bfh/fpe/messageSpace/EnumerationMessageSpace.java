package ch.bfh.fpe.messageSpace;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Message space that is defined over an enumeration.
 * The elements of the enumeration can be of arbitrary type M and are passed
 * at construction time. Later they can not be changed to retain the order.
 * The user of this class has precise control over the position of each
 * element in the list before construction and is responsible to retain this order
 * for every subsequent use.
 * @param <M> type of the elements of the enumeration
 */
public class EnumerationMessageSpace<M> implements MessageSpace<M> {
	
	private final List<M> enumeration = new ArrayList<M>(); //Elements of the message space
	
	/**
	 * Constructs a enumeration messages space.
	 * The enumeration must not be empty.
	 * It is then copied to prevent modifications and retain the order.
	 * @param enumeration List with elements of the message space.
	 */
	public EnumerationMessageSpace(List<M> enumeration) {
		if (enumeration == null || enumeration.size() == 0)
			throw new IllegalArgumentException("Message space must not be empty.");
		Set<M> tempSet = new HashSet<M>();
		for (M element : enumeration) {
			if (tempSet.add(element))
				this.enumeration.add(element);
		}
	}

	/**
	 * Returns the order of this message space,
	 * therefore the number of elements in the enumeration
	 * @return the order of the message space
	 */
	@Override
	public BigInteger getOrder() {
		return BigInteger.valueOf(enumeration.size());
	}

	/**
	 * Returns the position of an element inside the message space.
	 * @param value is the element that should be ranked
	 * @return the position of the element inside the message space
	 * @throws OutsideMessageSpaceException if the value is outside the message space
	 */
	@Override
	public BigInteger rank(M value) {
		int rank = enumeration.indexOf(value);
		if (rank == -1) throw new OutsideMessageSpaceException("Value " + value);
		return BigInteger.valueOf(rank);
	}

	/**
	 * Inverse function of rank.
	 * Returns for a given position the corresponding element.
	 * @param rank position of an element
	 * @return the element at the specified position
	 * @throws OutsideMessageSpaceException if the rank is outside the message space
	 */
	@Override
	public M unrank(BigInteger rank) {
		try {
			return enumeration.get(rank.intValueExact());
		}
		catch (IndexOutOfBoundsException ex) {
			throw new OutsideMessageSpaceException("Rank " + rank);
		}
	}

}
