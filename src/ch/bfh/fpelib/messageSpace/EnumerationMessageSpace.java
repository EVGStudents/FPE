package ch.bfh.fpelib.messageSpace;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Message space that is defined over an enumList.
 * The elements of the enumList can be of arbitrary type M and are passed
 * at construction time. Later they cannot be changed to retain the order.
 * The user of this class has precise control over the position of each
 * element in the list before construction and is responsible to retain this order
 * for every subsequent use.
 * @param <M> type of the elements of the enumList
 */
public class EnumerationMessageSpace<M> extends MessageSpace<M> {
	
	private final List<M> enumList = new ArrayList<M>(); //Elements of the message space
	private final Map<M,BigInteger> enumMap = new HashMap<M,BigInteger>(); //Elements with position index for fast rank
	
	/**
	 * Constructs a enumList messages space.
	 * The enumList must not be empty.
	 * It is then copied to prevent modifications and retain the order.
	 * @param enumList List with elements of the message space.
	 */
	public EnumerationMessageSpace(List<M> enumeration) {
		if (enumeration == null || enumeration.size() == 0)
			throw new IllegalArgumentException("Message space must not be empty.");
		BigInteger i = BigInteger.ZERO;
		for (M element : enumeration) {
			if (!enumMap.containsKey(element)) {
				this.enumMap.put(element, i);
				this.enumList.add(element);
				i = i.add(BigInteger.ONE);
			}
		}
	}

	/**
	 * Returns the order of this message space,
	 * therefore the number of elements in the enumList
	 * @return the order of the message space
	 */
	@Override
	public BigInteger getOrder() {
		return BigInteger.valueOf(enumList.size());
	}

	/**
	 * Returns the position of an element inside the message space.
	 * @param value is the element that should be ranked
	 * @return the position of the element inside the message space
	 * @throws OutsideMessageSpaceException if the value is outside the message space
	 */
	@Override
	public BigInteger rank(M value) {
		BigInteger rank = enumMap.get(value);
		if (rank == null) throw new OutsideMessageSpaceException("Value " + value);
		return rank;
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
			return enumList.get(rank.intValueExact());
		}
		catch (IndexOutOfBoundsException ex) {
			throw new OutsideMessageSpaceException("Rank " + rank);
		}
	}



}
