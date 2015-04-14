package ch.bfh.fpe.messageSpace;

import java.math.BigInteger;

/**
 * A class that implements this interface defines a message space.<br/>
 * A message spaces enables to define a domain.
 * Methods are provided to get the rank of a element of this domain
 * and the inverse, the element at a particular rank.<br/><br/>
 * 
 * In the context of this format-preserving encryption library
 * it is used in two different ways:<ul>
 * <li>A FPE cipher aims to encipher on a message space of the form
 * X'=[N]={0,1,...,N-1} for some arbitrary number N. The implementing class
 * IntegerMessageSpace is used to define N.</li> 
 * <li>The rank-then-encipher approach is used when the message to encrypt
 * is not part of the aforementioned domain X' but in a related domain X.
 * The message space is then used to transform an element of X to an
 * element of X' and backwards. For more details see the documentation of
 * the RankThenEncipher class.</li>
 * <li>But the message spaces could also be used independent from FPE
 * to perform rank/unrank operations.</li></ul>
 * 
 * The rank starts counting at 0.<br/>
 * All implementing classes are immutable. Thus the domain is defined
 * over the constructor and can not be changed after.<br/><br/>
 * 
 * @param <M> type of the elements of the domain. Thus the type of the
 * value that is ranked and the type of unrank's return value.
 */
public abstract class MessageSpace<M> {
	
	/**
	 * Returns the order of this message space,
	 * therefore the number of elements in the domain.
	 * @return the order of the message space
	 */
	public abstract BigInteger getOrder();
	
	/**
	 * Returns the maximum possible value of this message space,
	 * therefore the number of elements in the domain minus one.
	 * @return the order of the message space
	 */
	public BigInteger getMaxValue() {
		return getOrder().subtract(BigInteger.ONE);
	}
	
	/**
	 * Function X -> N, which returns for every element x of message space X
	 * a natural number n in 0 <= n < getOrder(), which is the position inside
	 * the message space. The order is defined by the implementing class.
	 * @param value that should be ranked
	 * @return the position of the value inside the message space
	 */
	public abstract BigInteger rank(M value);
	
	/**
	 * Inverse function of rank.
	 * Function N -> X, which returns for a position the corresponding element.
	 * @param rank position of an element
	 * @return the element at the specified position
	 */
	public abstract M unrank(BigInteger rank);
	
}
