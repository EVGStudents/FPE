package ch.bfh.fpe.intEnc;

import java.math.BigInteger;
import ch.bfh.fpe.FPECipher;
import ch.bfh.fpe.messageSpace.IntegerMessageSpace;

/**
 * IntegerCipher is an abstract class for implementing a Format Preserving Encryption (FPE) Cipher for numbers.<br>
 * The IntegerCipher encrypts a given input number from a specified range in such way, that the output value is also a number from the same range.<br>
 * This range is defined by an IntegerMessageSpace delivered in the constructor.<br/><br/>
 * 
 * Currently the only implemented IntegerCipher in this package is the FFXIntegerCipher who can handle numbers from zero to a maximum of 38 decimal digits (128 bits).<br>
 * For applications where numbers bigger than representable with 128 bit has to be encrypted, the implementation of a large-space FPECipher will be needed.<br>
 * The FFX standard has no mathematically proven security for message space sizes under 8 bits. For high security applications with small numbers the implementation of a tiny-space FPECipher will be needed.
 */
public abstract class IntegerCipher extends FPECipher<BigInteger> {

	/**
	 * Constructs a IntegerCipher for the number range determined in the IntegerMessageSpace.
	 * @param messageSpace IntegerMessageSpace to determine the number range of the input respectively output of the encryption/decryption
	 */
	public IntegerCipher(IntegerMessageSpace messageSpace) {
		super(messageSpace);
	}
	
}
