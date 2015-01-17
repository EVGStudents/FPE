package ch.bfh.fpe.messageSpace;

/**
 * Thrown to indicate that a value is outside the message space.
 */
public class OutsideMessageSpaceException extends RuntimeException {

	/**
	 * Construct a exception with a detail message that contains the
	 * value which caused the exception.
	 * @param value which is outside the message space
	 */
	public OutsideMessageSpaceException(String value) {
		super(value + " is outside the message space.");
	}

}
