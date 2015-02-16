package ch.bfh.fpe;

import ch.bfh.fpe.messageSpace.MessageSpace;

/**
 * FPECipher is an abstract class for implementing a Format Preserving Encryption (FPE) Cipher.<br>
 * A FPECipher encrypts a given plaintext in such a way that the output is in the same format as the input.<br>
 * The format is given by a MessageSpace delivered in the constructor.<br><br>
 * 
 * Implemented message spaces in this package are:<ul>
 * <li>StringMessageSpace: Format can be given by a regular expression or a deterministic finite-state automata</li>
 * <li>IntegerMessageSpace: Format defines numbers from zero to a maximum value</li>
 * <li>IntegerRangeMessageSpace: Format defines numbers from a minimum to a maximum value</li>
 * <li>EnumerationMessageSpace: No format is needed, all allowed values are specified in a list</li></ul>
 * For further informations about a specific message space consult its documentation.<br/><br/>
 * @param <M> type of elements in given message space respectively type of elements to be encrypted/decrypted
 */
public abstract class FPECipher<M> {
	
	private MessageSpace<M> messageSpace;
	
	/**
	 * Constructs a FPECipher for the format determined in the message space.
	 * @param messageSpace message space to determine the format of the input respectively output of the encryption/decryption
	 */
	public FPECipher(MessageSpace<M> messageSpace) {
		if (messageSpace == null) throw new IllegalArgumentException("Message space must not be null");
		this.messageSpace = messageSpace;
	}

	
	/**
	 * Returns the message space of this FPECipher.
	 * @return message space of this FPECipher
	 */
	public MessageSpace<M> getMessageSpace() {
		return messageSpace;
	}
	
	/**
	 * Encrypts a plaintext in such a way that the output is in the format as given in the message space.
	 * @param plaintext value to be encrypted, has to be in a valid format according to the given message space
	 * @param key randomly computed key 
	 * @param tweak random bytes to prevent deterministic encryption
	 * @return encrypted value of plaintext
	 */
	public abstract M encrypt(M plaintext, byte[] key, byte[] tweak);
	
	
	/**
	 * Decrypts a ciphertext to its originally plaintext.
	 * @param ciphertext ciphertext to be decrypted (has to be encrypted with the same MessageSpace as given in this instance)
	 * @param key must be exactly the same key as used for the encryption of this ciphertext
	 * @param tweak must be exactly the same tweak as used for the encryption of this ciphertext
	 * @return decrypted value of ciphertext
	 */
	public abstract M decrypt(M ciphertext, byte[] key, byte[] tweak);
	
}
