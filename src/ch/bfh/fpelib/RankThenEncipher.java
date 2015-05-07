package ch.bfh.fpelib;

import java.math.BigInteger;

import ch.bfh.fpelib.intEnc.EME2IntegerCipher;
import ch.bfh.fpelib.intEnc.FFXIntegerCipher;
import ch.bfh.fpelib.intEnc.IntegerCipher;
import ch.bfh.fpelib.intEnc.KnuthShuffleCipher;
import ch.bfh.fpelib.messageSpace.MessageSpace;

/** 
 * This class is an implementation of the "Rank-then-Encipher Approach" for Format Preserving Encryption Cipher: <a href="https://eprint.iacr.org/2009/251.pdf">https://eprint.iacr.org/2009/251.pdf</a><br><br>
 * 
 * RankThenEncipher encrypts a given plaintext in such a way that the output is in the same format as the input.<br>
 * The format is given by a message space delivered in the constructor. There are no restrictions concerning the type of the message space, all message spaces which implement the MessageSpaces interface are allowed.<br/><br/>  
 * 
 * Implemented MessageSpaces in this package are:
 * <ul><li>StringMessageSpace: Format can be given by a regular expression or a dfa automaton</li>
 * 		<li>IntegerMessageSpace: Format defines numbers from zero to a maximum value</li>
 * 		<li>IntegerRangeMessageSpace: Format defines numbers from a minimum to a maximum value</li>
 * 		<li>EnumerationMessageSpace: No format is needed, all allowed values are specified in a list</li></ul>
 * For further information about a specific MessageSpace consult its documentation.<br/><br/>
 * 
 * The main idea behind the "Rank-then-Encipher Approach" is that the algorithm does not directly encrypt the input value, e.g. a string, but assigns him first a number.<br>
 * This number is called "rank" and makes the input distinctly identifiable in the message space.
 * Since the rank is a normal number it can be encrypted with an IntegerCipher like the FFXIntegerCipher.<br> 
 * The encrypted number will also be a number distinctly identifiable in the message space and so we are able to "unrank" it and get back another possible (e.g. string) value in the message space.<br>
 * For further details about the "Rank-then-Encipher Approach" visits its documentation on the link given above.<br/><br/>
 * 
 * Following a simple example how to use a RankThenEncipher with an EnumerationMessageSpace:<br/><br/>
 * 
 * <code>String[] countries = new String[]{"Austria","Canada","France","Germany","Mexico","Poland","Spain","Switzerland","United States"};<br/><br/>
 * 
 * EnumerationMessageSpace<String> messageSpace = new EnumerationMessageSpace<String>(Arrays.asList(countries));<br>
 * RankThenEncipher<String> rankThenEnc = new RankThenEncipher<String>(messageSpace);<br/><br/>
 *	
 * String encCountry = rankThenEnc.encrypt("Switzerland", key, tweak); //possible encryption result: "Mexico"<br>
 * String decCountry = rankThenEnc.decrypt(encCountry, key, tweak);//decryption brings back "Switzerland"<br></code><br/>
 * 
 * If you try to encrypt or decrypt a value that is not defined in the message space, a OutsideMessageSpaceException is thrown.<br>
 * <code>String encCountry = rankThenEnc.encrypt("Afghanistan", key, tweak);</code><br>
 * This code would throw an Exception because "Afghanistan" is a country not defined in the EnumerationMessageSpace.<br/><br/>
 * 
 * Following an example how to use RankThenEncipher with an StringMessageSpace where a regular expression for valid MasterCard credit card numbers is defined:<br><br>
 * <code>String masterCardNumbers = "5[1-5][0-9]{14}";<br>
 * StringMessageSpace messageSpace = new StringMessageSpace(masterCardNumbers);<br/><br/>
 * 
 * RankThenEncipher<String> rankThenEnc = new RankThenEncipher<String>(messageSpace);<br>
 * String encCardNumber = rankThenEnc.encrypt("5500187004490131", key, tweak); //possible encryption result: "5333831844603012"</code><br/><br/>
 * 
 * The key is a random 16-byte-array and has to be the same for decrypting a value as he was for encrypting it.<br>
 * The tweak is a value similar to an initialization vector (iv) or a salt on hashing in the sense that he prevents a deterministic encryption. 
 * A tweak can be arbitrary long and has to be the same for decrypting a value as he was for encrypting it.<br/><br/>
 * 
 * @param <M> type of elements in given message space respectively type of elements to be encrypted/decrypted
 */
public class RankThenEncipher<M> extends FPECipher<M> {
	
	private IntegerCipher integerCipher;

	/**
	 * Constructs a RankThenEncipher-FPE-Cipher.
	 * Depending on the order, the most secure and then efficient integer cipher is chosen.
	 * At the moment, KnuthShuffleCipher, FFXIntegerCipher and EME2IntegerCipher are implemented.
	 * @param messageSpace defines the format of plaintext and ciphertext.
	 */
	public RankThenEncipher(MessageSpace<M> messageSpace) {
		super(messageSpace);
		if (messageSpace==null) throw new IllegalArgumentException("MessageSpace must not be null");
		
		//up to 7 bit use Knuth Shuffle
		if (messageSpace.getOrder().bitLength()<8){ 
			integerCipher = new KnuthShuffleCipher(messageSpace.getMaxValue());
		}
		//up to 128 bit use FFX
		else if (messageSpace.getOrder().bitLength()<=128) {
			integerCipher = new FFXIntegerCipher(messageSpace.getMaxValue());
		}
		//for more than 128 bit use EME2
		else {
			integerCipher = new EME2IntegerCipher(messageSpace.getMaxValue());
		}
	
	}
	
	/**
	 * Constructs a RankThenEncipher-FPE-Cipher.
	 * @param messageSpace defines the format of plaintext and ciphertext.
	 * @param integerCipher defines the FPE integer cipher used to encrypt/decrypt
	 */
	public RankThenEncipher(MessageSpace<M> messageSpace, IntegerCipher integerCipher) {
		super(messageSpace);
		if (messageSpace==null)
			throw new IllegalArgumentException("MessageSpace must not be null");
		if (integerCipher==null)
			throw new IllegalArgumentException("IntegerCipher must not be null");
		if (!messageSpace.getOrder().equals(integerCipher.getMessageSpace().getOrder()))
			throw new IllegalArgumentException("Message space of plain-/ciphertext and integer cipher must have the same order");
		this.integerCipher = integerCipher;
	}

	/**
	 * {@inheritDoc}
	 * @throws OutsideMessageSpaceException if plaintext is outside the message space.
	 */
	@Override
	public M encrypt(M plaintext, Key key, byte[] tweak) {
		BigInteger rank = getMessageSpace().rank(plaintext);
		BigInteger rankEnc = integerCipher.encrypt(rank, key, tweak);
		M ciphertext = getMessageSpace().unrank(rankEnc);
		return ciphertext;
	}

	/**
	 * {@inheritDoc}
	 * @throws OutsideMessageSpaceException if ciphertext is outside the message space.
	 */
	@Override
	public M decrypt(M ciphertext, Key key, byte[] tweak) {
		BigInteger rankEnc = getMessageSpace().rank(ciphertext);
		BigInteger rank = integerCipher.decrypt(rankEnc, key, tweak);
		M plaintext = getMessageSpace().unrank(rank);
		return plaintext;
	}

}
