package ch.bfh.fpe.intEnc;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;
import java.util.HashMap;
import java.util.Map.Entry;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import ch.bfh.fpe.Key;
import ch.bfh.fpe.messageSpace.IntegerMessageSpace;
import ch.bfh.fpe.messageSpace.OutsideMessageSpaceException;

/**
 * This class is an implementation of a tiny space FPE scheme based on the Knuth Shuffle.
 * Phillip Rogaway states in http://web.cs.ucdavis.edu/~rogaway/papers/synopsis.pdf (March 27, 2010)
 * that the Knuth shuffle is a possibility to build a tiny space FPE but gives no detail on a possible implementation.
 * 
 * The Knuth shuffle  algorithm is taken from http://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle#Modern_method
 * and is the key part of the class. An important variance is that one does not want the key to be truly random
 * but generated deterministically in order to reproduce the permutation for the decryption.
 * This deterministic random number is generated with AES based on a fixed encryption string. Key and tweak provides the
 * needed randomned for the permutation.
 * 
 * At first use, for every key and tweak a permutation table is created. A permutation table defines which plain text is
 * mapped to which cipher text and vice versa. Every subsequent encryption/decryption is then a fast table lookup.
 */
public class KnuthShuffleCipher extends IntegerCipher {
	
	//permutation table consists of two tables: one with the plaintext and one with ciphertext as key
	private HashMap<byte[],HashMap<byte[],HashMap<BigInteger,BigInteger>>> plaintextPermutationTable = new HashMap<>();
	private HashMap<byte[],HashMap<byte[],HashMap<BigInteger,BigInteger>>> ciphertextPermutationTable = new HashMap<>();
	
	//PBKDF parameters used if tweak has to be adjusted to 16 byte 
	private static final int PBKDF_ITERATION_COUNT = 10000;
	private static final byte[] PBKDF_SALT = new byte[]{21,3,-94,-128,0,127,13,43,-19,120,20,94,-62,101,14,91};;

	public KnuthShuffleCipher(IntegerMessageSpace messageSpace) {
		super(messageSpace);
	}
	
	public KnuthShuffleCipher(BigInteger maxValue) {
		this(new IntegerMessageSpace(maxValue));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public BigInteger encrypt(BigInteger plaintext, Key key, byte[] tweak) {
		return permuteValue(plaintext, key, tweak, plaintextPermutationTable);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public BigInteger decrypt(BigInteger ciphertext, Key key, byte[] tweak) {
		return permuteValue(ciphertext, key, tweak, ciphertextPermutationTable);
	}
	
	/**
	 * This method drops all permutation tables.
	 * A permutation table defines which plain text is mapped to which cipher text.
	 * Every key/tweak pair results in a unique permutation table which is generated
	 * at the first encryption/decryption and is stored for faster subsequent access.
	 */
	public void dropPermutationTables() {
		plaintextPermutationTable.clear();
		ciphertextPermutationTable.clear();
	}
	
	/**
	 * Performs encryption/decryption. I.e. lookup value in permutation table and return
	 * counterpart. When permutation table does not yet exists, it is generated.
	 * @param value plain-/ciphertext which is encrypted respectively decrypted 
	 * @param key secret used generate permutation
	 * @param tweak random bytes to prevent deterministic encryption
	 * @param permutationTable table used for mapping
	 * @return value after permutation
	 */
	private BigInteger permuteValue(BigInteger value, Key keyProvided, byte[] tweak, HashMap<byte[],HashMap<byte[],HashMap<BigInteger,BigInteger>>> permutationTable) {
		//validate input values
		if (value == null) throw new IllegalArgumentException("Input value must not be null");
		if (value.compareTo(BigInteger.ZERO)<0) throw new OutsideMessageSpaceException(value.toString());
		if (value.compareTo(getMessageSpace().getOrder())>=0) throw new OutsideMessageSpaceException(value.toString());
		if (tweak==null) throw new IllegalArgumentException("Tweak must not be null");
		if (keyProvided==null) throw new IllegalArgumentException("Key must not be null");
		byte[] key = keyProvided.getKey(16);
		if (tweak.length != 16) tweak = deriveTweak(tweak);
		
		//check if permutation available for tweak/key, if not generate
		if (!permutationTable.containsKey(key) ||
			!permutationTable.get(key).containsKey(tweak)) {
			knuthShuffle(key, tweak);
		}
		
		//lookup value in permutation table and return counterpart
		return permutationTable.get(key).get(tweak).get(value);
	}
	
	/**
	 * Generates the permutation table by means of the Knuth shuffle.
	 * The algorithm is taken from http://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle#Modern_method.
	 * To shuffle an array a of n elements (indices 0..n-1):
	 *   for i from n − 1 downto 1 do
	 *     j ← random integer with 0 ≤ j ≤ i
	 *     exchange a[j] and a[i]
	 * For the provided key/tweak pair a permutation table is created respectively
	 * one with the plain text and one with the cipher text as lookup key.
	 * The random integer j is deterministically derived with AES:
	 * 1) The 16 byte block "Hello World!! :D" is encrypted with key/tweak.
	 * 2) The output is calculated modulo (i+1) to cover the range 0 ≤ j ≤ i.
	 * @param key secret used generate permutation
	 * @param tweak random bytes to prevent deterministic encryption
	 */
	private void knuthShuffle(byte[] key, byte[] tweak) {
		//use AES to create deterministic random number
		BigInteger random = null;
		try {
			byte[] cipher = new byte[]{'H','e','l','l','o',' ','W','o','r','l','d','!','!',' ',':','D'};
			Cipher aesCipher = Cipher.getInstance("AES/CBC/NoPadding");
			aesCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),new IvParameterSpec(tweak));
			cipher = aesCipher.doFinal(cipher);
			random = new BigInteger(cipher);
		} catch (GeneralSecurityException e) {
			throw new RuntimeException("Invalid AES parameter specified. " + e.getMessage());
		}
		
		//initialize permutation table with i=i for i=n..0
		HashMap<BigInteger,BigInteger> plaintext = new HashMap<BigInteger,BigInteger>();
		for (int i=getMessageSpace().getMaxValue().intValue();i>=0;i--) {
			plaintext.put(BigInteger.valueOf(i), BigInteger.valueOf(i));
		}
		
		//do Knuth permutation
		for (int i=getMessageSpace().getMaxValue().intValue();i>=1;i--) {
			BigInteger currentPos = BigInteger.valueOf(i);				//i
			BigInteger newPos = random.mod(BigInteger.valueOf(i+1));	//j
			BigInteger tempExchange = plaintext.get(newPos);			//x = a[i] 
			plaintext.put(newPos, plaintext.get(currentPos));			//a[j] = a[i]
			plaintext.put(currentPos, tempExchange);					//a[i] = x
		}
		
		//copy plaintext- to ciphertext-permutation and use ciphertext as key instead
		HashMap<BigInteger,BigInteger> ciphertext = new HashMap<BigInteger,BigInteger>();
		for (Entry<BigInteger,BigInteger> entry : plaintext.entrySet()) {
			ciphertext.put(entry.getValue(), entry.getKey());
		}
		
		//add resulting permutation to permutation table
		if (plaintextPermutationTable.containsKey(key)) {
			plaintextPermutationTable.get(key).put(tweak, plaintext);
			ciphertextPermutationTable.get(key).put(tweak, ciphertext);
		}
		else {
			HashMap<byte[],HashMap<BigInteger,BigInteger>> tweakPlaintext = new HashMap<>();
			HashMap<byte[],HashMap<BigInteger,BigInteger>> tweakCiphertext = new HashMap<>();
			tweakPlaintext.put(tweak, plaintext);
			tweakCiphertext.put(tweak, ciphertext);
			plaintextPermutationTable.put(key, tweakPlaintext);
			ciphertextPermutationTable.put(key, tweakCiphertext);
		}
	}
	
	/**
	 * When tweak do not have a length of 16 byte,
	 * use PKCS#5 (PBKDF2 with SHA1-HMAC) derive it from provided tweak.
	 * @param length desired key length in bytes
	 */
	private byte[] deriveTweak(byte[] tweak) {
		
		try {
			SecretKeyFactory kf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			Charset latin1Charset = Charset.forName("ISO-8859-1"); 
			char[] pw = latin1Charset.decode(ByteBuffer.wrap(tweak)).array();         
		    KeySpec specs = new PBEKeySpec(pw, PBKDF_SALT, PBKDF_ITERATION_COUNT, 128);
		    SecretKey key = kf.generateSecret(specs);
		    return key.getEncoded();
		} catch (GeneralSecurityException e) {
			throw new RuntimeException("Key derivation failed. " + e.getMessage()); 
		}
	}
	
}
