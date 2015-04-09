package ch.bfh.fpe.intEnc;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map.Entry;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import ch.bfh.fpe.messageSpace.IntegerMessageSpace;
import ch.bfh.fpe.messageSpace.OutsideMessageSpaceException;

public class KnuthShuffleCipher extends IntegerCipher {
	
	private HashMap<byte[],HashMap<byte[],HashMap<BigInteger,BigInteger>>> plaintextPermutationTable = new HashMap<>();
	private HashMap<byte[],HashMap<byte[],HashMap<BigInteger,BigInteger>>> ciphertextPermutationTable = new HashMap<>();

	public KnuthShuffleCipher(IntegerMessageSpace messageSpace) {
		super(messageSpace);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public BigInteger encrypt(BigInteger plaintext, byte[] key, byte[] tweak) {
		return permuteValue(plaintext, key, tweak, plaintextPermutationTable);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public BigInteger decrypt(BigInteger ciphertext, byte[] key, byte[] tweak) {
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
	private BigInteger permuteValue(BigInteger value, byte[] key, byte[] tweak, HashMap<byte[],HashMap<byte[],HashMap<BigInteger,BigInteger>>> permutationTable) {
		//Validate input values
		if (value == null) throw new IllegalArgumentException("Input value must not be null");
		if (value.compareTo(BigInteger.ZERO)<0) throw new OutsideMessageSpaceException(value.toString());
		if (value.compareTo(getMessageSpace().getOrder())>=0) throw new OutsideMessageSpaceException(value.toString());
		if (tweak==null || tweak.length != 16) throw new IllegalArgumentException("Tweak must be 128 Bit long");
		if (key==null || key.length != 16) throw new IllegalArgumentException("Key must be 128 Bit long");
		
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
	
}
