package ch.bfh.fpelib.intEnc;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import ch.bfh.fpelib.Key;
import ch.bfh.fpelib.messageSpace.IntegerMessageSpace;
import ch.bfh.fpelib.messageSpace.OutsideMessageSpaceException;

/**
 * This class is an implementation of EME2 formerly known as EME*. Reference: "EME*: extending EME to handle arbitrary-length messages with associated data": <a href="http://eprint.iacr.org/2004/125.pdf">http://eprint.iacr.org/2004/125.pdf</a><br><br>
 * EME2 is a Format Preserving Encryption (FPE) Cipher for arbitrary long numbers with a minimum of 128 bits.<br>
 * The EME2IntegerCipher encrypts a given input number from a specified range in such way, that the output value is also a number from the same range.
 * This range is defined by an IntegerMessageSpace delivered in the constructor.<br/><br/>
 *
 * Following a simple example how to use a EME2Cipher. The goal in this example is to encrypt the number 12345 into another number in the range given by the IntegerMessageSpace:<br/><br/>
 * 
 * <code>
 * 		IntegerMessageSpace intMS = new IntegerMessageSpace(messageSpace.getOrder());//messageSpace contains more than 2^128 values<br> 
 *		EME2IntegerCipher eme2 = new EME2IntegerCipher(intMS);<br><br>
 *
 *		BigInteger plaintext = BigInteger.valueOf(12345); <br>
 *		BigInteger ciphertext = eme2.encrypt(plaintext,key,tweak); //possible result: 50376352154789653152</code><br/><br/>
 *
 * The ciphertext could now be for example 50376352154789653152. 
 * By putting this number into the decrypt-method of the EME2IntegerCipher, with the same key and the same tweak, you will receive the plaintext, in this case 12345, back.<br/><br/>
 * 
 * <code>BigInteger decPlaintext = eme2.decrypt(ciphertext, key,tweak); //result: 12345</code><br/><br/>
 * 
 * The keyLength parameter in the constructor specifies if you want to use AES-128 or AES-256. Be aware that there is a restriction on JDKs for AES-256 and it has first to be unlocked in the policy rules.
 * The key has to be the same for decrypting a value as he was for encrypting it.<br>
 * The tweak is a value similar to an initialization vector (iv) or a salt on hashing in the sense that he prevents a deterministic encryption. 
 * A tweak can be arbitrary long, even zero if no associated data is available, and has to be the same for decrypting a value as he was for encrypting it.<br/><br/>
 * 
 */
public class EME2IntegerCipher extends IntegerCipher {
	
	private static final int MIN_BIT_LENGTH = 128;
	private int keyLength = 0; //0=not explicit specified/use default, 128/256=128 respectively 256 bit

	
	/**
	 * Constructs a EME2IntegerCipher with the maximum value determined in the IntegerMessageSpace.<br>
	 * @param messageSpace IntegerMessageSpace to determine the number range of the input respectively output of the encryption/decryption
	 * @throws IllegalArgumentException if the maximum value in the IntegerMessageSpace is smaller than representable with 128 bits
	 */
	public EME2IntegerCipher(IntegerMessageSpace messageSpace) {
		super(messageSpace);
		if (messageSpace.getOrder().bitLength() < MIN_BIT_LENGTH) throw new IllegalArgumentException("Message space must be bigger than 128 bits");
	}
	
	/**
	 * Constructs a EME2IntegerCipher with the maximum value determined by the parameter.<br>
	 * @param maxValue Value to determine the number range of the input respectively output of the encryption/decryption
	 * @throws IllegalArgumentException if the maximum value in the IntegerMessageSpace is smaller than representable with 128 bits
	 */
	public EME2IntegerCipher(BigInteger maxValue) {
		this(new IntegerMessageSpace(maxValue));
	}
	
	/**
	 * Constructs a EME2IntegerCipher with the maximum value determined in the IntegerMessageSpace.<br>
	 * @param messageSpace IntegerMessageSpace to determine the number range of the input respectively output of the encryption/decryption
	 * @param keyLength set explicit key length to 128 or 256 bit. Default is 128 bit to support interoperability because JCE without unlimited strength policy files is restricted to this size.
	 * @throws IllegalArgumentException if the maximum value in the IntegerMessageSpace is smaller than representable with 128 bits
	 */
	public EME2IntegerCipher(IntegerMessageSpace messageSpace, int keyLength) {
		super(messageSpace);
		if (messageSpace.getOrder().bitLength() < MIN_BIT_LENGTH) throw new IllegalArgumentException("Message space must be bigger than 128 bits");
		if (keyLength != 128 && keyLength != 256) throw new IllegalArgumentException("Illegal key length. Must be 128 or 256 bit.");
		this.keyLength = keyLength;
	}
	
	/**
	 * Constructs a EME2IntegerCipher with the maximum value determined by the parameter.<br>
	 * @param maxValue Value to determine the number range of the input respectively output of the encryption/decryption
	 * @param keyLength set explicit key length to 128 or 256 bit. Default is 128 bit to support interoperability because JCE without unlimited strength policy files is restricted to this size.
	 * @throws IllegalArgumentException if the maximum value in the IntegerMessageSpace is smaller than representable with 128 bits
	 */
	public EME2IntegerCipher(BigInteger maxValue, int keyLength) {
		this(new IntegerMessageSpace(maxValue), keyLength);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public BigInteger encrypt(BigInteger plaintext, Key key, byte[] tweak) {
		return cipher(plaintext, key, tweak, true);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public BigInteger decrypt(BigInteger ciphertext, Key key, byte[] tweak) {
		return cipher(ciphertext, key, tweak, false);
	}
	
	
	/**
	 * First method called from encrypt/decrypt methods. Checks input values for invalidities and throws an Exception if an argument is not valid.<br>
	 * Encryption/Decryption takes place in a do-while-loop to be sure that the output is a value inside the given message space.<br> 
	 * If not, the encrypted/decrypted value is encrypted/decrypted once again and so on. This procedure is called "Cycle Walking".
	 * @param plaintext plaintext of arbtriray length. Will be padded to length of message space which is in minimum 16 bytes
	 * @param key encryption key
	 * @param tweak value of the associated data of arbitrary byte length (zero or more bytes)
	 * @param encryption true if this method is called for an encryption, false if for a decryption
	 * @throws IllegalArgumentException if input is null or negative, key is not 48 or 64 bytes or tweak is null
	 * @throws OutsideMessageSpaceException if plaintext/ciphertext is outside the message space
	 * @return returns a ciphertext or a plaintext, depending on encryption or decryption
	 */
	private BigInteger cipher(BigInteger input, Key keyProvided, byte[] tweak, boolean encryption){
		
		BigInteger maxMsValue = getMessageSpace().getMaxValue();
		if (input==null) throw new IllegalArgumentException("Input value must not be null.");
		if (input.compareTo(BigInteger.ZERO)<0) throw new IllegalArgumentException("Input value must not be negative");
		if (input.compareTo(maxMsValue)>0) throw new OutsideMessageSpaceException(input.toString());
		if (keyProvided==null) throw new IllegalArgumentException("Key must not be a null object");
		if (tweak==null) throw new IllegalArgumentException("Tweak must not be a null object");
		
		
		//Use 256-bit key when explicit specified. Per default use 128-bit key to provide interoperability because on most systems this is the highest allowed key length.
		//Key in JCE without unlimited strength policy files is restricted to this size due to judical reasons.
		byte[] key;
		if (keyLength==256) key = keyProvided.getKey(64); 
		else key = keyProvided.getKey(48);

		try {
			do{
				input = cipherFunction(input,key, tweak, encryption);
			} while (input.compareTo(maxMsValue)>0) ; //Cycle Walking: While new value is outside of message space, encipher again
		} catch (GeneralSecurityException e) {
			throw new IllegalArgumentException("A security exception occured: " + e.getMessage());
		}
		return input;
	}
	
	
	/**
	 * The EME2 cipher function is based on an encrypt-mix-encrypt approach. First encrypt the input data, than create masks with the encrypted plaintext and the tweak to xor the data ("mixing"). At the end 
	 * encrypt the whole data again. If the input is not a multiple of 16 bytes, a padding is applied during the function.
	 * @param input plaintext or ciphertext of arbtriray length. Will be padded to length of message space which is in minimum 16 bytes
	 * @param key encryption key
	 * @param tweak value of the associated data, of arbitrary byte length (zero or more bytes)
	 * @param encryption true if this method is called for an encryption, false if for a decryption
	 * @return a ciphertext or a plaintext, depending on encryption or decryption
	 * @throws GeneralSecurityException wrong security parameter in AES. Should not happen because we control/check all parameters.
	 */
	private BigInteger cipherFunction(BigInteger input, byte[] key, byte[] tweak, boolean encryption) throws GeneralSecurityException {
			
		// Split input key into three subkeys
		byte[] key2 = Arrays.copyOfRange(key, 0, 16);  //key2: 16 bytes for xor of the plaintext
		byte[] key3 = Arrays.copyOfRange(key, 16, 32); //key3: 16 bytes for xor of the tweak
		byte[] aesKey = Arrays.copyOfRange(key, 32, key.length); //last 16 or 32 bytes for the actual AES encryption
		
		
		// Initialize AES with ECB-mode. For the tweak-part, only the encrypt mode is used, independent of enc/dec of input 
		Cipher aesCipher = Cipher.getInstance("AES/ECB/NoPadding");
		aesCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"));
			
		
		
		/* Process the arbitrary long input tweak to get a 16-byte block tweak */
		byte[] tweakInBlockSize = new byte[16];
		
		if(tweak.length==0) tweakInBlockSize = aesCipher.doFinal(key3); //If tweak is zero, encrypted key3 is taken as tweak
		else{
			ArrayList<byte[]> tweakArray = new ArrayList<byte[]>();
			ArrayList<byte[]> encTweakArray = new ArrayList<byte[]>();
			
			//Copy each 16 byte blocks of input tweak as element in tweakArray
			for (int m=0; m < tweak.length-15;m+=16){
				tweakArray.add(Arrays.copyOfRange(tweak, m, m+16)); 
			}
			//If the last block is not 16 bytes, copy the rest in tweakArray and pad it to 16 bytes
			if(tweak.length%16 != 0){
				tweakArray.add(Arrays.copyOfRange(tweak, tweak.length-(16-((-tweak.length%16)+16)%16), tweak.length)); 
				tweakArray.set(tweakArray.size()-1, padToBlocksize(tweakArray.get(tweakArray.size()-1)));
			}
			key3 = multByAlpha(key3); //Recalculate key3
			
			// xor each tweak block with key3, encrypt it and xor again with key3
			for(int i=0; i<tweakArray.size();i++){
				encTweakArray.add(xor(aesCipher.doFinal(xor(tweakArray.get(i),key3)),key3));
				key3 = multByAlpha(key3);
			}

			// xor each encrypted tweak block with the next one to get the final block at the end
			for(byte[] encTweakBlock : encTweakArray) tweakInBlockSize = xor(tweakInBlockSize,encTweakBlock);
		}
				
		
		
		/* First encryption/decryption pass	*/
		
		if (encryption==false) aesCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES")); //if decryption switch AES to decrypt mode
				
		byte[] inputArray = input.toByteArray(); //Convert input BigInteger to a ByteArray
		
		// If first byte of the input is zero, it was used by BigInteger to represent a positive value and has to be removed
		if (inputArray[0] == 0) inputArray = Arrays.copyOfRange(inputArray, 1, inputArray.length);
		
		// Copy input in a new array with the length of message space
		byte[] plaintext = new byte[getMessageSpace().getOrder().toByteArray().length]; 
		System.arraycopy(inputArray, 0, plaintext, plaintext.length-inputArray.length, inputArray.length);
		
		//if plaintext is not a multiple of 16 bytes, last block is incomplete
		boolean lastPlainBlockIncomplete = false;	
		if(plaintext.length%16 != 0) lastPlainBlockIncomplete=true;	
			
		// Copy each 16 byte blocks of input plaintext as element in plainArray
		ArrayList<byte[]> plainArray = new ArrayList<byte[]>();
		for (int m=0; m < plaintext.length-15;m+=16){
			plainArray.add(Arrays.copyOfRange(plaintext, m, m+16));
		}
		// If the last block is not 16 bytes, copy the rest in plainArray
		if(lastPlainBlockIncomplete)plainArray.add(Arrays.copyOfRange(plaintext, (plaintext.length-(16-((-plaintext.length%16)+16)%16)), plaintext.length));
		
		int indexOfLastBlock = plainArray.size()-1;
		byte[] copyOfKey2 = key2.clone(); // Save a copy of key2
		//byte[] copyOfKey2 = new byte[16];
		//System.arraycopy(key2, 0, copyOfKey2, 0, key2.length); 
		
		// xor each plaintext block (except the last one) with key2 and encrypt it
		ArrayList<byte[]> encPlainArray = new ArrayList<byte[]>();
		for(int i=0; i<indexOfLastBlock;i++){
			encPlainArray.add(aesCipher.doFinal(xor(key2,plainArray.get(i))));
			key2 = multByAlpha(key2);
		}
		// if the last block does not have 16 bytes, pad it to blocksize (without an encryption)
		if(lastPlainBlockIncomplete) encPlainArray.add(padToBlocksize(plainArray.get(indexOfLastBlock)));
		// else encrypt it like the other ones before
		else encPlainArray.add(aesCipher.doFinal(xor(key2,plainArray.get(indexOfLastBlock))));

		
	
		/* Intermediate mixing part */
		
		//the denotations mp,m,m1,mc,mc1,mm of the masks are adopted from the definition of EME2
		byte[] mp, m, m1, mc, mc1, mm = null;
		
		// xor each encrypted plaintext block with the next one and the tweak and store it in mp
		mp = tweakInBlockSize.clone();
		for (byte[] encPlainBlock : encPlainArray) mp = xor(mp,encPlainBlock);
		
		// create the masks mm, mc, m m1
		if(lastPlainBlockIncomplete){
			mm = aesCipher.doFinal(mp);
			mc = aesCipher.doFinal(mm);	
			mc1 = mc.clone();
		} else {
			mc = aesCipher.doFinal(mp);
			mc1 = mc.clone();
			
		}
		m = m1 = xor(mp,mc);
		m1 = m.clone();

		ArrayList<byte[]> cipherArray = new ArrayList<byte[]>();
		cipherArray.add(new byte[16]); //placeholder for first element, is replaced later
		
		// xor each plaintext block with mask m and store in new array
		for (int i=1; i<indexOfLastBlock;i++){
			if ((i-1)%128 > 0) { 
				m = multByAlpha(m);
				cipherArray.add(xor(encPlainArray.get(i),m));
			}else{ //recalculate mask m after every 2048 bytes
				mp = xor(encPlainArray.get(i),m1);
				mc = aesCipher.doFinal(mp);
				m = xor(mp,mc);
				cipherArray.add(xor(mc,m1));	
				}
			}
		
		// treat the last block
		byte[] lastCipherBlock = null;
		if(lastPlainBlockIncomplete){
			byte[] truncatedMM = Arrays.copyOfRange(mm, 0, plainArray.get(indexOfLastBlock).length);
			lastCipherBlock = xor(plainArray.get(indexOfLastBlock),truncatedMM);
			cipherArray.add(padToBlocksize(lastCipherBlock));	
		} else if((indexOfLastBlock-1)%128 > 0) {
			m = multByAlpha(m);
			cipherArray.add(xor(encPlainArray.get(indexOfLastBlock),m));
		} else {
			cipherArray.add(xor(aesCipher.doFinal(xor(m1,encPlainArray.get(indexOfLastBlock))),m1));
		}
		
		// xor each encrypted block with the next one and set it as first element of the ciphertext array
		byte[] firstElementTemp = xor(mc1,tweakInBlockSize);
		for (byte[] cipherBlock : cipherArray){
			firstElementTemp = xor(firstElementTemp,cipherBlock);
		}
		cipherArray.set(0,firstElementTemp);
		
		
		
		/* Second encryption/decryption pass */
		
		key2 = copyOfKey2.clone(); // Restore key2 with the original value
		ArrayList<byte[]> encCipherArray = new ArrayList<byte[]>();
		
		// encrypt each block and xor it with key2
		for(int i=0; i<indexOfLastBlock; i++){
			encCipherArray.add(xor(aesCipher.doFinal(cipherArray.get(i)),key2));
			key2 = multByAlpha(key2);
		}
		
		// if the last block does not have 16 bytes add the already calculated last block
		if(lastPlainBlockIncomplete) encCipherArray.add(lastCipherBlock);
		else encCipherArray.add(xor(aesCipher.doFinal(cipherArray.get(indexOfLastBlock)),key2));
		
		// convert array list in a byte array
		byte[] output = new byte[plaintext.length];
		int i = 0;
		for (byte[] encCipherBlock : encCipherArray){
			for (byte byteValue : encCipherBlock){
				output[i] = byteValue;
				i++;
			}
		}
		
		return new BigInteger(1,output); // returns a positive BigInteger
	}

	
	/**
	 * Pads a byte array with less than 16 bytes to 16 bytes with the first bit set (according to definition of EME2). 
	 * If input is already 16 bytes or bigger it will returned immediately.
	 * @param input byte array smaller than 16 bytes
	 * @return 16 bytes long byte array
	 */
	private static byte[] padToBlocksize(byte[] input){
		if(input.length>=16) return input;
		byte[] output = new byte[input.length + (((-input.length%16)+16)%16)];
		System.arraycopy(input, 0, output, 0, input.length);
		output[input.length] = (byte) 128; //Set the first bit in the first padded block
		return output;
	}
	
	
	/**
	 * Multiplies a 16-byte input value by a primitive element α in the field GF(2^128) (Galois Field Multiplication)
	 * @param input ByteArray to be multiplied
	 * @return Multiplied ByteArray
	 */
	private static byte[] multByAlpha(byte[] input){
		if (input.length != 16) throw new IllegalArgumentException("Input must be 16 bytes");
		byte[] output = new byte[16];
		
		for(int i=0;i<16;i++){
			output[i] = (byte) ((2 * input[i]) % 256);
			if(i>0 && input[i-1] > 127) output[i] = (byte) (output[i] + 1);
		}
		if (input[15] > 127) output[0] = (byte) (output[0] ^ 0x87);
		return output;	
	}
	
	
	/**
	 * Calculates the XOR value for two given ByteArrays with the same length.
	 * @param array1 First ByteArray
	 * @param array2 Second ByteArray
	 * @return a ByteArray with the XOR value
	 * @throws IllegalArgumentException if arrays don't have the same length
	 */
	private static byte[] xor(byte[] array1, byte[] array2)
	{
		if (array1.length != array2.length) throw new IllegalArgumentException("lenght of array1 (" + array1.length + ") must be equal to the length array2 (" + array2.length + ")");
		byte[] xorArray = new byte[array1.length];
		int i = 0;
		for (byte b : array1){
			xorArray[i] = (byte) (b ^ array2[i++]);
		}
		return xorArray;
	}
}
