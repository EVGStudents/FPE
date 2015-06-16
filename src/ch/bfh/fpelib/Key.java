package ch.bfh.fpelib;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * This class is used in the encryption and decryption method of a FPE cipher
 * and is contains the key used for encyption/decryption.
 * Varying FPE ciphers use different key lengths. This class provides the functionality
 * to derive a key of the required length with the use of use PKCS#5 (PBKDF2 with SHA1-HMAC).
 */
public class Key {
	
	//fixed PBKDF parameters used to derive key of required length
	private static final int PBKDF_ITERATION_COUNT = 10000;
	private static final byte[] PBKDF_SALT = new byte[]{39,3,-94,-128,0,127,13,43,-19,120,20,94,-62,101,14,91};
	
	private final HashMap<Integer,byte[]> keys = new HashMap<Integer,byte[]>(); //buffer keys for fast subsequent access
	private final int providedKeyLength; //length of the base key
	
	/**
	 * Constructs a new key class by providing a base key.
	 * @param key base key
	 */
	public Key(byte[] key) {
		if (key==null) throw new IllegalArgumentException("Key must not be null");
		providedKeyLength = key.length;
		keys.put(providedKeyLength, key);
	}
	
	/**
	 * Checks if the AES key length is allowed on the current system. On most systems 128 bit is the highest allowed key length.
	 * Key in JCE without unlimited strength policy files is restricted to this size due to judical reasons.
	 * @param keyLength Length to check 
	 * @return true if provided key length is allowed, otherwise false
	 */
	public static boolean isKeyLengthAllowed(int keyLength) {
		try {
			return (keyLength<=Cipher.getMaxAllowedKeyLength("AES"));
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
	/**
	 * Returns a key with the specified length.
	 * If the length is equal to the one of the provided base key, that is returned unaltered.
	 * If not, a new key is derived from the provided base key. 
	 * @param length Length of the key in bytes
	 * @return key with the specified length
	 */
	public byte[] getKey(int length) {
		if (!keys.containsKey(length)) deriveKey(length);
		return keys.get(length);
	}
	
	/**
	 * When key is too long or too short, use PKCS#5 (PBKDF2 with SHA1-HMAC)
	 * to generate a key of appropriate length.
	 * @param length desired key length in bytes
	 */
	private void deriveKey(int length) {
		
		try {
			SecretKeyFactory kf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			Charset charset = Charset.forName("UTF-8"); 
			char[] pw = charset.decode(ByteBuffer.wrap(keys.get(providedKeyLength))).array();         
		    KeySpec specs = new PBEKeySpec(pw, PBKDF_SALT, PBKDF_ITERATION_COUNT, length*8);
		    SecretKey key = kf.generateSecret(specs);
		    keys.put(length, key.getEncoded());
		} catch (GeneralSecurityException e) {
			throw new RuntimeException("Key derivation failed. " + e.getMessage()); 
		}
	}

}
