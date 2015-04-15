package ch.bfh.fpe;

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
 * 
 */
public class Key {
	
	private static final int PBKDF_ITERATION_COUNT = 10000;
	private static final byte[] PBKDF_SALT = new byte[]{39,3,-94,-128,0,127,13,43,-19,120,20,94,-62,101,14,91};;
	
	private final HashMap<Integer,byte[]> keys = new HashMap<>();
	private final int providedKeyLength;
	
	public Key(byte[] key) {
		if (key==null) throw new IllegalArgumentException("Key must not be null");
		providedKeyLength = key.length;
		keys.put(providedKeyLength, key);
	}
	
	public static boolean isKeyLengthAllowed(int keyLength) {
		try {
			return (keyLength<=Cipher.getMaxAllowedKeyLength("AES"));
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.getMessage());
		}
	}
	
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
			Charset latin1Charset = Charset.forName("ISO-8859-1"); 
			char[] pw = latin1Charset.decode(ByteBuffer.wrap(keys.get(providedKeyLength))).array();         
		    KeySpec specs = new PBEKeySpec(pw, PBKDF_SALT, PBKDF_ITERATION_COUNT, length*8);
		    SecretKey key = kf.generateSecret(specs);
		    keys.put(length, key.getEncoded());
		} catch (GeneralSecurityException e) {
			throw new RuntimeException("Key derivation failed. " + e.getMessage()); 
		}
	}

}
