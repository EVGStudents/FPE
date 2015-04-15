package ch.bfh.fpe.test;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.Random;

import org.junit.Before;
import org.junit.Test;

import ch.bfh.fpe.Key;
import ch.bfh.fpe.intEnc.EME2IntegerCipher;
import ch.bfh.fpe.messageSpace.IntegerMessageSpace;
import ch.bfh.fpe.messageSpace.OutsideMessageSpaceException;

public class EME2IntegerCipherTest {
	
	Key key = new Key(new byte[48]);
	byte[] tweak = new byte[37];
	byte[] plaintext = new byte[43];
	byte[] msMax = new byte[500];
	IntegerMessageSpace intMS;
			
	
	@Before
    public void initObjects() {
		//Set the highest byte in the array, so all bytes of the array are going into the BigInteger
		tweak[0] =  (byte)127;
		plaintext[0] =  (byte)127;
		msMax[0] =  (byte)127;
		intMS = new IntegerMessageSpace(new BigInteger(msMax));
    }
	
	@Test
	public void testEncryptDecryptSimple() {
		EME2IntegerCipher eme2 = new EME2IntegerCipher(intMS);

		BigInteger plaintext2 = BigInteger.valueOf(511);
		BigInteger ciphertext = eme2.encrypt(plaintext2, key,tweak);
		BigInteger decPlaintext = eme2.decrypt(ciphertext, key,tweak);			 
		assertEquals(plaintext2, decPlaintext);
	}
	
	
	@Test(expected = IllegalArgumentException.class)
	public void testNotNull() {
		IntegerMessageSpace intMS = null;
		new EME2IntegerCipher(intMS);
	}


	@Test(expected = IllegalArgumentException.class)
	public void testEncryptNullPlaintext() {
		EME2IntegerCipher eme2 = new EME2IntegerCipher(intMS);
		eme2.encrypt(null, key,tweak);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testDecryptNullCiphertext() {
		EME2IntegerCipher eme2 = new EME2IntegerCipher(intMS);
		eme2.decrypt(null, key,tweak);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testEncrypttNullKey() {
		EME2IntegerCipher eme2 = new EME2IntegerCipher(intMS);
		eme2.encrypt(new BigInteger(plaintext), null,tweak);
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testEncryptTweakNull() {
		EME2IntegerCipher eme2 = new EME2IntegerCipher(intMS);
		eme2.encrypt(new BigInteger(plaintext), key,null);
	}

	@Test
	public void testEncryptZeroTweak() {
		EME2IntegerCipher eme2 = new EME2IntegerCipher(intMS);
		byte[] tweak = new byte[0];
		new Random().nextBytes(tweak);
		BigInteger cipher1 = eme2.encrypt(BigInteger.valueOf(511),key,tweak);
		BigInteger cipher2 = eme2.encrypt(BigInteger.valueOf(511),key,tweak);
		assertEquals(cipher1, cipher2);
	}
	
	@Test
	public void testEncryptLongTweak() {
		EME2IntegerCipher eme2 = new EME2IntegerCipher(intMS);
		byte[] tweak = new byte[1000000]; // 1 megabyte
		new Random().nextBytes(tweak);

		BigInteger cipher1 = eme2.encrypt(new BigInteger(plaintext),key,tweak);
		BigInteger cipher2 = eme2.encrypt(new BigInteger(plaintext),key,tweak);
		assertEquals(cipher1, cipher2);
	}

	@Test
	public void testKeyNot48or64Byte() {
		EME2IntegerCipher eme2 = new EME2IntegerCipher(intMS);
		Key key = new Key(new byte[9]); // 72Bit Key
		BigInteger plaintext2 = BigInteger.valueOf(511);
		BigInteger ciphertext = eme2.encrypt(plaintext2, key,tweak);
		BigInteger decPlaintext = eme2.decrypt(ciphertext, key,tweak);			 
		assertEquals(plaintext2, decPlaintext);
	}
	
	@Test(expected = OutsideMessageSpaceException.class)
	public void testEncryptPlaintextNotInMS() {
		EME2IntegerCipher eme2 = new EME2IntegerCipher(intMS);
		byte[] plaintext = new byte[501]; //MSMax = 500 Bytes
		plaintext[0] =  (byte)127;
		eme2.encrypt(new BigInteger(plaintext),key,tweak);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testEncryptNegative() {
		EME2IntegerCipher eme2 = new EME2IntegerCipher(intMS);
		BigInteger plaintext = BigInteger.valueOf(-5613);
		eme2.encrypt(plaintext, key,tweak);
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testEncryptDecryptMSSmallerThan128Bit() {
		IntegerMessageSpace iMs = new IntegerMessageSpace(BigInteger.valueOf(123478));
		new EME2IntegerCipher(iMs);
	}
	
	@Test
	public void testEncryptTwoTimesSameOutput() {
		EME2IntegerCipher eme2 = new EME2IntegerCipher(intMS);
		BigInteger cipher1 = eme2.encrypt(new BigInteger(plaintext),key,tweak);
		BigInteger cipher2 = eme2.encrypt(new BigInteger(plaintext),key,tweak);
		assertEquals(cipher1, cipher2);
	}
	
	@Test
	public void testEncryptTwoTimesDifferentKeys() {
		EME2IntegerCipher eme2 = new EME2IntegerCipher(intMS);
		byte[] key2Array = new byte[48];
		key2Array[0] = (byte)66;
		Key key2 = new Key(key2Array);
		BigInteger cipher1 = eme2.encrypt(new BigInteger(plaintext),key,tweak);
		BigInteger cipher2 = eme2.encrypt(new BigInteger(plaintext),key2,tweak);
		assertFalse(cipher1 == cipher2);
	}
	
	@Test
	public void testEncryptTwoTimesDifferentTweak() {
		EME2IntegerCipher eme2 = new EME2IntegerCipher(intMS);
		byte[] tweak2 = new byte[]{15,14,13,12,11,10,9,8};
		BigInteger cipher1 = eme2.encrypt(new BigInteger(plaintext),key,tweak);
		BigInteger cipher2 = eme2.encrypt(new BigInteger(plaintext),key,tweak2);
		assertFalse(cipher1 == cipher2);
	}
	

	
	@Test
	public void testEncryptDecryptWrongKey() {
		EME2IntegerCipher eme2 = new EME2IntegerCipher(intMS);
		byte[] key2Array = new byte[48];
		key2Array[0] = (byte)66;
		Key key2 = new Key(key2Array);
		BigInteger ciphertext = eme2.encrypt(new BigInteger(plaintext), key,tweak);
		BigInteger decPlaintext = eme2.decrypt(ciphertext, key2,tweak);
		assertFalse(new BigInteger(plaintext) == decPlaintext);
	}

	@Test
	public void testEncryptDecryptWrongCiphertextCorrectKey() {
		EME2IntegerCipher eme2 = new EME2IntegerCipher(intMS);
		BigInteger correctCipher = eme2.encrypt(new BigInteger(plaintext), key,tweak);
		
		BigInteger wrongCipher = correctCipher.add(BigInteger.ONE);
		BigInteger decPlaintext = eme2.decrypt(wrongCipher, key,tweak);
		assertFalse(new BigInteger(plaintext) == decPlaintext);
	}


	@Test
	public void testEncryptDecryptSmallMS() {
		byte[] msMaxSmall = new byte[17];
		msMaxSmall[0]=127;
		IntegerMessageSpace iMs = new IntegerMessageSpace(new BigInteger(msMaxSmall));
		EME2IntegerCipher eme2 = new EME2IntegerCipher(iMs);

		BigInteger plaintext = BigInteger.valueOf(0);
		BigInteger ciphertext = eme2.encrypt(plaintext, key,tweak);
		BigInteger decPlaintext = eme2.decrypt(ciphertext, key,tweak);			 
		assertEquals(plaintext, decPlaintext);
	}
	
	@Test
	public void testEncryptDecryptBigMS() {
		byte[] msMaxBig = new byte[10000]; //10 KiloByte
		msMaxBig[0] = (byte)127;
		IntegerMessageSpace iMs = new IntegerMessageSpace(new BigInteger(msMaxBig));
		EME2IntegerCipher eme2 = new EME2IntegerCipher(iMs);

		BigInteger ciphertext = eme2.encrypt(new BigInteger(plaintext), key,tweak);
		BigInteger decPlaintext = eme2.decrypt(ciphertext, key,tweak);			 
		assertEquals(new BigInteger(plaintext), decPlaintext);
	}	
}