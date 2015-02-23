package ch.bfh.fpe.test;

import static org.junit.Assert.*;
import java.math.BigInteger;
import java.util.Random;

import org.junit.Test;
import ch.bfh.fpe.intEnc.FFXIntegerCipher;
import ch.bfh.fpe.messageSpace.IntegerMessageSpace;
import ch.bfh.fpe.messageSpace.OutsideMessageSpaceException;

public class FFXIntegerCipherTest {
	
	
	byte[] key = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
	byte[] tweak = new byte[]{0,1,2,3,4,5,6};


	
	@Test
	public void testEncryptDecryptSimple() {
		IntegerMessageSpace iMs = new IntegerMessageSpace(BigInteger.valueOf(120000));
		FFXIntegerCipher ffx = new FFXIntegerCipher(iMs);

		BigInteger plaintext = BigInteger.valueOf(15320);
		BigInteger ciphertext = ffx.encrypt(plaintext, key,tweak);
		BigInteger decPlaintext = ffx.decrypt(ciphertext, key,tweak);			 
		assertEquals(plaintext, decPlaintext);
	}
	
	
	@Test(expected = IllegalArgumentException.class)
	public void testNotNull() {
		IntegerMessageSpace iMs = null;
		new FFXIntegerCipher(iMs);
	}


	@Test(expected = IllegalArgumentException.class)
	public void testEncryptNullPlaintext() {
		IntegerMessageSpace iMs = new IntegerMessageSpace(BigInteger.TEN);
		FFXIntegerCipher ffx = new FFXIntegerCipher(iMs);
		ffx.encrypt(null, key,tweak);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testDecryptNullCiphertext() {
		IntegerMessageSpace iMs = new IntegerMessageSpace(BigInteger.TEN);
		FFXIntegerCipher ffx = new FFXIntegerCipher(iMs);
		ffx.decrypt(null, key,tweak);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testEncrypttNullKey() {
		IntegerMessageSpace iMs = new IntegerMessageSpace(BigInteger.TEN);
		FFXIntegerCipher ffx = new FFXIntegerCipher(iMs);
		ffx.encrypt(BigInteger.valueOf(2), null,tweak);
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testEncrypttTweakNull() {
		IntegerMessageSpace iMs = new IntegerMessageSpace(BigInteger.TEN);
		FFXIntegerCipher ffx = new FFXIntegerCipher(iMs);
		ffx.encrypt(BigInteger.valueOf(2), key,null);
	}
	

	@Test
	public void testEncryptSmallTweak() {
		IntegerMessageSpace iMs = new IntegerMessageSpace(BigInteger.valueOf(61431411));
		FFXIntegerCipher ffx = new FFXIntegerCipher(iMs);
		byte[] tweak = new byte[1];
		new Random().nextBytes(tweak);
		BigInteger cipher1 = ffx.encrypt(BigInteger.valueOf(511),key,tweak);
		BigInteger cipher2 = ffx.encrypt(BigInteger.valueOf(511),key,tweak);
		assertEquals(cipher1, cipher2);
	}
	
	@Test
	public void testEncryptLongTweak() {
		IntegerMessageSpace iMs = new IntegerMessageSpace(BigInteger.valueOf(61431411));
		FFXIntegerCipher ffx = new FFXIntegerCipher(iMs);
		byte[] tweak = new byte[1000000]; // 1 megabyte
		new Random().nextBytes(tweak);

		BigInteger cipher1 = ffx.encrypt(BigInteger.valueOf(511),key,tweak);
		BigInteger cipher2 = ffx.encrypt(BigInteger.valueOf(511),key,tweak);
		assertEquals(cipher1, cipher2);
	}


	@Test(expected = IllegalArgumentException.class)
	public void testKeyNot128Bit() {
		IntegerMessageSpace iMs = new IntegerMessageSpace(BigInteger.TEN);
		FFXIntegerCipher ffx = new FFXIntegerCipher(iMs);
		ffx.encrypt(BigInteger.valueOf(5), new byte[9],tweak); // 72Bit Key
	}
	
	@Test(expected = OutsideMessageSpaceException.class)
	public void testEncryptPlaintextNotInMS() {
		IntegerMessageSpace iMs = new IntegerMessageSpace(BigInteger.TEN);
		FFXIntegerCipher ffx = new FFXIntegerCipher(iMs);
		ffx.encrypt(BigInteger.valueOf(11),key,tweak);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testEncryptNegative() {
		IntegerMessageSpace iMs = new IntegerMessageSpace(BigInteger.valueOf(50000));
		FFXIntegerCipher ffx = new FFXIntegerCipher(iMs);
		BigInteger plaintext = BigInteger.valueOf(-5613);
		ffx.encrypt(plaintext, key,tweak);
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testEncryptDecryptMSBiggerThan128Bit() {
		BigInteger bigNumber = BigInteger.valueOf(Long.MAX_VALUE).multiply(BigInteger.valueOf(Long.MAX_VALUE).multiply(BigInteger.valueOf(Long.MAX_VALUE)));
		IntegerMessageSpace iMs = new IntegerMessageSpace(bigNumber);
		new FFXIntegerCipher(iMs);

	}
	
	@Test
	public void testEncryptTwoTimesSameOutput() {
		IntegerMessageSpace iMs = new IntegerMessageSpace(BigInteger.TEN);
		FFXIntegerCipher ffx = new FFXIntegerCipher(iMs);

		BigInteger cipher1 = ffx.encrypt(BigInteger.valueOf(5),key,tweak);
		BigInteger cipher2 = ffx.encrypt(BigInteger.valueOf(5),key,tweak);
		assertEquals(cipher1, cipher2);
	}
	
	@Test
	public void testEncryptTwoTimesDifferentKeys() {
		IntegerMessageSpace iMs = new IntegerMessageSpace(BigInteger.valueOf(61431411));
		FFXIntegerCipher ffx = new FFXIntegerCipher(iMs);
		byte[] key2 = new byte[]{15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0};
		BigInteger cipher1 = ffx.encrypt(BigInteger.valueOf(511),key,tweak);
		BigInteger cipher2 = ffx.encrypt(BigInteger.valueOf(511),key2,tweak);
		assertFalse(cipher1 == cipher2);
	}
	
	@Test
	public void testEncryptTwoTimesDifferentTweak() {
		IntegerMessageSpace iMs = new IntegerMessageSpace(BigInteger.valueOf(61431411));
		FFXIntegerCipher ffx = new FFXIntegerCipher(iMs);
		byte[] tweak2 = new byte[]{15,14,13,12,11,10,9,8};
		BigInteger cipher1 = ffx.encrypt(BigInteger.valueOf(511),key,tweak);
		BigInteger cipher2 = ffx.encrypt(BigInteger.valueOf(511),key,tweak2);
		assertFalse(cipher1 == cipher2);
	}
	

	
	@Test
	public void testEncryptDecryptWrongKey() {
		IntegerMessageSpace iMs = new IntegerMessageSpace(BigInteger.TEN);
		FFXIntegerCipher ffx = new FFXIntegerCipher(iMs);
		BigInteger plaintext = BigInteger.valueOf(5);
		byte[] key2 = new byte[]{15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0};
		BigInteger ciphertext = ffx.encrypt(plaintext, key,tweak);
		BigInteger decPlaintext = ffx.decrypt(ciphertext, key2,tweak);
		assertFalse(plaintext == decPlaintext);
	}

	@Test
	public void testEncryptDecryptWrongCiphertextCorrectKey() {
		IntegerMessageSpace iMs = new IntegerMessageSpace(BigInteger.valueOf(500000));
		FFXIntegerCipher ffx = new FFXIntegerCipher(iMs);
		BigInteger plaintext = BigInteger.valueOf(8);
		BigInteger correctCipher = ffx.encrypt(plaintext, key,tweak);
		
		BigInteger wrongCipher = correctCipher.add(BigInteger.ONE);
		BigInteger decPlaintext = ffx.decrypt(wrongCipher, key,tweak);
		assertFalse(plaintext == decPlaintext);
	}


	@Test
	public void testEncryptDecryptSmallMS() {
		IntegerMessageSpace iMs = new IntegerMessageSpace(BigInteger.valueOf(1));
		FFXIntegerCipher ffx = new FFXIntegerCipher(iMs);

		BigInteger plaintext = BigInteger.valueOf(0);
		BigInteger ciphertext = ffx.encrypt(plaintext, key,tweak);
		BigInteger decPlaintext = ffx.decrypt(ciphertext, key,tweak);			 
		assertEquals(plaintext, decPlaintext);
	}
	
	@Test
	public void testEncryptDecryptBigMS() {
		BigInteger bigNumber = BigInteger.valueOf(Long.MAX_VALUE);
		bigNumber = bigNumber.multiply(BigInteger.valueOf(Long.MAX_VALUE));
		IntegerMessageSpace iMs = new IntegerMessageSpace(bigNumber);
		FFXIntegerCipher ffx = new FFXIntegerCipher(iMs);

		BigInteger plaintext = bigNumber;
		BigInteger ciphertext = ffx.encrypt(plaintext, key,tweak);
		BigInteger decPlaintext = ffx.decrypt(ciphertext, key,tweak);			 
		assertEquals(plaintext, decPlaintext);
	}

	/*
	@Test
	public void testEncryptDecryptWholeMS() {
		int msLimit =  500000;
		IntegerMessageSpace iMs = new IntegerMessageSpace(BigInteger.valueOf(msLimit));
		FFXIntegerCipher ffx = new FFXIntegerCipher(iMs);
		BigInteger plaintext, ciphertext,plaintext2;
	
		for (int i=0; i<msLimit;i++){
		 plaintext = BigInteger.valueOf(i);
		 ciphertext = ffx.encrypt(plaintext, key,tweak);
		 plaintext2 = ffx.decrypt(ciphertext, key,tweak);
		 System.out.println(plaintext + " >>enc>> " + ciphertext+ " >>dec>> " + plaintext2);	 
		}	
	}
	*/
}
