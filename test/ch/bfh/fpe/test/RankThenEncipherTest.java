package ch.bfh.fpe.test;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.ArrayList;

import org.junit.Test;

import ch.bfh.fpe.Key;
import ch.bfh.fpe.RankThenEncipher;
import ch.bfh.fpe.intEnc.FFXIntegerCipher;
import ch.bfh.fpe.intEnc.IntegerCipher;
import ch.bfh.fpe.messageSpace.EnumerationMessageSpace;
import ch.bfh.fpe.messageSpace.IntegerMessageSpace;
import ch.bfh.fpe.messageSpace.IntegerRangeMessageSpace;
import ch.bfh.fpe.messageSpace.OutsideMessageSpaceException;


public class RankThenEncipherTest {
	Key key = new Key(new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15});
	byte[] tweak = new byte[]{0,1,2,3,4,5,6,7};
	

	@Test(expected = IllegalArgumentException.class)
	public void testNotNull() {
		IntegerRangeMessageSpace iMs = null;
		new RankThenEncipher<BigInteger>(iMs);
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testMSNotEqual() {
		IntegerRangeMessageSpace irMs = new IntegerRangeMessageSpace(BigInteger.ONE, BigInteger.TEN);
		IntegerMessageSpace iMs = new IntegerMessageSpace(BigInteger.TEN);
		IntegerCipher iC = new FFXIntegerCipher(iMs);
		new RankThenEncipher<BigInteger>(irMs, iC);
	}

	@Test
	public void testKeyNot128Bit() {
		IntegerRangeMessageSpace iMs = new IntegerRangeMessageSpace(BigInteger.ONE, BigInteger.TEN);
		RankThenEncipher<BigInteger> rte = new RankThenEncipher<BigInteger>(iMs);
		Key shortKey = new Key(new byte[5]);
		rte.encrypt(BigInteger.ONE, shortKey,tweak); 
	}

	@Test(expected = OutsideMessageSpaceException.class)
	public void testEncryptEmptyPlaintext() {
		ArrayList<String> list = new ArrayList<String>();
		list.add("a");
		list.add("b");
		EnumerationMessageSpace<String> eMs = new EnumerationMessageSpace<String>(list);
		RankThenEncipher<String> rte = new RankThenEncipher<String>(eMs);
		rte.encrypt("", key, tweak);
	}

	@Test(expected = OutsideMessageSpaceException.class)
	public void testEncryptPlaintextNotInMS() {
		IntegerRangeMessageSpace iMs = new IntegerRangeMessageSpace(BigInteger.ONE, BigInteger.TEN);
		RankThenEncipher<BigInteger> rte = new RankThenEncipher<BigInteger>(iMs);
		rte.encrypt(BigInteger.ZERO, key, tweak);
	}

	@Test
	public void testEncryptTwoTimesSameOutput() {
		IntegerRangeMessageSpace iMs = new IntegerRangeMessageSpace(BigInteger.ONE, BigInteger.TEN);
		RankThenEncipher<BigInteger> rte = new RankThenEncipher<BigInteger>(iMs);
		BigInteger cipher1 = rte.encrypt(BigInteger.ONE, key, tweak);
		BigInteger cipher2 = rte.encrypt(BigInteger.ONE, key, tweak);
		assertEquals(cipher1, cipher2);
	}

	@Test
	public void testEncryptDecryptIntegerMessageSpace() {
		IntegerRangeMessageSpace iMs = new IntegerRangeMessageSpace(BigInteger.ONE,	BigInteger.TEN);
		RankThenEncipher<BigInteger> rte = new RankThenEncipher<BigInteger>(iMs);
		BigInteger plaintext = BigInteger.valueOf(5);
		BigInteger ciphertext = rte.encrypt(plaintext, key, tweak);
		BigInteger decPlaintext = rte.decrypt(ciphertext, key, tweak);
		assertEquals(plaintext, decPlaintext);
	}

	@Test
	public void testEncryptDecryptEnumMessageSpace() {
		ArrayList<String> list = new ArrayList<String>();
		list.add("a");
		list.add("b");
		list.add("c");
		EnumerationMessageSpace<String> eMs = new EnumerationMessageSpace<String>(list);
		RankThenEncipher<String> rte = new RankThenEncipher<String>(eMs);
		String plaintext = "b";
		String ciphertext = rte.encrypt(plaintext, key, tweak);
		String decPlaintext = rte.decrypt(ciphertext, key, tweak);
		assertEquals(plaintext, decPlaintext);
	}

	@Test
	public void testEncryptDecryptWrongKey() {
		IntegerRangeMessageSpace iMs = new IntegerRangeMessageSpace(BigInteger.ONE, BigInteger.TEN);
		RankThenEncipher<BigInteger> rte = new RankThenEncipher<BigInteger>(iMs);
		BigInteger plaintext = BigInteger.valueOf(5);
		Key key2 = new Key(new byte[]{15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0});
		BigInteger ciphertext = rte.encrypt(plaintext, key, tweak);
		BigInteger decPlaintext = rte.decrypt(ciphertext, key2, tweak);
		assertFalse(plaintext == decPlaintext);
	}

	@Test
	public void testEncryptDecryptWrongCiphertextCorrectKey() {
		IntegerRangeMessageSpace iMs = new IntegerRangeMessageSpace(BigInteger.ONE, BigInteger.TEN);
		RankThenEncipher<BigInteger> rte = new RankThenEncipher<BigInteger>(iMs);
		BigInteger plaintext = BigInteger.valueOf(5);
		Key key = new Key(new byte[16]);
		BigInteger correctCipher = rte.encrypt(plaintext, key, tweak);
		BigInteger wrongCipher = correctCipher.add(BigInteger.ONE);
		BigInteger decPlaintext = rte.decrypt(wrongCipher, key, tweak);
		assertFalse(plaintext == decPlaintext);
	}

}
