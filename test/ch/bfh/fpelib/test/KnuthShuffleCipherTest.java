package ch.bfh.fpelib.test;

import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.Test;

import ch.bfh.fpelib.Key;
import ch.bfh.fpelib.intEnc.KnuthShuffleCipher;
import ch.bfh.fpelib.messageSpace.IntegerMessageSpace;
import ch.bfh.fpelib.messageSpace.OutsideMessageSpaceException;

public class KnuthShuffleCipherTest {
	
	static Key key = new Key(new byte[]{28,93,-94,-128,0,117,23,43,-19,120,86,94,-62,101,14,21});
	static Key key2 = new Key(new byte[]{29,93,-94,-128,0,117,23,43,-19,120,86,94,-62,101,14,21});
	static byte[] tweak = new byte[]{-13,87,22,94,28,43,46,-17,-20,87,22,94,28,43,46,-19};
	static byte[] tweak2 = new byte[]{-14,87,22,94,28,43,46,-17,-20,87,22,94,28,43,46,-19};
	IntegerMessageSpace ims10 = new IntegerMessageSpace(BigInteger.TEN);

	@Test(expected = IllegalArgumentException.class)
	public void testInputNull() {
		KnuthShuffleCipher knuth = new KnuthShuffleCipher(ims10);
		knuth.encrypt(null, key, tweak);
	}
	
	@Test(expected = OutsideMessageSpaceException.class)
	public void testInputToBig() {
		KnuthShuffleCipher knuth = new KnuthShuffleCipher(ims10);
		BigInteger input = BigInteger.valueOf(11);
		knuth.encrypt(input, key, tweak);
	}
	
	@Test(expected = OutsideMessageSpaceException.class)
	public void testInputNegative() {
		KnuthShuffleCipher knuth = new KnuthShuffleCipher(ims10);
		BigInteger input = BigInteger.valueOf(-1);
		knuth.encrypt(input, key, tweak);
	}
	
	@Test
	public void testInputMin() {
		KnuthShuffleCipher knuth = new KnuthShuffleCipher(ims10);
		BigInteger input = BigInteger.ZERO;
		BigInteger output = knuth.encrypt(input, key, tweak);
		assertNotNull(output);
	}
	
	@Test
	public void testInputMax() {
		KnuthShuffleCipher knuth = new KnuthShuffleCipher(ims10);
		BigInteger input = BigInteger.TEN;
		BigInteger output = knuth.encrypt(input, key, tweak);
		assertNotNull(output);
	}
	
	@Test
	public void testDifferentKeyLength() {
		KnuthShuffleCipher knuth = new KnuthShuffleCipher(ims10);
		BigInteger input = BigInteger.TEN;
		Key key = new Key(new byte[15]);
		knuth.encrypt(input, key, tweak);
	}
	
	@Test
	public void testDifferentTweakLength() {
		KnuthShuffleCipher knuth = new KnuthShuffleCipher(ims10);
		BigInteger input = BigInteger.TEN;
		byte[] tweak = new byte[15];
		knuth.encrypt(input, key, tweak);
	}
	
	@Test
	public void testTwoTimesSameOutput() {
		KnuthShuffleCipher knuth = new KnuthShuffleCipher(ims10);
		KnuthShuffleCipher knuth2 = new KnuthShuffleCipher(ims10);
		BigInteger input = BigInteger.TEN;
		BigInteger output = knuth.encrypt(input, key, tweak);
		BigInteger output2 = knuth2.encrypt(input, key, tweak);
		assertEquals(output, output2);
	}
	
	@Test
	public void testEncryptDecryptAll() {
		KnuthShuffleCipher knuth = new KnuthShuffleCipher(ims10);
		for (int i=0; i<=10; i++) {
			BigInteger enc = knuth.encrypt(BigInteger.valueOf(i), key, tweak);
			BigInteger dec = knuth.decrypt(enc, key, tweak);
			assertEquals(BigInteger.valueOf(i), dec);
		}
	}
	
	@Test
	public void testDifferentKeyDifferentOutput() {
		KnuthShuffleCipher knuth = new KnuthShuffleCipher(ims10);
		boolean equal = true;
		for (int i=0; i<=10; i++) {
			BigInteger output1 = knuth.encrypt(BigInteger.valueOf(i), key, tweak);
			BigInteger output2 = knuth.encrypt(BigInteger.valueOf(i), key2, tweak);
			if (!output1.equals(output2)) equal = false;
		}
		assertFalse(equal);
	}
	
	@Test
	public void testDifferentTweakDifferentOutput() {
		KnuthShuffleCipher knuth = new KnuthShuffleCipher(ims10);
		boolean equal = true;
		for (int i=0; i<=10; i++) {
			BigInteger output1 = knuth.encrypt(BigInteger.valueOf(i), key, tweak);
			BigInteger output2 = knuth.encrypt(BigInteger.valueOf(i), key, tweak2);
			if (!output1.equals(output2)) equal = false;
		}
		assertFalse(equal);
	}

}
