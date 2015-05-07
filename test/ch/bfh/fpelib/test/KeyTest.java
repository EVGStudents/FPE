package ch.bfh.fpelib.test;

import static org.junit.Assert.*;

import org.junit.Test;

import ch.bfh.fpelib.Key;

public class KeyTest {
	
	byte[] key3Byte = new byte[]{23,38,-14};
	byte[] key16Byte = new byte[]{64,93,-94,-128,0,127,23,43,-19,120,86,94,-62,101,14,22};
	byte[] key32Byte = new byte[]{23,43,-19,120,86,94,-62,101,14,22,64,93,-94,-128,0,127,64,93,-94,-128,0,127,23,43,-19,120,86,94,-62,101,14,23};

	@Test
	public void testGetKeySameLength() {
		Key key = new Key(key16Byte);
		byte[] actualKey = key.getKey(16);
		assertArrayEquals(key16Byte, actualKey);
	}
	
	@Test
	public void testDeriveShorterKey() {
		Key key = new Key(key32Byte);
		byte[] actualKey = key.getKey(8);
		assertEquals(8, actualKey.length);
	}
	
	@Test
	public void testDeriveLongerKey() {
		Key key = new Key(key3Byte);
		byte[] actualKey = key.getKey(64);
		assertEquals(64, actualKey.length);
	}
	
	@Test
	public void testTwoTimesSameKey() {
		Key key1 = new Key(key16Byte);
		Key key2 = new Key(key16Byte);
		byte[] actualKey1 = key1.getKey(8);
		byte[] actualKey2 = key2.getKey(8);
		byte[] actualKey3 = key2.getKey(8);
		assertArrayEquals(actualKey1, actualKey2);
		assertArrayEquals(actualKey2, actualKey3);
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void testKeyNull() {
		Key key = new Key(null);
		key.getKey(64);
	}
	
	@Test
	public void testKeyEmpty() {
		byte[] empty = new byte[]{};
		Key key = new Key(empty);
		byte[] actualKey = key.getKey(8);
		assertEquals(8, actualKey.length);
	}

}
