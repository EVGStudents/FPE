package ch.bfh.fpe.intEnc;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import ch.bfh.fpe.messageSpace.IntegerMessageSpace;
import ch.bfh.fpe.messageSpace.OutsideMessageSpaceException;

public class EME2IntegerCipher extends IntegerCipher {
	
	private static final int MIN_BIT_LENGTH = 128;	

	public EME2IntegerCipher(IntegerMessageSpace messageSpace) {
		super(messageSpace);
		if (messageSpace.getOrder().bitLength() < MIN_BIT_LENGTH) throw new IllegalArgumentException("Message space must be bigger than 128 bit");
	}

	@Override
	public BigInteger encrypt(BigInteger plaintext, byte[] key, byte[] tweak) {
		return cipher(plaintext, key, tweak, true);
	}

	@Override
	public BigInteger decrypt(BigInteger ciphertext, byte[] key, byte[] tweak) {
		return cipher(ciphertext, key, tweak, false);
	}
	
	

	private BigInteger cipher(BigInteger input, byte[] key, byte[] tweak, boolean encryption){
		
		BigInteger maxMsValue = getMessageSpace().getOrder().subtract(BigInteger.ONE); //-1 because the order is 1 more than the max allowed value	
		if (input==null) throw new IllegalArgumentException("Input value must not be null");
		if (input.compareTo(BigInteger.ZERO)==-1) throw new IllegalArgumentException("Input value must not be negative");
		if (input.compareTo(maxMsValue)==1) throw new OutsideMessageSpaceException(input.toString());
		if (key==null || key.length != 48) throw new IllegalArgumentException("Key must be 48 byte long");
		if (tweak==null) throw new IllegalArgumentException("Tweak must not be null");

	
		
		try {
			do{
				System.out.println("----------Cycle Walk-----------");
				System.out.println("Plaintext: " + input);
				input = cipherFunction(input,key, tweak, encryption);
			
				
			} while (input.compareTo(maxMsValue)==1); //Cycle Walking: While new value is outside of message space, encipher again
		
		} catch (GeneralSecurityException e) {
			throw new IllegalArgumentException("A security exception occured: " + e.getMessage());
		}
			
		return input;
		
		
	}
	
	
	private BigInteger cipherFunction(BigInteger plaintext, byte[] key, byte[] tweak, boolean encryption) throws GeneralSecurityException {
		
		boolean lastBlockNotFull = true;	
		byte[] T_star = new byte[16];
		byte[] key1 = new byte[16]; //Key used for AES encryption
		byte[] key2 = new byte[16];
		byte[] key3 = new byte[16];
		
		System.arraycopy(key, 0, key1, 0, 16);
		System.arraycopy(key, 16, key2, 0, 16);
		System.arraycopy(key, 32, key3, 0,16);
		
		
		// Initialize AES for the Tweak-Part it's always encryption
		Cipher aesCipher = Cipher.getInstance("AES/ECB/NoPadding");
		aesCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key1, "AES"));
		
		
		
		
		// Process the associated data T to get the 16-byte block T_star
	//	System.out.println("tweak.length: " + tweak.length);
		//System.out.println("tweak.length-1-(-tweak.length%16): " + (tweak.length-(16-((-tweak.length%16)+16)%16)));
		ArrayList<byte[]> T = new ArrayList<byte[]>();
		for (int m=0; m < tweak.length-15;m+=16) T.add(Arrays.copyOfRange(tweak, m, m+16)); //Copy 16 byte blocks as element in ArrayList
		if(tweak.length%16 != 0) T.add(Arrays.copyOfRange(tweak, (tweak.length-(16-((-tweak.length%16)+16)%16)), tweak.length));
		
		
		ArrayList<byte[]> TT= new ArrayList<byte[]>();
		
	
		if(T.size()==0) T_star = aesCipher.doFinal(key3);
		else{
			key3 = multByAlpha(key3);
			
			for(int i=0; i<T.size()-1;i++){
				TT.add(xor(aesCipher.doFinal(xor(T.get(i),key3)),key3));
				key3 = multByAlpha(key3);
			}
			
			if(T.get(T.size()-1).length < 16){
				T.set(T.size()-1, padToBlocksize(T.get(T.size()-1)));
				key3 = multByAlpha(key3);
			}
			TT.add(xor(aesCipher.doFinal(xor(T.get(T.size()-1),key3)),key3));
			

			for(byte[] TTi : TT) T_star = xor(T_star,TTi);
		}
				
		
	
		if (encryption==false) aesCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key1, "AES")); //if decryption switch AES to decrypt mode
		
		byte[] plaintextByteArray = plaintext.toByteArray();
		int byteLengthMS = getMessageSpace().getOrder().toByteArray().length;
		byte[] bytePlain = new byte[byteLengthMS];
		//System.out.println("input: " + Arrays.toString(input));
		System.out.println("byteLengthMS: " + bytePlain.length);
		System.out.println("byteLengthplaintext: " + plaintextByteArray.length);
		System.arraycopy(plaintextByteArray, 0, bytePlain, bytePlain.length-plaintextByteArray.length, plaintextByteArray.length);
		
		
		// First ECB pass
		byte[] L = key2;
		ArrayList<byte[]> P = new ArrayList<byte[]>();
		
		
		for (int m=0; m < bytePlain.length-15;m+=16){
		//	System.out.println("m: " + m);
			P.add(Arrays.copyOfRange(bytePlain, m, m+16)); //Copy 16 byte blocks as element in ArrayList
		}
		//System.out.println("P: " + P.toString());
		
		if(bytePlain.length%16 != 0) P.add(Arrays.copyOfRange(bytePlain, (bytePlain.length-(16-((-bytePlain.length%16)+16)%16)), bytePlain.length));
		System.out.println("P.size(): " + P.size());
				
		int indexOfLastBlock = P.size()-1; //m
		int lengthOfLastBlock = P.get(indexOfLastBlock).length; //len(Pm)
		if(lengthOfLastBlock == 16) lastBlockNotFull = false;	
		
		System.out.println("indexOfLastBlock: " + indexOfLastBlock);
		System.out.println("lengthOfLastBlock: " + lengthOfLastBlock);
	
		ArrayList<byte[]> PPP = new ArrayList<byte[]>(); //PPP contains the encrypted plaintext
		for(int i=0; i<indexOfLastBlock;i++){
			PPP.add(aesCipher.doFinal(xor(L,P.get(i))));
			L = multByAlpha(L);
		}
		
		if(lastBlockNotFull) PPP.add(padToBlocksize(P.get(indexOfLastBlock)));
		else PPP.add(aesCipher.doFinal(xor(L,P.get(indexOfLastBlock))));

		System.out.println("PPP.length: " + PPP.size());
		
		
		// Intermediate mixing
		byte[] MP = T_star;
		for (byte[] PPPi : PPP) MP = xor(MP,PPPi);
		
		byte[] M, M1, MC, MC1, MM = null, Cm = null;
		if(lastBlockNotFull){
			MM = aesCipher.doFinal(MP);
			MC = MC1 = aesCipher.doFinal(MM);	
		} else {
			MC = MC1 = aesCipher.doFinal(MP);	
		}
		
		M = M1 = xor(MP,MC);

		ArrayList<byte[]> CCC = new ArrayList<byte[]>();
		CCC.add(new byte[16]); //placeholder for first element, is replaced later
		
		for (int i=1; i<indexOfLastBlock;i++){
			if ((i-1)%128 > 0) {
				M = multByAlpha(M);
				CCC.add(xor(PPP.get(i),M));
				
			}else{
				MP = xor(PPP.get(i),M1);
				MC = aesCipher.doFinal(MP);
				M = xor(MP,MC);
				CCC.add(xor(MC,M1));	
				}
			}
		
		if(lastBlockNotFull){
			Cm = xor(P.get(indexOfLastBlock),MM);
			CCC.add(padToBlocksize(Cm));	
		} else if((indexOfLastBlock-1)%128 > 0) {
			M = multByAlpha(M);
			CCC.add(xor(PPP.get(indexOfLastBlock),M));
		} else {
			CCC.add(xor(aesCipher.doFinal(xor(M1,PPP.get(indexOfLastBlock))),M1));
		}
		
		byte[] CCC1temp = xor(MC1,T_star);
		
		for (byte[] CCCi : CCC){
		//	System.out.println("CCCtemp: " + Arrays.toString(CCC1temp));
		//	System.out.println("CCCi: " + Arrays.toString(CCCi));
			CCC1temp = xor(CCC1temp,CCCi);
		}
		CCC.set(0,CCC1temp);
		
		System.out.println("CCC.length: " + CCC.size());
		
		// Second ECB Pass
		L = key2;
		ArrayList<byte[]> C = new ArrayList<byte[]>();
		
		for(int i=0; i<indexOfLastBlock; i++){
			C.add(xor(aesCipher.doFinal(CCC.get(i)),L));
			L = multByAlpha(L);
		}
		
		/* Note that we computed the last ciphertext block above if it was short */
		if(lastBlockNotFull) C.add(Cm);
		else C.add(xor(aesCipher.doFinal(CCC.get(indexOfLastBlock)),L));
		
	
	
		System.out.println("C.length: " + C.size());
		System.out.println("Letzer Block in C length: " + C.get(C.size()-1).length);
		byte[] output = new byte[bytePlain.length];
		int i = 0;
		for (byte[] block : C){
		//	System.out.println("block.length: " + block.length);
			for (byte element : block){
			//	System.out.println(i);
				output[i] = element;
				i++;
			}
		}
		
		System.out.println("ByteArrayoutput.length: " +output.length);
		BigInteger returnval = new BigInteger(1,output);
		System.out.println("BigInteger output.length: " +returnval.toByteArray().length);
		return  returnval;
	}

	
	
	
	private static byte[] padToBlocksize(byte[] input){
		byte[] output = new byte[input.length + (((-input.length%16)+16)%16)];
		//System.out.println("input: " + Arrays.toString(input));
		System.arraycopy(input, 0, output, 0, input.length);
		output[input.length] = (byte) 1;
		//System.out.println("output: " + Arrays.toString(output));
		return output;
	}
	
	
	private static byte[] multByAlpha(byte[] input){
		byte[] output = new byte[16];
		
		for(int i=0;i<16;i++){
			output[i] = (byte) ((2 * input[i]) % 256);
			if(i>0 && input[i-1] > 127) output[i] = (byte) (output[i] + 1);
		}
		if (input[15] > 127) output[0] = (byte) (output[0] ^ 0x87);
		return output;	
	}
	
	/**
	 * Calculates the XOR value for two given ByteArrays.
	 * @param array1 First ByteArray
	 * @param array2 Second ByteArray
	 * @return a ByteArray with the XOR value
	 */
	private static byte[] xor(byte[] array1, byte[] array2)
	{
		byte[] xorArray = new byte[array1.length];
		int i = 0;
		for (byte b : array1){
			xorArray[i] = (byte) (b ^ array2[i++]);
		}
		return xorArray;
	}
	
	
}
