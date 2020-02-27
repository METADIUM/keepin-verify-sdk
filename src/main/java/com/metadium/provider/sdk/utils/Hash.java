package com.metadium.provider.sdk.utils;

import org.bouncycastle.jcajce.provider.digest.Keccak;

/**
 * Hash 함수
 * <p/>
 * 
 * @author ybjeon
 */
public class Hash {
	/**
	 * sha3 (keccak 256)
	 * 
	 * @param input		hash 할 데이터
	 * @param offset	input 의 시작
	 * @param length	처리 길이
	 * @return
	 */
	public static byte[] sha3(byte[] input, int offset, int length) {
	    Keccak.DigestKeccak kecc = new Keccak.Digest256();
	    kecc.update(input, offset, length);
	    return kecc.digest();
	}
	
	/**
	 * sha3
	 * {@link #sha3(byte[], int, int)} 참조
	 * 
	 * @param input hash 할 데이터
	 * @return
	 * @see #sha3(byte[], int, int)
	 */
	public static byte[] sha3(byte[] input) {
		return sha3(input, 0, input.length);
	}
}
