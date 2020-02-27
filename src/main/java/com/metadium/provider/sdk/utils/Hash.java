package com.metadium.provider.sdk.utils;

import org.bouncycastle.jcajce.provider.digest.Keccak;

public class Hash {
	public static byte[] sha3(byte[] input, int offset, int length) {
	    Keccak.DigestKeccak kecc = new Keccak.Digest256();
	    kecc.update(input, offset, length);
	    return kecc.digest();
	}
	
	public static byte[] sha3(byte[] input) {
		return sha3(input, 0, input.length);
	}
}
