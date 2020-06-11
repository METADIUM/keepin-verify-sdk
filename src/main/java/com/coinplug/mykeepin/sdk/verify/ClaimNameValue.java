package com.coinplug.mykeepin.sdk.verify;

/**
 * Claim 의 name, value
 * 
 * @author ybjeon
 *
 * @param <T> value 의 타입
 */
public class ClaimNameValue<T> {
	private String name;
	private T value;
	

	public static <T> ClaimNameValue<T> create(String name, T value) {
		ClaimNameValue<T> cnv = new ClaimNameValue<T>(name, value);
		return cnv;
	}

	public ClaimNameValue(String name, T value) {
		this.name = name;
		this.value = value;
	}
	

	public String getName() {
		return name;
	}

	public T getValue() {
		return value;
	}
}
