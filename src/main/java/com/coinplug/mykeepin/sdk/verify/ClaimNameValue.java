package com.coinplug.mykeepin.sdk.verify;

/**
 * Claim 의 name, value
 * 
 * @author ybjeon
 *
 * @param <T> value 의 타입
 */
public class ClaimNameValue {
	private String name;
	private Object value;
	

	public static ClaimNameValue create(String name, Object value) {
		ClaimNameValue cnv = new ClaimNameValue(name, value);
		return cnv;
	}

	public ClaimNameValue(String name, Object value) {
		this.name = name;
		this.value = value;
	}
	

	public String getName() {
		return name;
	}

	public Object getValue() {
		return value;
	}
}
