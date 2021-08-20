package com.coinplug.mykeepin.sdk.verify;

/**
 * Claim 의 name, value
 * 
 * @author ybjeon
 *
 * @param <T> value 의 타입
 */
public class ClaimNameValue {
	private String credentialName;
	private String name;
	private Object value;
	

	public static ClaimNameValue create(String credentialName, String name, Object value) {
		ClaimNameValue cnv = new ClaimNameValue(credentialName, name, value);
		return cnv;
	}

	public ClaimNameValue(String credentialName, String name, Object value) {
		this.credentialName = credentialName;
		this.name = name;
		this.value = value;
	}
	
	public String getCredentialName() {
		return credentialName;
	}

	public String getName() {
		return name;
	}
	
	public Object getValue() {
		return value;
	}
	
	
}
