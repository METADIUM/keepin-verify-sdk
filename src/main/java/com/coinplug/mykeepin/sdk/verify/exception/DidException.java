package com.coinplug.mykeepin.sdk.verify.exception;

/**
 * DID 관련 예외
 * 
 * @author ybjeon
 *
 */
public class DidException extends RuntimeException {
	private static final long serialVersionUID = -4797924977225093230L;

	public DidException() {
		super();
	}

	public DidException(String message) {
		super(message);
	}
}
