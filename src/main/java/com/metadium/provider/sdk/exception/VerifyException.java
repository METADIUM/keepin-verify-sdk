package com.metadium.provider.sdk.exception;

public class VerifyException extends RuntimeException {
	private static final long serialVersionUID = -2489979984691553083L;

	public VerifyException() {
		super();
	}

	public VerifyException(String message) {
		super(message);
	}

	public VerifyException(String message, Throwable cause) {
		super(message, cause);
	}
}
