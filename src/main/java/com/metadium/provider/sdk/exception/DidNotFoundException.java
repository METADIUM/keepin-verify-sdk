package com.metadium.provider.sdk.exception;

/**
 * DID 가 존재하지 않을 때의 예외
 * 
 * @author ybjeon
 *
 */
public class DidNotFoundException extends DidException {
	private static final long serialVersionUID = -2192063504730949320L;

	public DidNotFoundException() {
		super();
	}

	public DidNotFoundException(String message) {
		super(message);
	}
}
