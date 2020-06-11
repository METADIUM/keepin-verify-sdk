package com.coinplug.mykeepin.sdk.verify.exception;

import com.metadium.vc.VerifiableCredential;

public class CredentialException extends Exception {
	private static final long serialVersionUID = 5187876489252645575L;
	private VerifiableCredential credential;
	private ErrorCode errorCode;
	
	public CredentialException(ErrorCode errorCode, VerifiableCredential credential) {
		super();
		this.credential = credential;
		this.errorCode = errorCode;
	}

	public CredentialException(ErrorCode errorCode, String message) {
		super(message);
		this.errorCode = errorCode;
	}
	
	
	public VerifiableCredential getCredential() {
		return credential;
	}

	public ErrorCode getErrorCode() {
		return errorCode;
	}


	static enum ErrorCode {
		NotFoundCredential,
		ExpiredCredential,
		NotFoundClaim,
		MismatchClaimType,
		RevokedCredential,
		IssuerServerError
		;
	}
}
