package com.metadium.did.exception;

public class DidException extends Exception {
	private static final long serialVersionUID = 672189694667663376L;

	public DidException() {
		super();
	}

	public DidException(String message, Throwable cause) {
		super(message, cause);
	}

	public DidException(String message) {
		super(message);
	}

	public DidException(Throwable cause) {
		super(cause);
	}
}
