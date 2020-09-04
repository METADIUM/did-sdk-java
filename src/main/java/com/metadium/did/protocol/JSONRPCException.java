package com.metadium.did.protocol;

import org.web3j.protocol.core.Response;

import java.util.Locale;

/**
 * General web3j exception
 */
public class JSONRPCException extends Exception {
	private static final long serialVersionUID = -7642445459414340510L;
	private Response.Error error;

    public JSONRPCException(Response.Error error) {
        super(String.format(Locale.getDefault(), "code:%d %s", error.getCode(), error.getMessage()));

        this.error = error;
    }

    public Response.Error getError() {
        return error;
    }
}
