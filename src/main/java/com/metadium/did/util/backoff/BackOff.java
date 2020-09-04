package com.metadium.did.util.backoff;

/**
 * Back-off
 */
public interface BackOff {
    public BackOffExecution start();
}
