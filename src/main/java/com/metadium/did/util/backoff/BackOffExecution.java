package com.metadium.did.util.backoff;

/**
 * back-off execute interface
 */
public interface BackOffExecution {
    long STOP = -1;

    public long nextBackOff();
}
