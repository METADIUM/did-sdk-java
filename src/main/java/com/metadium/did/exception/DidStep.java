package com.metadium.did.exception;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * One on-chain transaction of an operation that is made of several transactions
 * (create DID, update key, delete DID), as reported by {@link DidPartialFailureException}.
 */
public final class DidStep implements Serializable {
	private static final long serialVersionUID = 2738205540367012953L;

	/** What the transaction does */
	public enum Operation {
		CREATE_IDENTITY,
		ADD_ASSOCIATED_ADDRESS,
		ADD_PUBLIC_KEY,
		REMOVE_PUBLIC_KEY,
		REMOVE_ASSOCIATED_ADDRESS
	}

	/** The key the transaction acts on */
	public enum Target {
		/** the key of the wallet (the old key while the key is updated) */
		CURRENT_KEY,
		/** the new key of {@code updateKeyOfDid} */
		NEW_KEY
	}

	/** Result of the transaction */
	public enum Status {
		/** the receipt has status 0x1: the change is on-chain */
		CONFIRMED,
		/** the receipt has another status: the transaction reverted and changed nothing */
		FAILED,
		/**
		 * The transaction was submitted but the receipt could not be read (timeout, network error).
		 * It may still be mined later, so its effect is unknown: check the transaction hash on the node.
		 */
		SUBMITTED_UNCONFIRMED
	}

	private final Operation operation;
	private final Target target;
	private final String txHash;
	private final Status status;
	private final BigInteger blockNumber;

	public DidStep(Operation operation, Target target, String txHash, Status status) {
		this(operation, target, txHash, status, null);
	}

	/**
	 * @param blockNumber block of the receipt. Nullable: null while the receipt is unknown ({@link Status#SUBMITTED_UNCONFIRMED}). A {@link Status#FAILED} (reverted) transaction is mined, so it has the block too
	 */
	public DidStep(Operation operation, Target target, String txHash, Status status, BigInteger blockNumber) {
		this.operation = operation;
		this.target = target;
		this.txHash = txHash;
		this.status = status;
		this.blockNumber = blockNumber;
	}

	public Operation getOperation() {
		return operation;
	}

	public Target getTarget() {
		return target;
	}

	/** Transaction hash. Not null for a step that was submitted */
	public String getTxHash() {
		return txHash;
	}

	public Status getStatus() {
		return status;
	}

	/** Block that contains the transaction. Null while the step is {@link Status#SUBMITTED_UNCONFIRMED}; {@link Status#CONFIRMED} and {@link Status#FAILED} steps have it */
	public BigInteger getBlockNumber() {
		return blockNumber;
	}

	@Override
	public String toString() {
		return operation + "(" + target + ") tx=" + txHash + " " + status + (blockNumber == null ? "" : " block=" + blockNumber);
	}
}
