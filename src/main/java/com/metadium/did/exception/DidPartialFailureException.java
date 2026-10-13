package com.metadium.did.exception;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A DID operation made of several on-chain steps failed after some of them had completed.
 * The cause is the original failure (an exception of the external signer, a failed transaction, ...).
 * Errors of the compensation steps are attached to the cause as suppressed exceptions.
 *
 * <p>{@link #getSteps()} and {@link #getCompensationSteps()} describe the transactions in a form a program can use
 * (operation, target key, transaction hash, status). {@link #getCompletedSteps()} and {@link #getUnrecoveredSteps()}
 * are the same information as text for logs.
 *
 * <p>If a transaction was submitted but not confirmed ({@link DidStep.Status#SUBMITTED_UNCONFIRMED}), its effect is unknown
 * and it may still be mined, so nothing is rolled back; {@link #getUnrecoveredSteps()} tells which transaction to check.
 */
public class DidPartialFailureException extends DidException {
	private static final long serialVersionUID = 5360347586953418841L;

	private final String did;
	private final ArrayList<String> completedSteps;
	private final ArrayList<String> unrecoveredSteps;
	private final ArrayList<DidStep> steps;
	private final ArrayList<DidStep> compensationSteps;

	/**
	 * @param message          message
	 * @param cause            original failure
	 * @param did              DID of the operation. Null if the DID is not known
	 * @param completedSteps   on-chain steps completed before the failure (with transaction hash if known)
	 * @param unrecoveredSteps steps that still have to be done or undone. Empty if the compensation succeeded
	 */
	public DidPartialFailureException(String message, Throwable cause, String did, List<String> completedSteps, List<String> unrecoveredSteps) {
		this(message, cause, did, completedSteps, unrecoveredSteps, new ArrayList<DidStep>(), new ArrayList<DidStep>());
	}

	/**
	 * @param steps             every transaction of the operation that was submitted, in order, with its status
	 * @param compensationSteps transactions submitted to undo completed steps, in order, with their status
	 */
	public DidPartialFailureException(String message, Throwable cause, String did, List<String> completedSteps, List<String> unrecoveredSteps, List<DidStep> steps, List<DidStep> compensationSteps) {
		super(message, cause);
		this.did = did;
		this.completedSteps = new ArrayList<String>(completedSteps);
		this.unrecoveredSteps = new ArrayList<String>(unrecoveredSteps);
		this.steps = new ArrayList<DidStep>(steps);
		this.compensationSteps = new ArrayList<DidStep>(compensationSteps);
	}

	/** DID of the operation. Null if the DID is not known */
	public String getDid() {
		return did;
	}

	/** On-chain steps completed before the failure */
	public List<String> getCompletedSteps() {
		return Collections.unmodifiableList(completedSteps);
	}

	/** Steps that still have to be done or undone. Empty if the compensation succeeded */
	public List<String> getUnrecoveredSteps() {
		return Collections.unmodifiableList(unrecoveredSteps);
	}

	/**
	 * Every transaction of the operation that was submitted, in order, including a reverted one
	 * ({@link DidStep.Status#FAILED}) and one that was not confirmed ({@link DidStep.Status#SUBMITTED_UNCONFIRMED}).
	 * Empty if the exception was created with the constructor that has no steps.
	 */
	public List<DidStep> getSteps() {
		return Collections.unmodifiableList(steps);
	}

	/** Transactions submitted to undo completed steps, in order, with their status */
	public List<DidStep> getCompensationSteps() {
		return Collections.unmodifiableList(compensationSteps);
	}
}
