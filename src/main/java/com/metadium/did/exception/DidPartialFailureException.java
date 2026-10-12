package com.metadium.did.exception;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A DID operation made of several on-chain steps failed after some of them had completed.
 * The cause is the original failure (an exception of the external signer, a failed transaction, ...).
 * Errors of the compensation steps are attached to the cause as suppressed exceptions.
 */
public class DidPartialFailureException extends DidException {
	private static final long serialVersionUID = 5360347586953418841L;

	private final String did;
	private final ArrayList<String> completedSteps;
	private final ArrayList<String> unrecoveredSteps;

	/**
	 * @param message          message
	 * @param cause            original failure
	 * @param did              DID of the operation. Null if the DID is not known
	 * @param completedSteps   on-chain steps completed before the failure (with transaction hash if known)
	 * @param unrecoveredSteps steps that still have to be done or undone. Empty if the compensation succeeded
	 */
	public DidPartialFailureException(String message, Throwable cause, String did, List<String> completedSteps, List<String> unrecoveredSteps) {
		super(message, cause);
		this.did = did;
		this.completedSteps = new ArrayList<String>(completedSteps);
		this.unrecoveredSteps = new ArrayList<String>(unrecoveredSteps);
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
}
