from typing import Any

from app.core.logging import logger


class VerificationResult:
    def __init__(self, verified: bool, status: str, details: str):
        self.verified = verified
        self.status = status  # VERIFIED, VERIFICATION_FAILED
        self.details = details


def verify_response_action(
    action_type: str,
    before_state: dict[str, Any],
    after_state: dict[str, Any],
    adapter_success: bool,
) -> VerificationResult:
    """
    Forensically verifies whether an action achieved its intended containment/remediation objective
    by comparing before and after system telemetry.
    """
    if not adapter_success or "error" in after_state:
        err_msg = after_state.get("error", "Adapter returned execution failure")
        logger.error("Action execution failed: %s", err_msg)
        return VerificationResult(
            verified=False,
            status="VERIFICATION_FAILED",
            details=f"Execution error reported by adapter: {err_msg}",
        )

    action_upper = action_type.strip().upper()

    if action_upper == "IP_CONTAINMENT":
        traffic_before = before_state.get("traffic_status")
        traffic_after = after_state.get("traffic_status")
        if traffic_before == "ALLOWED" and traffic_after == "DENIED":
            return VerificationResult(
                verified=True,
                status="VERIFIED",
                details=(
                    "CONTAINMENT VERIFIED: Firewall successfully transitioned traffic state from ALLOWED to DENIED."
                ),
            )
        return VerificationResult(
            verified=False,
            status="VERIFICATION_FAILED",
            details=f"State check failed: expected ALLOWED -> DENIED, but got {traffic_before} -> {traffic_after}.",
        )

    elif action_upper == "ACCOUNT_LOCKOUT":
        status_before = before_state.get("account_status")
        status_after = after_state.get("account_status")
        if status_before == "ACTIVE" and status_after == "LOCKED":
            return VerificationResult(
                verified=True,
                status="VERIFIED",
                details=(
                    "ACCOUNT LOCKOUT VERIFIED: Directory service confirmed account state "
                    "transitioned from ACTIVE to LOCKED."
                ),
            )
        return VerificationResult(
            verified=False,
            status="VERIFICATION_FAILED",
            details=f"State check failed: expected ACTIVE -> LOCKED, but got {status_before} -> {status_after}.",
        )

    elif action_upper == "SESSION_REVOCATION":
        sessions_before = before_state.get("active_sessions", 0)
        sessions_after = after_state.get("active_sessions", 0)
        tokens_valid = after_state.get("refresh_tokens_valid", True)
        if sessions_after == 0 and not tokens_valid:
            return VerificationResult(
                verified=True,
                status="VERIFIED",
                details=(
                    f"SESSION REVOCATION VERIFIED: Invalidated {sessions_before} active session(s) "
                    "and revoked refresh tokens."
                ),
            )
        return VerificationResult(
            verified=False,
            status="VERIFICATION_FAILED",
            details="State check failed: active sessions or valid refresh tokens remain in after_state.",
        )

    elif action_upper == "HOST_ISOLATION":
        net_before = before_state.get("network_status")
        net_after = after_state.get("network_status")
        if net_before == "CONNECTED" and net_after == "ISOLATED":
            return VerificationResult(
                verified=True,
                status="VERIFIED",
                details=(
                    "HOST ISOLATION VERIFIED: EDR confirmed endpoint network transitioned from CONNECTED to ISOLATED."
                ),
            )
        return VerificationResult(
            verified=False,
            status="VERIFICATION_FAILED",
            details=f"State check failed: expected CONNECTED -> ISOLATED, but got {net_before} -> {net_after}.",
        )

    elif action_upper in ("L2_ESCALATION", "COLLECT_EVIDENCE"):
        return VerificationResult(
            verified=True,
            status="VERIFIED",
            details=f"Workflow action '{action_upper}' executed and logged successfully.",
        )

    return VerificationResult(
        verified=False,
        status="VERIFICATION_FAILED",
        details=f"Unrecognized action type '{action_type}' for verification.",
    )
