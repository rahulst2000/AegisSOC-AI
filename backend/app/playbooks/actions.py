from typing import Any


class MockFirewallAdapter:
    """Safe lab/mock adapter simulating perimeter firewall operations."""

    @classmethod
    def block_ip(cls, ip_address: str) -> dict[str, Any]:
        before_state = {
            "target": ip_address,
            "traffic_status": "ALLOWED",
            "firewall_rule": "DEFAULT_ALLOW",
        }

        # Simulate failure if requested
        if "FAIL_SIMULATION" in ip_address or ip_address == "0.0.0.0":  # nosec: B104
            after_state = {
                "target": ip_address,
                "traffic_status": "ALLOWED",
                "error": "Perimeter firewall API connection timed out",
            }
            return {
                "before": before_state,
                "action": "BLOCK_IP",
                "after": after_state,
                "success": False,
            }

        after_state = {
            "target": ip_address,
            "traffic_status": "DENIED",
            "firewall_rule": f"DENY_INGRESS_{ip_address.replace('.', '_')}",
        }
        return {
            "before": before_state,
            "action": "BLOCK_IP",
            "after": after_state,
            "success": True,
        }


class MockIdentityAdapter:
    """Safe lab/mock adapter simulating Identity Provider (IdP/IAM/LDAP) operations."""

    @classmethod
    def lock_account(cls, username: str) -> dict[str, Any]:
        before_state = {
            "username": username,
            "account_status": "ACTIVE",
            "login_allowed": True,
        }

        if "FAIL_SIMULATION" in username:
            after_state = {
                "username": username,
                "account_status": "ACTIVE",
                "login_allowed": True,
                "error": "Directory service replication failed",
            }
            return {
                "before": before_state,
                "action": "LOCK_ACCOUNT",
                "after": after_state,
                "success": False,
            }

        after_state = {
            "username": username,
            "account_status": "LOCKED",
            "login_allowed": False,
        }
        return {
            "before": before_state,
            "action": "LOCK_ACCOUNT",
            "after": after_state,
            "success": True,
        }

    @classmethod
    def revoke_sessions(cls, username: str) -> dict[str, Any]:
        before_state = {
            "username": username,
            "active_sessions": 3,
            "refresh_tokens_valid": True,
        }

        after_state = {
            "username": username,
            "active_sessions": 0,
            "refresh_tokens_valid": False,
        }
        return {
            "before": before_state,
            "action": "REVOKE_SESSION",
            "after": after_state,
            "success": True,
        }


class MockEndpointAdapter:
    """Safe lab/mock adapter simulating Endpoint Detection & Response (EDR) network isolation."""

    @classmethod
    def isolate_host(cls, hostname: str) -> dict[str, Any]:
        before_state = {
            "hostname": hostname,
            "network_status": "CONNECTED",
            "quarantined": False,
        }

        if "FAIL_SIMULATION" in hostname:
            after_state = {
                "hostname": hostname,
                "network_status": "CONNECTED",
                "quarantined": False,
                "error": "EDR agent unresponsive on target endpoint",
            }
            return {
                "before": before_state,
                "action": "ISOLATE_HOST",
                "after": after_state,
                "success": False,
            }

        after_state = {
            "hostname": hostname,
            "network_status": "ISOLATED",
            "quarantined": True,
        }
        return {
            "before": before_state,
            "action": "ISOLATE_HOST",
            "after": after_state,
            "success": True,
        }
