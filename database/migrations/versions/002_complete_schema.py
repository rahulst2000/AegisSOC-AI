"""Complete schema migration: adds missing incident columns and creates all phase 2-5 security tables

Revision ID: 002_complete_schema
Revises: 001_initial_schema
Create Date: 2026-10-28 12:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "002_complete_schema"
down_revision: str | None = "001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Add missing columns to incidents table
    with op.batch_alter_table("incidents") as batch_op:
        batch_op.add_column(sa.Column("mitre_techniques", sa.JSON(), nullable=False, server_default="[]"))
        batch_op.add_column(sa.Column("detection_ids", sa.JSON(), nullable=False, server_default="[]"))
        batch_op.add_column(sa.Column("affected_assets", sa.JSON(), nullable=False, server_default="[]"))
        batch_op.add_column(sa.Column("affected_users", sa.JSON(), nullable=False, server_default="[]"))
        batch_op.add_column(sa.Column("source_ips", sa.JSON(), nullable=False, server_default="[]"))
        batch_op.add_column(sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True))

    # 2. Detection Rules table
    op.create_table(
        "detection_rules",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("rule_id", sa.String(length=100), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("version", sa.String(length=50), nullable=False, server_default="1.0.0"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("severity", sa.String(length=50), nullable=False, server_default="MEDIUM"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.9"),
        sa.Column("event_types", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("conditions", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("mitre_tactics", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("mitre_techniques", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("tags", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_detection_rules_rule_id", "detection_rules", ["rule_id"], unique=True)
    op.create_index("ix_detection_rules_tenant_id", "detection_rules", ["tenant_id"])
    op.create_index("ix_detection_rules_name", "detection_rules", ["name"])
    op.create_index("ix_detection_rules_enabled", "detection_rules", ["enabled"])
    op.create_index("ix_detection_rules_severity", "detection_rules", ["severity"])
    op.create_index("ix_detection_rules_tenant_enabled", "detection_rules", ["tenant_id", "enabled"])

    # 3. Detection Results table
    op.create_table(
        "detection_results",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rule_id", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=50), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("event_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("mitre_tactics", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("mitre_techniques", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("detection_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("previous_occurrences", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("false_positive_status", sa.String(length=50), nullable=False, server_default="UNREVIEWED"),
        sa.Column("analyst_feedback", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("dedup_hash", sa.String(length=64), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_detection_results_tenant_id", "detection_results", ["tenant_id"])
    op.create_index("ix_detection_results_rule_id", "detection_results", ["rule_id"])
    op.create_index("ix_detection_results_dedup_hash", "detection_results", ["dedup_hash"])
    op.create_index("ix_detection_results_timestamp", "detection_results", ["timestamp"])
    op.create_index("ix_detection_results_tenant_timestamp", "detection_results", ["tenant_id", "timestamp"])

    # 4. Investigations table
    op.create_table(
        "investigations",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("incident_id", sa.Uuid(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="ACTIVE"),
        sa.Column("executive_summary", sa.Text(), nullable=False),
        sa.Column("attack_chain", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("known_facts", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("unknowns", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("recommended_next_steps", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("l1_decision", sa.String(length=50), nullable=True),
        sa.Column("l2_escalation_recommended", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_investigations_tenant_id", "investigations", ["tenant_id"])
    op.create_index("ix_investigations_incident_id", "investigations", ["incident_id"])

    # 5. Investigation Hypotheses table
    op.create_table(
        "investigation_hypotheses",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("investigation_id", sa.Uuid(as_uuid=True), sa.ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("hypothesis_id", sa.String(length=50), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="FORMULATED"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("evidence_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("supporting_evidence", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("contradicting_evidence", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("unknowns", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_inv_hypotheses_tenant_id", "investigation_hypotheses", ["tenant_id"])
    op.create_index("ix_inv_hypotheses_inv_id", "investigation_hypotheses", ["investigation_id"])

    # 6. Investigation Findings table
    op.create_table(
        "investigation_findings",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("investigation_id", sa.Uuid(as_uuid=True), sa.ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="CONFIRMED"),
        sa.Column("evidence_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.9"),
        sa.Column("reasoning_summary", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_inv_findings_tenant_id", "investigation_findings", ["tenant_id"])
    op.create_index("ix_inv_findings_inv_id", "investigation_findings", ["investigation_id"])

    # 7. Playbook Definitions table
    op.create_table(
        "playbook_definitions",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("playbook_id", sa.String(length=100), nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("action_type", sa.String(length=100), nullable=False),
        sa.Column("required_role", sa.String(length=50), nullable=False, server_default="SOC_L2"),
        sa.Column("risk_level", sa.String(length=50), nullable=False, server_default="MEDIUM"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("parameters_schema", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_playbooks_playbook_id", "playbook_definitions", ["playbook_id"], unique=True)
    op.create_index("ix_playbooks_tenant_id", "playbook_definitions", ["tenant_id"])

    # 8. Action Requests table
    op.create_table(
        "action_requests",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("incident_id", sa.Uuid(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("investigation_id", sa.Uuid(as_uuid=True), sa.ForeignKey("investigations.id", ondelete="SET NULL"), nullable=True),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action_type", sa.String(length=100), nullable=False),
        sa.Column("target_entity", sa.String(length=255), nullable=False),
        sa.Column("target_type", sa.String(length=50), nullable=False),
        sa.Column("playbook_id", sa.String(length=100), nullable=False),
        sa.Column("requested_by", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("policy_evaluation", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("required_approval_role", sa.String(length=50), nullable=False, server_default="SOC_L2"),
        sa.Column("approval_status", sa.String(length=50), nullable=False, server_default="PENDING_APPROVAL"),
        sa.Column("approved_by", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("execution_status", sa.String(length=50), nullable=False, server_default="NOT_STARTED"),
        sa.Column("verification_status", sa.String(length=50), nullable=False, server_default="UNVERIFIED"),
        sa.Column("evidence_before", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("evidence_after", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("result", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_actions_tenant_id", "action_requests", ["tenant_id"])
    op.create_index("ix_actions_incident_id", "action_requests", ["incident_id"])

    # 9. Security Policies table
    op.create_table(
        "security_policies",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("action_type", sa.String(length=100), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("min_role_for_approval", sa.String(length=50), nullable=False, server_default="SOC_L2"),
        sa.Column("require_human_approval", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("conditions", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_policies_tenant_id", "security_policies", ["tenant_id"])

    # 10. L2 Escalations table
    op.create_table(
        "l2_escalations",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("incident_id", sa.Uuid(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("investigation_id", sa.Uuid(as_uuid=True), sa.ForeignKey("investigations.id", ondelete="SET NULL"), nullable=True),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("escalated_by", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("escalated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("urgency", sa.String(length=50), nullable=False, server_default="MEDIUM"),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="PENDING"),
        sa.Column("l2_package", sa.JSON(), nullable=False, server_default="{}"),
    )
    op.create_index("ix_l2_escalations_tenant_id", "l2_escalations", ["tenant_id"])
    op.create_index("ix_l2_escalations_incident_id", "l2_escalations", ["incident_id"])

    # 11. Adversary Assessments & Results
    op.create_table(
        "adversary_assessments",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("environment", sa.String(length=50), nullable=False, server_default="LAB"),
        sa.Column("authorized_scope", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("scenario", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="PLANNED"),
        sa.Column("created_by", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("authorized_by", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_adversary_assessments_tenant_id", "adversary_assessments", ["tenant_id"])

    op.create_table(
        "adversary_assessment_results",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("assessment_id", sa.Uuid(as_uuid=True), sa.ForeignKey("adversary_assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scenario_id", sa.String(length=100), nullable=False),
        sa.Column("technique_id", sa.String(length=50), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("simulation_status", sa.String(length=50), nullable=False, server_default="PENDING"),
        sa.Column("detection_status", sa.String(length=50), nullable=False, server_default="UNDETECTED"),
        sa.Column("correlation_status", sa.String(length=50), nullable=False, server_default="UNCORRELATED"),
        sa.Column("investigation_status", sa.String(length=50), nullable=False, server_default="UNINVESTIGATED"),
        sa.Column("response_status", sa.String(length=50), nullable=False, server_default="UNRESOLVED"),
        sa.Column("verification_status", sa.String(length=50), nullable=False, server_default="UNVERIFIED"),
        sa.Column("evidence_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("finding_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("cleanup_status", sa.String(length=50), nullable=False, server_default="CLEAN"),
        sa.Column("overall_result", sa.String(length=50), nullable=False, server_default="PENDING"),
        sa.Column("details", sa.JSON(), nullable=False, server_default="{}"),
    )
    op.create_index("ix_adv_results_tenant_id", "adversary_assessment_results", ["tenant_id"])
    op.create_index("ix_adv_results_assessment_id", "adversary_assessment_results", ["assessment_id"])

    # 12. Security Findings & Remediation
    op.create_table(
        "security_findings",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("assessment_id", sa.Uuid(as_uuid=True), sa.ForeignKey("adversary_assessments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("severity", sa.String(length=50), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("asset", sa.String(length=255), nullable=False),
        sa.Column("technique", sa.String(length=50), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("root_cause", sa.Text(), nullable=False),
        sa.Column("business_impact", sa.Text(), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column("priority", sa.String(length=50), nullable=False, server_default="MEDIUM"),
        sa.Column("owner", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="OPEN"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_findings_tenant_id", "security_findings", ["tenant_id"])

    op.create_table(
        "remediation_actions",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", sa.Uuid(as_uuid=True), sa.ForeignKey("security_findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("proposed_change", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("change_type", sa.String(length=50), nullable=False),
        sa.Column("approval_status", sa.String(length=50), nullable=False, server_default="PENDING_REVIEW"),
        sa.Column("approved_by", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retest_assessment_id", sa.Uuid(as_uuid=True), sa.ForeignKey("adversary_assessments.id", ondelete="SET NULL"), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_remediation_tenant_id", "remediation_actions", ["tenant_id"])

    # 13. Intelligence tables
    op.create_table(
        "security_state_snapshots",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("posture_score", sa.Float(), nullable=False, server_default="100.0"),
        sa.Column("open_incidents_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("active_alerts_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("monitored_assets_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("monitored_identities_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("state_vector", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("state_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_state_snapshots_tenant_ts", "security_state_snapshots", ["tenant_id", "timestamp"])

    op.create_table(
        "security_state_transitions",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("trigger_type", sa.String(length=50), nullable=False),
        sa.Column("trigger_entity_id", sa.String(length=100), nullable=False),
        sa.Column("from_state_summary", sa.String(length=255), nullable=False),
        sa.Column("to_state_summary", sa.String(length=255), nullable=False),
        sa.Column("risk_delta", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("posture_delta", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("evidence_references", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
    )
    op.create_index("ix_state_transitions_tenant_ts", "security_state_transitions", ["tenant_id", "timestamp"])

    op.create_table(
        "attack_trajectories",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("incident_id", sa.Uuid(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("current_stage", sa.String(length=100), nullable=False),
        sa.Column("observed_stages", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("predicted_next_stages", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("evidence_event_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_trajectories_tenant_incident", "attack_trajectories", ["tenant_id", "incident_id"])

    op.create_table(
        "attack_graph_snapshots",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("incident_id", sa.Uuid(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True),
        sa.Column("nodes", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("edges", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("graph_metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_graph_snapshots_tenant_id", "attack_graph_snapshots", ["tenant_id"])

    op.create_table(
        "organizational_security_memory",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("category", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("tags", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("evidence_references", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.8"),
        sa.Column("created_by", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_org_memory_tenant_cat", "organizational_security_memory", ["tenant_id", "category"])

    op.create_table(
        "threat_intel_indicators",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True),
        sa.Column("indicator_type", sa.String(length=50), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column("threat_type", sa.String(length=100), nullable=False),
        sa.Column("reputation_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("source_provider", sa.String(length=100), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("metadata_json", sa.JSON(), nullable=False, server_default="{}"),
    )
    op.create_index("ix_ti_indicators_type_val", "threat_intel_indicators", ["indicator_type", "value"])

    op.create_table(
        "continuous_adversary_schedules",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("scenario_id", sa.String(length=100), nullable=False),
        sa.Column("cron_expression", sa.String(length=100), nullable=False),
        sa.Column("environment", sa.String(length=50), nullable=False, server_default="LAB"),
        sa.Column("authorized_scope", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("target_allowlist", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("technique_allowlist", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_adv_schedules_tenant_id", "continuous_adversary_schedules", ["tenant_id"])

    op.create_table(
        "grc_control_mappings",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("framework", sa.String(length=50), nullable=False),
        sa.Column("control_id", sa.String(length=50), nullable=False),
        sa.Column("control_name", sa.String(length=255), nullable=False),
        sa.Column("domain", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="COMPLIANT"),
        sa.Column("evidence_references", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("gap_description", sa.Text(), nullable=True),
        sa.Column("risk_level", sa.String(length=50), nullable=False, server_default="LOW"),
        sa.Column("remediation_plan", sa.Text(), nullable=True),
        sa.Column("verification_method", sa.String(length=100), nullable=False, server_default="AUTOMATED"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_grc_tenant_framework", "grc_control_mappings", ["tenant_id", "framework"])

    op.create_table(
        "detection_improvement_candidates",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("incident_id", sa.Uuid(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("mitre_techniques", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("proposed_rule_yaml", sa.Text(), nullable=False),
        sa.Column("test_results", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="OPEN"),
        sa.Column("reviewed_by", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_candidates_tenant_id", "detection_improvement_candidates", ["tenant_id"])


def downgrade() -> None:
    pass
