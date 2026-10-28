from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

revision: str = "002_complete_schema"
down_revision: str | None = "001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def reconcile_table(
    table_name: str,
    columns: list[sa.Column],
    indexes: list[tuple[str, list[str], bool]],
    existing_tables: set[str],
    inspector: sa.Inspector | None,
) -> None:
    """
    Reconciles a table against the actual database state:
    - If the table does not exist: creates the table and all its declared indexes.
    - If the table already exists: preserves existing data, verifies each column,
      adds only genuinely missing columns, and creates any missing indexes.
    """
    if table_name not in existing_tables:
        op.create_table(table_name, *columns)
        for idx_name, idx_cols, is_unique in indexes:
            op.create_index(idx_name, table_name, idx_cols, unique=is_unique)
        return

    # Table already exists in database - reconcile columns and indexes safely
    existing_cols: set[str] = set()
    existing_idx_names: set[str] = set()

    if inspector is not None:
        try:
            existing_cols = {col["name"] for col in inspector.get_columns(table_name)}
        except sa.exc.SQLAlchemyError:
            existing_cols = set()
        try:
            existing_idx_names = {idx["name"] for idx in inspector.get_indexes(table_name) if idx.get("name")}
        except sa.exc.SQLAlchemyError:
            existing_idx_names = set()

    missing_cols = [col for col in columns if col.name not in existing_cols]
    if missing_cols:
        with op.batch_alter_table(table_name) as batch_op:
            for col in missing_cols:
                batch_op.add_column(col)

    for idx_name, idx_cols, is_unique in indexes:
        if idx_name not in existing_idx_names:
            op.create_index(idx_name, table_name, idx_cols, unique=is_unique)


def upgrade() -> None:
    bind = op.get_bind()
    is_offline = context.is_offline_mode()

    if is_offline or bind is None:
        existing_tables: set[str] = set()
        inspector = None
    else:
        inspector = sa.inspect(bind)
        existing_tables = set(inspector.get_table_names())

    # 1. Reconcile extended columns on incidents table (from Phase 1 baseline)
    incident_extended_cols = [
        sa.Column("mitre_techniques", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("detection_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("affected_assets", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("affected_users", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("source_ips", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
    ]

    existing_incident_cols: set[str] = set()
    if inspector is not None and "incidents" in existing_tables:
        try:
            existing_incident_cols = {c["name"] for c in inspector.get_columns("incidents")}
        except sa.exc.SQLAlchemyError:
            existing_incident_cols = set()

    missing_incident_cols = [c for c in incident_extended_cols if c.name not in existing_incident_cols]
    if missing_incident_cols:
        with op.batch_alter_table("incidents") as batch_op:
            for c in missing_incident_cols:
                batch_op.add_column(c)

    # 2. Detection Rules table
    reconcile_table(
        table_name="detection_rules",
        columns=[
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
        ],
        indexes=[
            ("ix_detection_rules_rule_id", ["rule_id"], True),
            ("ix_detection_rules_tenant_id", ["tenant_id"], False),
            ("ix_detection_rules_name", ["name"], False),
            ("ix_detection_rules_enabled", ["enabled"], False),
            ("ix_detection_rules_severity", ["severity"], False),
            ("ix_detection_rules_tenant_enabled", ["tenant_id", "enabled"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )

    # 3. Detection Results table
    reconcile_table(
        table_name="detection_results",
        columns=[
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
        ],
        indexes=[
            ("ix_detection_results_tenant_id", ["tenant_id"], False),
            ("ix_detection_results_rule_id", ["rule_id"], False),
            ("ix_detection_results_dedup_hash", ["dedup_hash"], False),
            ("ix_detection_results_timestamp", ["timestamp"], False),
            ("ix_detection_results_tenant_timestamp", ["tenant_id", "timestamp"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )

    # 4. Investigations table
    reconcile_table(
        table_name="investigations",
        columns=[
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
        ],
        indexes=[
            ("ix_investigations_tenant_id", ["tenant_id"], False),
            ("ix_investigations_incident_id", ["incident_id"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )

    # 5. Investigation Hypotheses table
    reconcile_table(
        table_name="investigation_hypotheses",
        columns=[
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
        ],
        indexes=[
            ("ix_inv_hypotheses_tenant_id", ["tenant_id"], False),
            ("ix_inv_hypotheses_inv_id", ["investigation_id"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )

    # 6. Investigation Findings table
    reconcile_table(
        table_name="investigation_findings",
        columns=[
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
            sa.Column("investigation_id", sa.Uuid(as_uuid=True), sa.ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False),
            sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("finding", sa.Text(), nullable=False),
            sa.Column("status", sa.String(length=50), nullable=False, server_default="CONFIRMED"),
            sa.Column("evidence_ids", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("confidence", sa.Float(), nullable=False, server_default="0.9"),
            sa.Column("reasoning_summary", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        ],
        indexes=[
            ("ix_inv_findings_tenant_id", ["tenant_id"], False),
            ("ix_inv_findings_inv_id", ["investigation_id"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )

    # 7. Playbook Definitions table
    reconcile_table(
        table_name="playbook_definitions",
        columns=[
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
        ],
        indexes=[
            ("ix_playbooks_playbook_id", ["playbook_id"], True),
            ("ix_playbooks_tenant_id", ["tenant_id"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )

    # 8. Action Requests table
    reconcile_table(
        table_name="action_requests",
        columns=[
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
        ],
        indexes=[
            ("ix_actions_tenant_id", ["tenant_id"], False),
            ("ix_actions_incident_id", ["incident_id"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )

    # 9. Security Policies table
    reconcile_table(
        table_name="security_policies",
        columns=[
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
        ],
        indexes=[
            ("ix_policies_tenant_id", ["tenant_id"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )

    # 10. L2 Escalations table
    reconcile_table(
        table_name="l2_escalations",
        columns=[
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
        ],
        indexes=[
            ("ix_l2_escalations_tenant_id", ["tenant_id"], False),
            ("ix_l2_escalations_incident_id", ["incident_id"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )

    # 11. Adversary Assessments table
    reconcile_table(
        table_name="adversary_assessments",
        columns=[
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
        ],
        indexes=[
            ("ix_adversary_assessments_tenant_id", ["tenant_id"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )

    # 12. Adversary Assessment Results table
    reconcile_table(
        table_name="adversary_assessment_results",
        columns=[
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
        ],
        indexes=[
            ("ix_adv_results_tenant_id", ["tenant_id"], False),
            ("ix_adv_results_assessment_id", ["assessment_id"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )

    # 13. Security Findings table
    reconcile_table(
        table_name="security_findings",
        columns=[
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
        ],
        indexes=[
            ("ix_findings_tenant_id", ["tenant_id"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )

    # 14. Remediation Actions table
    reconcile_table(
        table_name="remediation_actions",
        columns=[
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
        ],
        indexes=[
            ("ix_remediation_tenant_id", ["tenant_id"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )

    # 15. Security State Snapshots table
    reconcile_table(
        table_name="security_state_snapshots",
        columns=[
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
        ],
        indexes=[
            ("ix_state_snapshots_tenant_ts", ["tenant_id", "timestamp"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )

    # 16. Security State Transitions table
    reconcile_table(
        table_name="security_state_transitions",
        columns=[
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
        ],
        indexes=[
            ("ix_state_transitions_tenant_ts", ["tenant_id", "timestamp"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )

    # 17. Attack Trajectories table
    reconcile_table(
        table_name="attack_trajectories",
        columns=[
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
            sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("incident_id", sa.Uuid(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
            sa.Column("current_stage", sa.String(length=100), nullable=False),
            sa.Column("observed_stages", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("predicted_next_stages", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"),
            sa.Column("evidence_event_ids", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        ],
        indexes=[
            ("ix_trajectories_tenant_incident", ["tenant_id", "incident_id"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )

    # 18. Attack Graph Snapshots table
    reconcile_table(
        table_name="attack_graph_snapshots",
        columns=[
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
            sa.Column("tenant_id", sa.Uuid(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("incident_id", sa.Uuid(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True),
            sa.Column("nodes", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("edges", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("graph_metadata", sa.JSON(), nullable=False, server_default="{}"),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        ],
        indexes=[
            ("ix_graph_snapshots_tenant_id", ["tenant_id"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )

    # 19. Organizational Security Memory table
    reconcile_table(
        table_name="organizational_security_memory",
        columns=[
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
        ],
        indexes=[
            ("ix_org_memory_tenant_cat", ["tenant_id", "category"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )

    # 20. Threat Intel Indicators table
    reconcile_table(
        table_name="threat_intel_indicators",
        columns=[
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
        ],
        indexes=[
            ("ix_ti_indicators_type_val", ["indicator_type", "value"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )

    # 21. Continuous Adversary Schedules table
    reconcile_table(
        table_name="continuous_adversary_schedules",
        columns=[
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
        ],
        indexes=[
            ("ix_adv_schedules_tenant_id", ["tenant_id"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )

    # 22. GRC Control Mappings table
    reconcile_table(
        table_name="grc_control_mappings",
        columns=[
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
        ],
        indexes=[
            ("ix_grc_tenant_framework", ["tenant_id", "framework"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )

    # 23. Detection Improvement Candidates table
    reconcile_table(
        table_name="detection_improvement_candidates",
        columns=[
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
        ],
        indexes=[
            ("ix_candidates_tenant_id", ["tenant_id"], False),
        ],
        existing_tables=existing_tables,
        inspector=inspector,
    )


def downgrade() -> None:
    pass
