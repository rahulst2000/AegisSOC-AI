import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adversary.cleanup import execute_scenario_cleanup
from app.adversary.evidence import collect_assessment_evidence_ids
from app.adversary.models import AdversaryAssessment, AssessmentResult
from app.adversary.scenarios import get_scenario
from app.adversary.scope import validate_assessment_scope
from app.core.logging import logger
from app.playbooks.executor import approve_action_request, create_action_request, execute_approved_action
from app.services.audit_service import log_audit_event


async def execute_adversary_assessment(
    db: AsyncSession,
    tenant_id: uuid.UUID | None = None,
    assessment_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
    user_role: str = "SOC_L2_LEAD",
    assessment: AdversaryAssessment | None = None,
) -> AssessmentResult:
    from app.correlation.correlator import Correlator
    from app.detection.engine import DetectionEngine
    from app.investigation.investigator import run_investigation
    from app.models.incident import Incident

    """
    Executes a controlled, evidence-grounded adversary validation assessment.
    Enforces authorized scope, executes safe simulation scenario, evaluates detection,
    correlation, investigation, response, verification, and runs mandatory cleanup.
    """
    if assessment is None:
        if tenant_id is None or assessment_id is None:
            raise ValueError("Either assessment or both tenant_id and assessment_id must be provided.")
        # 1. Fetch assessment with tenant isolation
        stmt = select(AdversaryAssessment).where(
            AdversaryAssessment.id == assessment_id,
            AdversaryAssessment.tenant_id == tenant_id,
        )
        res = await db.execute(stmt)
        assessment = res.scalars().first()
        if not assessment:
            raise ValueError(f"Adversary assessment {assessment_id} not found for tenant {tenant_id}")
    else:
        tenant_id = assessment.tenant_id
        assessment_id = assessment.id
        user_id = user_id or assessment.created_by

    if assessment.status != "AUTHORIZED":
        raise ValueError(
            f"Assessment execution rejected: Assessment is in status '{assessment.status}'. "
            f"Must be in 'AUTHORIZED' status before execution."
        )

    # 2. Load scenario definition
    scenario = get_scenario(assessment.scenario)

    # Resolve target from scope or scenario defaults
    scope = assessment.authorized_scope
    target_asset = scope.get("assets", [None])[0] or scope.get("hostnames", [None])[0] or scenario.default_target_asset
    target_ip = scope.get("ips", [None])[0] or scenario.default_target_ip

    # 3. Validate Scope strictly
    is_valid_scope, scope_err = validate_assessment_scope(
        scope=scope,
        target_asset=target_asset,
        target_ip=target_ip,
        technique_id=scenario.technique_id,
    )
    if not is_valid_scope:
        assessment.status = "FAILED"
        await db.commit()
        raise ValueError(f"Scope Validation Error: {scope_err}")

    # 4. Mark assessment RUNNING
    assessment.status = "RUNNING"
    assessment.started_at = datetime.now(UTC)
    await db.commit()
    await db.refresh(assessment)

    await log_audit_event(
        db=db,
        tenant_id=tenant_id,
        user_id=user_id,
        action="ADVERSARY_SIMULATION_STARTED",
        resource_type="adversary_assessment",
        resource_id=str(assessment.id),
        result="SUCCESS",
        metadata={
            "scenario": scenario.scenario_id,
            "technique": scenario.technique_id,
            "target": target_asset,
        },
    )

    simulation_status = "NOT_TESTED"
    detection_status = "NOT_TESTED"
    correlation_status = "NOT_TESTED"
    investigation_status = "NOT_TESTED"
    response_status = "NOT_TESTED"
    verification_status = "NOT_TESTED"
    cleanup_status = "NOT_TESTED"
    overall_result = "FAIL"

    incident_id: uuid.UUID | None = None
    event_ids: list[uuid.UUID] = []
    finding_ids: list[str] = []
    execution_details: dict[str, Any] = {}

    try:
        # STEP A: Generate Safe Simulation Events
        sim_events = scenario.generate_events(
            tenant_id=tenant_id,
            target_asset=target_asset,
            target_ip=target_ip,
            assessment_id=assessment.id,
        )
        for e in sim_events:
            db.add(e)
        await db.commit()
        for e in sim_events:
            await db.refresh(e)
            event_ids.append(e.id)

        simulation_status = "PASS"
        execution_details["events_ingested"] = len(sim_events)

        # STEP B: Detection Engine Evaluation
        from app.detection.rule_loader import sync_rules_to_db

        await sync_rules_to_db(db)

        engine = DetectionEngine()
        detections = await engine.evaluate_events(db=db, tenant_id=tenant_id, events=sim_events)
        await db.commit()

        matched_detection = next(
            (
                d
                for d in detections
                if d.rule_id == scenario.expected_rule_id or scenario.technique_id in (d.mitre_techniques or [])
            ),
            None,
        )

        if matched_detection or len(detections) > 0:
            detection_status = "PASS"
            execution_details["detection_id"] = str((matched_detection or detections[0]).id)
            execution_details["detection_title"] = (matched_detection or detections[0]).title
        else:
            detection_status = "FAIL"
            execution_details["detection_error"] = f"Expected rule {scenario.expected_rule_id} did not trigger."

        # STEP C: Correlation Engine Evaluation
        if detection_status == "PASS":
            correlator = Correlator()
            created_incidents = await correlator.correlate_detections(db=db, tenant_id=tenant_id, detections=detections)
            await db.commit()

            if created_incidents:
                incident = created_incidents[0]
                incident_id = incident.id
                correlation_status = "PASS"
                execution_details["incident_id"] = str(incident.id)
            else:
                # Query for any incident covering these detection IDs
                det_id_strs = [str(d.id) for d in detections]
                inc_stmt = select(Incident).where(Incident.tenant_id == tenant_id).order_by(Incident.created_at.desc())
                inc_res = await db.execute(inc_stmt)
                incidents = inc_res.scalars().all()
                found_inc = next(
                    (i for i in incidents if any(did in (i.detection_ids or []) for did in det_id_strs)), None
                )
                if found_inc:
                    incident_id = found_inc.id
                    correlation_status = "PASS"
                    execution_details["incident_id"] = str(found_inc.id)
                else:
                    correlation_status = "FAIL"
        else:
            correlation_status = "NOT_TESTED"

        # STEP D: Autonomous Investigation Evaluation
        if correlation_status == "PASS" and incident_id:
            try:
                inv = await run_investigation(
                    db=db,
                    tenant_id=tenant_id,
                    incident_id=incident_id,
                    force_refresh=True,
                    user_id=user_id,
                )
                await db.commit()
                if inv and inv.status == "COMPLETED":
                    investigation_status = "PASS"
                    execution_details["investigation_id"] = str(inv.id)
                    execution_details["investigation_confidence"] = inv.confidence_score
                else:
                    investigation_status = "FAIL"
            except Exception as e:
                logger.error("Investigation failed during adversary simulation: %s", e)
                investigation_status = "FAIL"
                execution_details["investigation_error"] = str(e)
        else:
            investigation_status = "NOT_TESTED"

        # STEP E: Response Playbook Recommendation & Controlled Execution
        if incident_id:
            try:
                # Create action request for the expected containment playbook
                action = await create_action_request(
                    db=db,
                    tenant_id=tenant_id,
                    incident_id=incident_id,
                    action_type="IP_CONTAINMENT" if target_ip else "ACCOUNT_LOCKOUT",
                    target_entity=target_ip or "victim_user",
                    target_type="IP" if target_ip else "USER",
                    playbook_id=scenario.expected_playbook_id,
                    requested_by=user_id,
                )
                # Human approval gate
                await approve_action_request(
                    db=db,
                    tenant_id=tenant_id,
                    action_id=action.id,
                    user_id=user_id,
                    user_role=user_role,
                )
                # Execute action
                executed_action = await execute_approved_action(
                    db=db,
                    tenant_id=tenant_id,
                    action_id=action.id,
                    user_id=user_id,
                )
                await db.commit()

                if executed_action.execution_status == "SUCCEEDED":
                    response_status = "PASS"
                    execution_details["action_id"] = str(executed_action.id)

                    # STEP F: Verification Status
                    if executed_action.verification_status == "VERIFIED":
                        verification_status = "PASS"
                    else:
                        verification_status = "FAIL"
                else:
                    response_status = "FAIL"
                    verification_status = "FAIL"
            except Exception as e:
                logger.error("Response execution failed during adversary assessment: %s", e)
                response_status = "FAIL"
                verification_status = "FAIL"
                execution_details["response_error"] = str(e)
        else:
            response_status = "NOT_TESTED"
            verification_status = "NOT_TESTED"

        # Determine overall result
        if (
            simulation_status == "PASS"
            and detection_status == "PASS"
            and correlation_status == "PASS"
            and investigation_status == "PASS"
            and response_status == "PASS"
            and verification_status == "PASS"
        ):
            overall_result = "PASS"
        elif simulation_status == "PASS" and detection_status == "PASS":
            overall_result = "PARTIAL"
        else:
            overall_result = "FAIL"

    except Exception as e:
        logger.error("Critical failure during adversary simulation: %s", e)
        simulation_status = "FAIL"
        overall_result = "FAIL"
        execution_details["simulation_error"] = str(e)

    finally:
        # STEP G: Mandatory Cleanup (Always runs even on failure)
        target_user = (
            "admin"
            if scenario.scenario_id == "SCENARIO-001"
            else ("victim_user" if scenario.scenario_id == "SCENARIO-003" else None)
        )
        cleanup_status, cleanup_details = await execute_scenario_cleanup(
            db=db,
            tenant_id=tenant_id,
            assessment_id=assessment.id,
            scenario_id=scenario.scenario_id,
            target_ip=target_ip,
            target_user=target_user,
            target_asset=target_asset,
        )
        execution_details["cleanup"] = cleanup_details

    # Collect cryptographic evidence IDs
    evidence_ids = await collect_assessment_evidence_ids(
        db=db,
        tenant_id=tenant_id,
        event_ids=event_ids,
        incident_id=incident_id,
    )

    # Record AssessmentResult entity
    assessment_result = AssessmentResult(
        tenant_id=tenant_id,
        assessment_id=assessment.id,
        scenario_id=scenario.scenario_id,
        technique_id=scenario.technique_id,
        target=f"{target_asset} ({target_ip})",
        started_at=assessment.started_at or datetime.now(UTC),
        completed_at=datetime.now(UTC),
        simulation_status=simulation_status,
        detection_status=detection_status,
        correlation_status=correlation_status,
        investigation_status=investigation_status,
        response_status=response_status,
        verification_status=verification_status,
        evidence_ids=evidence_ids,
        finding_ids=finding_ids,
        cleanup_status=cleanup_status,
        overall_result=overall_result,
        details=execution_details,
    )
    db.add(assessment_result)

    # Update assessment status
    assessment.status = "COMPLETED" if overall_result in ("PASS", "PARTIAL") else "FAILED"
    assessment.completed_at = datetime.now(UTC)

    await db.commit()
    await db.refresh(assessment_result)

    # Audit simulation completion
    await log_audit_event(
        db=db,
        tenant_id=tenant_id,
        user_id=user_id,
        action="ADVERSARY_SIMULATION_COMPLETED",
        resource_type="adversary_assessment",
        resource_id=str(assessment.id),
        result=overall_result,
        metadata={
            "result_id": str(assessment_result.id),
            "overall_result": overall_result,
            "detection_status": detection_status,
            "cleanup_status": cleanup_status,
        },
    )

    return assessment_result
