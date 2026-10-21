export type Role =
  | "TENANT_ADMIN"
  | "SOC_L1"
  | "SOC_L2"
  | "SECURITY_ENGINEER"
  | "GRC_ANALYST"
  | "SECURITY_MANAGER"
  | "CISO";

export interface Tenant {
  id: string;
  name: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface User {
  id: string;
  tenant_id: string;
  email: string;
  role: Role;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  user: User;
}

export interface Asset {
  id: string;
  tenant_id: string;
  hostname: string;
  ip_address: string;
  asset_type: string;
  criticality: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  environment: "PRODUCTION" | "STAGING" | "DEVELOPMENT" | "LAB";
  status: "ACTIVE" | "OFFLINE" | "DECOMMISSIONED";
  created_at: string;
  updated_at: string;
}

export interface SecurityEvent {
  id: string;
  tenant_id: string;
  timestamp: string;
  source: string;
  event_type: string;
  severity: "INFORMATIONAL" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  source_ip?: string;
  username?: string;
  hostname?: string;
  raw_event: Record<string, any>;
  normalized_event: Record<string, any>;
  created_at: string;
}

export interface Alert {
  id: string;
  tenant_id: string;
  event_id?: string;
  detection_rule: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  confidence: number;
  status: "OPEN" | "IN_TRIAGE" | "RESOLVED" | "FALSE_POSITIVE";
  created_at: string;
}

export interface Incident {
  id: string;
  tenant_id: string;
  title: string;
  description: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  risk_score: number;
  confidence: number;
  status: "OPEN" | "INVESTIGATING" | "CONTAINED" | "RESOLVED" | "CLOSED";
  mitre_techniques?: string[];
  detection_ids?: string[];
  affected_assets?: string[];
  affected_users?: string[];
  source_ips?: string[];
  first_seen?: string | null;
  last_seen?: string | null;
  created_at: string;
  updated_at: string;
}

export interface DetectionRule {
  id: string;
  rule_id: string;
  tenant_id?: string | null;
  name: string;
  description: string;
  version: string;
  enabled: boolean;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  confidence: number;
  event_types: string[];
  conditions: Record<string, any>;
  mitre_tactics: string[];
  mitre_techniques: string[];
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface DetectionResult {
  id: string;
  tenant_id: string;
  rule_id: string;
  title: string;
  description: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  confidence: number;
  event_ids: string[];
  mitre_tactics: string[];
  mitre_techniques: string[];
  detection_count: number;
  previous_occurrences: number;
  false_positive_status: "UNREVIEWED" | "CONFIRMED_TRUE_POSITIVE" | "FALSE_POSITIVE" | "BENIGN_KNOWN";
  analyst_feedback: Record<string, any>;
  dedup_hash?: string;
  timestamp: string;
}

export interface TimelineItem {
  timestamp: string;
  item_type: "DETECTION" | "SECURITY_EVENT" | "EVIDENCE";
  id: string;
  title: string;
  description: string;
  severity: string;
  source?: string | null;
  mitre_techniques: string[];
  metadata: Record<string, any>;
}

export interface AuditLog {
  id: string;
  tenant_id: string;
  user_id?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  result: "SUCCESS" | "FAILURE" | "DENIED";
  timestamp: string;
  metadata: Record<string, any>;
}

export interface InvestigationFinding {
  id: string;
  investigation_id: string;
  tenant_id: string;
  finding: string;
  status: "CONFIRMED" | "LIKELY" | "UNKNOWN" | "DISPROVED";
  evidence_ids: string[];
  confidence: number;
  reasoning_summary: string;
  created_at: string;
}

export interface InvestigationHypothesis {
  id: string;
  investigation_id: string;
  tenant_id: string;
  hypothesis_id: string;
  title: string;
  description: string;
  status: "CONFIRMED" | "LIKELY" | "UNKNOWN" | "DISPROVED";
  confidence: number;
  evidence_ids: string[];
  supporting_evidence: string[];
  contradicting_evidence: string[];
  unknowns: string[];
  created_at: string;
}

export interface Investigation {
  id: string;
  incident_id: string;
  tenant_id: string;
  status: "IN_PROGRESS" | "COMPLETED" | "ESCALATED";
  executive_summary: string;
  attack_chain: string[];
  known_facts: string[];
  unknowns: string[];
  recommended_next_steps: string[];
  l1_decision: string;
  l2_escalation_recommended: boolean;
  risk_score: number;
  confidence_score: number;
  created_at: string;
  updated_at: string;
  hypotheses: InvestigationHypothesis[];
  findings: InvestigationFinding[];
}

export interface ActionRecommendation {
  action_type: string;
  target_entity: string;
  target_type: string;
  playbook_id: string;
  reason: string;
  risk_score: number;
  confidence: number;
  evidence_ids: string[];
}

export interface ActionRequest {
  id: string;
  incident_id: string;
  investigation_id?: string | null;
  tenant_id: string;
  action_type: string;
  target_entity: string;
  target_type: string;
  playbook_id: string;
  requested_by?: string | null;
  requested_at: string;
  policy_evaluation: Record<string, any>;
  required_approval_role: string;
  approval_status: "REQUESTED" | "APPROVED" | "REJECTED";
  approved_by?: string | null;
  approved_at?: string | null;
  rejection_reason?: string | null;
  execution_status: "PENDING" | "EXECUTING" | "SUCCEEDED" | "FAILED";
  verification_status: "PENDING" | "VERIFIED" | "VERIFICATION_FAILED";
  evidence_before: Record<string, any>;
  evidence_after: Record<string, any>;
  result: Record<string, any>;
  error?: string | null;
  timestamp: string;
}

export interface L2Escalation {
  id: string;
  incident_id: string;
  investigation_id?: string | null;
  tenant_id: string;
  escalated_by?: string | null;
  escalated_at: string;
  reason: string;
  urgency: "NORMAL" | "HIGH" | "CRITICAL";
  status: "OPEN" | "ACKNOWLEDGED" | "RESOLVED";
  l2_package: Record<string, any>;
}

// ==========================================
// Phase 4: Adversary Validation & Improvement
// ==========================================

export interface AuthorizedScope {
  environment: "LAB";
  assets: string[];
  hostnames?: string[];
  ips?: string[];
  allowed_techniques: string[];
  prohibited_techniques: string[];
  expires_at: string;
  authorized_by?: string | null;
}

export interface AssessmentResult {
  id: string;
  tenant_id: string;
  assessment_id: string;
  scenario_id: string;
  technique_id: string;
  target: string;
  started_at: string;
  completed_at: string;
  simulation_status: "PASS" | "FAIL" | "PARTIAL" | "NOT_TESTED";
  detection_status: "PASS" | "FAIL" | "PARTIAL" | "NOT_TESTED";
  correlation_status: "PASS" | "FAIL" | "PARTIAL" | "NOT_TESTED";
  investigation_status: "PASS" | "FAIL" | "PARTIAL" | "NOT_TESTED";
  response_status: "PASS" | "FAIL" | "PARTIAL" | "NOT_TESTED";
  verification_status: "PASS" | "FAIL" | "PARTIAL" | "NOT_TESTED";
  evidence_ids: string[];
  finding_ids: string[];
  cleanup_status: "CLEANED" | "FAILED" | "NOT_TESTED";
  overall_result: "PASS" | "FAIL" | "PARTIAL" | "NOT_TESTED";
  details: Record<string, any>;
}

export interface AdversaryAssessment {
  id: string;
  tenant_id: string;
  name: string;
  description?: string | null;
  environment: "LAB";
  scenario: string;
  status: "DRAFT" | "AUTHORIZED" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED";
  authorized_scope: AuthorizedScope;
  created_by?: string | null;
  authorized_by?: string | null;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  results?: AssessmentResult[];
}

export interface RemediationAction {
  id: string;
  tenant_id: string;
  finding_id: string;
  proposed_change: string;
  change_type: "RULE_UPDATE" | "POLICY_UPDATE" | "ASSET_CONFIG";
  approval_status: "PENDING" | "APPROVED" | "REJECTED";
  approved_by?: string | null;
  applied_at?: string | null;
  retest_assessment_id?: string | null;
  details: Record<string, any>;
  created_at: string;
}

export interface SecurityFinding {
  id: string;
  tenant_id: string;
  assessment_id?: string | null;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  title: string;
  description: string;
  asset: string;
  technique: string;
  evidence_ids: string[];
  root_cause: string;
  business_impact: string;
  recommendation: string;
  priority: "P1" | "P2" | "P3" | "P4";
  owner: string;
  status:
    | "OPEN"
    | "UNDER_REMEDIATION"
    | "PARTIALLY_REMEDIATED"
    | "REMEDIATION_FAILED"
    | "VERIFIED"
    | "CLOSED"
    | "REOPENED";
  created_at: string;
  updated_at: string;
  remediations: RemediationAction[];
}

export interface DetectionGapReport {
  gap_type: "DETECTION_GAP" | "CORRELATION_GAP" | "INVESTIGATION_GAP" | "RESPONSE_GAP" | "VERIFICATION_GAP";
  technique_id: string;
  target: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  summary: string;
  recommendation: string;
  assessment_id: string;
  scenario_id: string;
}

export interface MitreCoverageItem {
  technique_id: string;
  technique_name: string;
  tactics: string[];
  simulation: "PASS" | "FAIL" | "PARTIAL" | "NOT_TESTED";
  detection: "PASS" | "FAIL" | "PARTIAL" | "NOT_TESTED";
  correlation: "PASS" | "FAIL" | "PARTIAL" | "NOT_TESTED";
  investigation: "PASS" | "FAIL" | "PARTIAL" | "NOT_TESTED";
  response: "PASS" | "FAIL" | "PARTIAL" | "NOT_TESTED";
  verification: "PASS" | "FAIL" | "PARTIAL" | "NOT_TESTED";
  overall: "PASS" | "FAIL" | "PARTIAL" | "NOT_TESTED";
}

export interface SecurityPostureScore {
  category: string;
  tested_techniques: number;
  successful_detections: number;
  coverage_percentage: number;
  status: string;
}

export interface SecurityPostureReport {
  test_coverage_percentage: number;
  overall_posture_score: number;
  categories: SecurityPostureScore[];
  total_findings_open: number;
  total_findings_remediated: number;
  remediation_success_rate: number;
}

