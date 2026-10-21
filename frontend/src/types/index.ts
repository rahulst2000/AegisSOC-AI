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
  created_at: string;
  updated_at: string;
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
