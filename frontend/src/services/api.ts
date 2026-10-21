import {
  Alert,
  Asset,
  AuthResponse,
  Incident,
  SecurityEvent,
  Tenant,
  User,
} from "../types";

const API_BASE = "/api/v1";

class ApiService {
  private token: string | null = null;

  constructor() {
    this.token = localStorage.getItem("aegis_access_token");
  }

  setToken(token: string | null) {
    this.token = token;
    if (token) {
      localStorage.setItem("aegis_access_token", token);
    } else {
      localStorage.removeItem("aegis_access_token");
    }
  }

  getToken(): string | null {
    return this.token || localStorage.getItem("aegis_access_token");
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(options.headers as Record<string, string>),
    };

    const token = this.getToken();
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    const response = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      let errorMessage = `HTTP error ${response.status}`;
      try {
        const errorJson = await response.json();
        errorMessage = errorJson.detail || errorJson.error || errorMessage;
      } catch {
        // Fallback to status text
      }
      throw new Error(errorMessage);
    }

    return response.json() as Promise<T>;
  }

  // Health
  async getHealth(): Promise<{ status: string; service: string; version: string; database: string }> {
    return this.request("/health");
  }

  // Auth
  async register(data: {
    organization_name: string;
    email: string;
    password: string;
    role?: string;
  }): Promise<AuthResponse> {
    const res = await this.request<AuthResponse>("/auth/register", {
      method: "POST",
      body: JSON.stringify(data),
    });
    this.setToken(res.access_token);
    return res;
  }

  async login(credentials: { email: string; password: string }): Promise<AuthResponse> {
    const res = await this.request<AuthResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify(credentials),
    });
    this.setToken(res.access_token);
    return res;
  }

  async getMe(): Promise<User> {
    return this.request<User>("/auth/me");
  }

  logout() {
    this.setToken(null);
  }

  // Tenant
  async getMyTenant(): Promise<Tenant> {
    return this.request<Tenant>("/tenants/me");
  }

  // Assets
  async getAssets(): Promise<Asset[]> {
    return this.request<Asset[]>("/assets");
  }

  async createAsset(asset: {
    hostname: string;
    ip_address: string;
    asset_type?: string;
    criticality?: string;
    environment?: string;
  }): Promise<Asset> {
    return this.request<Asset>("/assets", {
      method: "POST",
      body: JSON.stringify(asset),
    });
  }

  // Events
  async getEvents(): Promise<SecurityEvent[]> {
    return this.request<SecurityEvent[]>("/events");
  }

  async ingestEvent(event: {
    source: string;
    event_type: string;
    severity?: string;
    source_ip?: string;
    username?: string;
    hostname?: string;
    raw_event: Record<string, any>;
  }): Promise<SecurityEvent> {
    return this.request<SecurityEvent>("/events", {
      method: "POST",
      body: JSON.stringify(event),
    });
  }

  // Alerts
  async getAlerts(): Promise<Alert[]> {
    return this.request<Alert[]>("/alerts");
  }

  // Incidents
  async getIncidents(): Promise<Incident[]> {
    return this.request<Incident[]>("/incidents");
  }

  async getIncidentById(id: string): Promise<Incident> {
    return this.request<Incident>(`/incidents/${id}`);
  }

  async createIncident(incident: {
    title: string;
    description: string;
    severity?: string;
    risk_score?: number;
    confidence?: number;
    status?: string;
  }): Promise<Incident> {
    return this.request<Incident>("/incidents", {
      method: "POST",
      body: JSON.stringify(incident),
    });
  }

  async getIncidentTimeline(incidentId: string): Promise<import("../types").TimelineItem[]> {
    return this.request<import("../types").TimelineItem[]>(`/incidents/${incidentId}/timeline`);
  }

  // Detection Rules
  async getDetectionRules(): Promise<import("../types").DetectionRule[]> {
    return this.request<import("../types").DetectionRule[]>("/rules");
  }

  async createDetectionRule(rule: Partial<import("../types").DetectionRule>): Promise<import("../types").DetectionRule> {
    return this.request<import("../types").DetectionRule>("/rules", {
      method: "POST",
      body: JSON.stringify(rule),
    });
  }

  async updateDetectionRule(ruleId: string, updates: Partial<import("../types").DetectionRule>): Promise<import("../types").DetectionRule> {
    return this.request<import("../types").DetectionRule>(`/rules/${ruleId}`, {
      method: "PATCH",
      body: JSON.stringify(updates),
    });
  }

  // Detections
  async getDetections(): Promise<import("../types").DetectionResult[]> {
    return this.request<import("../types").DetectionResult[]>("/detections");
  }

  // Phase 3: Investigation
  async investigateIncident(
    incidentId: string,
    forceRefresh = true,
    analystNotes?: string,
  ): Promise<import("../types").Investigation> {
    return this.request<import("../types").Investigation>(`/incidents/${incidentId}/investigate`, {
      method: "POST",
      body: JSON.stringify({ force_refresh: forceRefresh, analyst_notes: analystNotes }),
    });
  }

  async getInvestigation(incidentId: string): Promise<import("../types").Investigation> {
    return this.request<import("../types").Investigation>(`/incidents/${incidentId}/investigation`);
  }

  async getIncidentRecommendations(incidentId: string): Promise<import("../types").ActionRecommendation[]> {
    return this.request<import("../types").ActionRecommendation[]>(`/incidents/${incidentId}/recommendations`);
  }

  // Phase 3: Actions & Playbooks
  async getActions(incidentId?: string): Promise<import("../types").ActionRequest[]> {
    const query = incidentId ? `?incident_id=${incidentId}` : "";
    return this.request<import("../types").ActionRequest[]>(`/actions${query}`);
  }

  async createAction(data: {
    incident_id: string;
    action_type: string;
    target_entity: string;
    target_type: string;
    playbook_id: string;
    investigation_id?: string;
  }): Promise<import("../types").ActionRequest> {
    return this.request<import("../types").ActionRequest>("/actions", {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  async approveAction(actionId: string, reason?: string): Promise<import("../types").ActionRequest> {
    return this.request<import("../types").ActionRequest>(`/actions/${actionId}/approve`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    });
  }

  async rejectAction(actionId: string, reason: string): Promise<import("../types").ActionRequest> {
    return this.request<import("../types").ActionRequest>(`/actions/${actionId}/reject`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    });
  }

  async executeAction(actionId: string): Promise<import("../types").ActionRequest> {
    return this.request<import("../types").ActionRequest>(`/actions/${actionId}/execute`, {
      method: "POST",
    });
  }

  async getActionVerification(actionId: string): Promise<any> {
    return this.request<any>(`/actions/${actionId}/verification`);
  }

  // Phase 3: L2 Escalation
  async escalateIncident(
    incidentId: string,
    reason: string,
    urgency = "HIGH",
  ): Promise<import("../types").L2Escalation> {
    return this.request<import("../types").L2Escalation>(`/incidents/${incidentId}/escalate`, {
      method: "POST",
      body: JSON.stringify({ reason, urgency }),
    });
  }

  async getIncidentEscalation(incidentId: string): Promise<import("../types").L2Escalation> {
    return this.request<import("../types").L2Escalation>(`/incidents/${incidentId}/escalation`);
  }

  // Phase 4: Adversary Validation (AegisRed)
  async getAssessments(status?: string): Promise<import("../types").AdversaryAssessment[]> {
    const query = status ? `?status=${status}` : "";
    return this.request<import("../types").AdversaryAssessment[]>(`/adversary/assessments${query}`);
  }

  async getAssessment(id: string): Promise<import("../types").AdversaryAssessment> {
    return this.request<import("../types").AdversaryAssessment>(`/adversary/assessments/${id}`);
  }

  async createAssessment(data: {
    name: string;
    description?: string;
    environment: string;
    scenario: string;
    authorized_scope: import("../types").AuthorizedScope;
  }): Promise<import("../types").AdversaryAssessment> {
    return this.request<import("../types").AdversaryAssessment>("/adversary/assessments", {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  async authorizeAssessment(id: string, scope?: any): Promise<import("../types").AdversaryAssessment> {
    return this.request<import("../types").AdversaryAssessment>(`/adversary/assessments/${id}/authorize`, {
      method: "POST",
      body: JSON.stringify(scope ? { authorized_scope: scope } : {}),
    });
  }

  async startAssessment(id: string): Promise<import("../types").AssessmentResult> {
    return this.request<import("../types").AssessmentResult>(`/adversary/assessments/${id}/start`, {
      method: "POST",
    });
  }

  async cancelAssessment(id: string): Promise<import("../types").AdversaryAssessment> {
    return this.request<import("../types").AdversaryAssessment>(`/adversary/assessments/${id}/cancel`, {
      method: "POST",
    });
  }

  async getAssessmentResults(id: string): Promise<import("../types").AssessmentResult[]> {
    return this.request<import("../types").AssessmentResult[]>(`/adversary/assessments/${id}/results`);
  }

  // Phase 4: Continuous Security Improvement & Gaps
  async getGaps(): Promise<import("../types").DetectionGapReport[]> {
    return this.request<import("../types").DetectionGapReport[]>("/security-improvement/gaps");
  }

  async getCoverage(): Promise<import("../types").MitreCoverageItem[]> {
    return this.request<import("../types").MitreCoverageItem[]>("/security-improvement/coverage");
  }

  async getPosture(): Promise<import("../types").SecurityPostureReport> {
    return this.request<import("../types").SecurityPostureReport>("/security-improvement/posture");
  }

  async getTuningRecommendations(): Promise<any[]> {
    return this.request<any[]>("/security-improvement/recommendations");
  }

  async getFindings(status?: string, severity?: string): Promise<import("../types").SecurityFinding[]> {
    const params = new URLSearchParams();
    if (status) params.append("status", status);
    if (severity) params.append("severity", severity);
    const query = params.toString() ? `?${params.toString()}` : "";
    return this.request<import("../types").SecurityFinding[]>(`/security-improvement/findings${query}`);
  }

  async getFinding(id: string): Promise<import("../types").SecurityFinding> {
    return this.request<import("../types").SecurityFinding>(`/security-improvement/findings/${id}`);
  }

  async remediateFinding(
    findingId: string,
    data: { proposed_change: string; change_type: string; details?: any },
  ): Promise<import("../types").RemediationAction> {
    return this.request<import("../types").RemediationAction>(`/security-improvement/findings/${findingId}/remediate`, {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  async approveRemediation(remediationId: string): Promise<import("../types").RemediationAction> {
    return this.request<import("../types").RemediationAction>(
      `/security-improvement/remediations/${remediationId}/approve`,
      {
        method: "POST",
      },
    );
  }

  async retestFinding(findingId: string, simulateRegression = false): Promise<any> {
    const query = simulateRegression ? "?simulate_regression_failure=true" : "";
    return this.request<any>(`/security-improvement/findings/${findingId}/retest${query}`, {
      method: "POST",
    });
  }
}

export const api = new ApiService();
