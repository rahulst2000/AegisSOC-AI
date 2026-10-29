import {
  Alert,
  Asset,
  AuthResponse,
  Incident,
  SecurityEvent,
  Tenant,
  User,
} from "../types";

export class ApiError extends Error {
  status: number;
  data: any;
  isAuthError: boolean;
  isForbidden: boolean;
  isNotFound: boolean;
  isValidationError: boolean;
  isConflict: boolean;
  isServerError: boolean;

  constructor(status: number, message: string, data?: any) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.data = data;
    this.isAuthError = status === 401;
    this.isForbidden = status === 403;
    this.isNotFound = status === 404;
    this.isValidationError = status === 422;
    this.isConflict = status === 409;
    this.isServerError = status >= 500;
  }
}

export type AuthExpiredCallback = () => void;

const API_BASE = `${import.meta.env.VITE_API_URL || "http://localhost:8000"}/api/v1`;
class ApiService {
  private token: string | null = null;
  private refreshTokenVal: string | null = null;
  private isRefreshing: boolean = false;
  private authExpiredCallbacks: AuthExpiredCallback[] = [];

  constructor() {
    this.token = localStorage.getItem("aegis_access_token");
    this.refreshTokenVal = localStorage.getItem("aegis_refresh_token");
  }

  onAuthExpired(cb: AuthExpiredCallback) {
    this.authExpiredCallbacks.push(cb);
  }

  private notifyAuthExpired() {
    this.authExpiredCallbacks.forEach((cb) => {
      try {
        cb();
      } catch {
        // Safe callback execution
      }
    });
  }

  setToken(accessToken: string | null, refreshToken?: string | null) {
    this.token = accessToken;
    if (accessToken) {
      localStorage.setItem("aegis_access_token", accessToken);
    } else {
      localStorage.removeItem("aegis_access_token");
    }

    if (refreshToken !== undefined) {
      this.refreshTokenVal = refreshToken;
      if (refreshToken) {
        localStorage.setItem("aegis_refresh_token", refreshToken);
      } else {
        localStorage.removeItem("aegis_refresh_token");
      }
    }
  }

  getToken(): string | null {
    return this.token || localStorage.getItem("aegis_access_token");
  }

  getRefreshToken(): string | null {
    return this.refreshTokenVal || localStorage.getItem("aegis_refresh_token");
  }

  async refreshToken(): Promise<string | null> {
    const rfToken = this.getRefreshToken();
    if (!rfToken) {
      this.logout();
      return null;
    }
    try {
      const response = await fetch(`${API_BASE}/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: rfToken }),
      });
      if (!response.ok) {
        this.logout();
        this.notifyAuthExpired();
        return null;
      }
      const data = await response.json();
      this.setToken(data.access_token, data.refresh_token);
      return data.access_token;
    } catch {
      this.logout();
      this.notifyAuthExpired();
      return null;
    }
  }

  private async request<T>(endpoint: string, options: RequestInit = {}, retryOn401 = true): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(options.headers as Record<string, string>),
    };

    const token = this.getToken();
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    let response: Response;
    try {
      response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers,
      });
    } catch (netErr: any) {
      throw new ApiError(0, `Network failure or server unreachable: ${netErr.message || "Unknown error"}`);
    }

    // 401 handling with automatic token refresh attempt
    if (response.status === 401 && retryOn401 && endpoint !== "/auth/login" && endpoint !== "/auth/refresh") {
      if (!this.isRefreshing) {
        this.isRefreshing = true;
        try {
          const newToken = await this.refreshToken();
          this.isRefreshing = false;
          if (newToken) {
            return this.request<T>(endpoint, options, false);
          }
        } catch {
          this.isRefreshing = false;
        }
      }
      this.logout();
      this.notifyAuthExpired();
      throw new ApiError(401, "Authentication expired — please sign in again.");
    }

    if (!response.ok) {
      let errorMessage = `HTTP error ${response.status}`;
      let errorData: any = null;
      try {
        errorData = await response.json();
        errorMessage = errorData.detail || errorData.error || errorMessage;
      } catch {
        // Fallback to status text
      }
      throw new ApiError(response.status, errorMessage, errorData);
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
    this.setToken(res.access_token, res.refresh_token);
    return res;
  }

  async login(credentials: { email: string; password: string }): Promise<AuthResponse> {
    const res = await this.request<AuthResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify(credentials),
    });
    this.setToken(res.access_token, res.refresh_token);
    return res;
  }

  async getMe(): Promise<User> {
    return this.request<User>("/auth/me");
  }

  async logout(): Promise<void> {
    try {
      if (this.getToken()) {
        await this.request("/auth/logout", { method: "POST" }, false);
      }
    } catch {
      // Best-effort logout notification
    } finally {
      this.setToken(null, null);
    }
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

  // Global Threat Search
  async search(query: string): Promise<{
    query: string;
    total_matches: number;
    categories: {
      incidents: any[];
      events: any[];
      alerts: any[];
      assets: any[];
      detections: any[];
      threat_intelligence: any[];
    };
  }> {
    return this.request(`/search?q=${encodeURIComponent(query)}`);
  }

  // Events
  async getEvents(params?: {
    skip?: number;
    limit?: number;
    severity?: string;
    event_type?: string;
    source?: string;
    source_ip?: string;
    username?: string;
    search?: string;
  }): Promise<SecurityEvent[]> {
    if (!params) {
      return this.request<SecurityEvent[]>("/events");
    }
    const query = new URLSearchParams();
    if (params.skip !== undefined) query.set("skip", String(params.skip));
    if (params.limit !== undefined) query.set("limit", String(params.limit));
    if (params.severity) query.set("severity", params.severity);
    if (params.event_type) query.set("event_type", params.event_type);
    if (params.source) query.set("source", params.source);
    if (params.source_ip) query.set("source_ip", params.source_ip);
    if (params.username) query.set("username", params.username);
    if (params.search) query.set("search", params.search);
    const qs = query.toString();
    return this.request<SecurityEvent[]>(`/events${qs ? `?${qs}` : ""}`);
  }

  async getEventById(id: string): Promise<SecurityEvent> {
    return this.request<SecurityEvent>(`/events/${id}`);
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
  async getIncidents(params?: {
    skip?: number;
    limit?: number;
    severity?: string;
    status?: string;
    time_window?: string;
  }): Promise<Incident[]> {
    const query = new URLSearchParams();
    if (params?.skip !== undefined) query.set("skip", String(params.skip));
    if (params?.limit !== undefined) query.set("limit", String(params.limit));
    if (params?.severity && params.severity !== "ALL") query.set("severity", params.severity);
    if (params?.status && params.status !== "ALL") query.set("status", params.status);
    if (params?.time_window && params.time_window !== "ALL") query.set("time_window", params.time_window);
    const qs = query.toString();
    return this.request<Incident[]>(`/incidents${qs ? `?${qs}` : ""}`);
  }

  async getIncidentStats(params?: {
    severity?: string;
    status?: string;
    time_window?: string;
  }): Promise<{
    total_count: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    open_count: number;
    investigating_count: number;
    resolved_count: number;
    max_risk_score: number;
    posture_status: string;
    posture_color: string;
  }> {
    const query = new URLSearchParams();
    if (params?.severity && params.severity !== "ALL") query.set("severity", params.severity);
    if (params?.status && params.status !== "ALL") query.set("status", params.status);
    if (params?.time_window && params.time_window !== "ALL") query.set("time_window", params.time_window);
    const qs = query.toString();
    return this.request(`/incidents/stats${qs ? `?${qs}` : ""}`);
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

  // Phase 5B: Advanced Security Intelligence
  async getSecurityState(): Promise<import("../types").SecurityStateRecord> {
    return this.request<import("../types").SecurityStateRecord>("/intelligence/state");
  }

  async getAttackTrajectory(incidentId: string): Promise<import("../types").AttackTrajectoryReport> {
    return this.request<import("../types").AttackTrajectoryReport>(`/intelligence/trajectory/${incidentId}`);
  }

  async getAttackGraph(): Promise<import("../types").AttackGraphResponse> {
    return this.request<import("../types").AttackGraphResponse>("/intelligence/graph");
  }

  async getWhyNow(incidentId: string): Promise<import("../types").WhyNowReport> {
    return this.request<import("../types").WhyNowReport>(`/intelligence/why-now/${incidentId}`);
  }

  async runCounterfactual(incidentId: string, scenario: string): Promise<import("../types").CounterfactualResult> {
    return this.request<import("../types").CounterfactualResult>("/intelligence/counterfactual", {
      method: "POST",
      body: JSON.stringify({ incident_id: incidentId, simulated_action: scenario }),
    });
  }

  async getBlastRadius(assetId: string): Promise<import("../types").BlastRadiusReport> {
    return this.request<import("../types").BlastRadiusReport>(`/intelligence/digital-twin/blast-radius/${assetId}`);
  }

  async getThreatIntel(indicatorType: string, indicatorValue: string): Promise<import("../types").ThreatIntelResult> {
    return this.request<import("../types").ThreatIntelResult>("/intelligence/threat-intel/lookup", {
      method: "POST",
      body: JSON.stringify({ indicator_type: indicatorType, indicator_value: indicatorValue }),
    });
  }

  async getExecutivePosture(): Promise<import("../types").ExecutivePostureResponse> {
    return this.request<import("../types").ExecutivePostureResponse>("/intelligence/posture/executive");
  }

  async getGrcControls(): Promise<import("../types").GrcControlItem[]> {
    return this.request<import("../types").GrcControlItem[]>("/intelligence/grc/controls");
  }

  async getImprovementCandidates(): Promise<any[]> {
    return this.request<any[]>("/intelligence/continuous-improvement/candidates");
  }

  async reviewImprovementCandidate(candidateId: string, decision: "APPROVED" | "REJECTED"): Promise<any> {
    return this.request<any>(`/intelligence/continuous-improvement/candidates/${candidateId}/review`, {
      method: "POST",
      body: JSON.stringify({ decision }),
    });
  }
}

export const api = new ApiService();
