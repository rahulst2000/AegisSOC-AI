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
}

export const api = new ApiService();
