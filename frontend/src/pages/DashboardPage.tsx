import React from "react";
import {
  AlertTriangle,
  Server,
  Activity,
  Bell,
  ShieldCheck,
  Zap,
  ArrowRight,
} from "lucide-react";
import { Alert, Asset, Incident, SecurityEvent, User } from "../types";
import { MetricCard } from "../components/MetricCard";
import { StatusBadge } from "../components/StatusBadge";

interface DashboardPageProps {
  user: User;
  incidents: Incident[];
  assets: Asset[];
  events: SecurityEvent[];
  alerts: Alert[];
  onNavigateTab: (tab: any) => void;
  onRefresh: () => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  user: _user,
  incidents,
  assets,
  events,
  alerts,
  onNavigateTab,
  onRefresh,
}) => {
  const criticalCount = incidents.filter((i) => i.severity === "CRITICAL" || i.severity === "HIGH").length;
  const openIncidents = incidents.filter((i) => i.status !== "RESOLVED" && i.status !== "CLOSED").length;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.75rem" }}>
      {/* Welcome & Live Status Header */}
      <div
        className="glass-panel glow-cyan"
        style={{
          padding: "1.5rem 1.75rem",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          background: "linear-gradient(135deg, rgba(15, 23, 42, 0.8) 0%, rgba(6, 182, 212, 0.08) 100%)",
        }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.25rem" }}>
            <span style={{ fontSize: "1.25rem", fontWeight: 700, color: "#f8fafc" }}>
              Security Operations Center
            </span>
            <span style={{ color: "#38bdf8", fontSize: "0.9rem" }}>• Evidence Engine</span>
          </div>
          <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)" }}>
            Real-time adversary validation and tenant-isolated detection active.
          </p>
        </div>

        <div style={{ display: "flex", gap: "0.75rem" }}>
          <button onClick={onRefresh} className="btn-secondary" style={{ fontSize: "0.8rem" }}>
            <Zap size={14} />
            <span>Sync Telemetry</span>
          </button>
          <button
            onClick={() => onNavigateTab("events")}
            className="btn-primary"
            style={{ fontSize: "0.8rem" }}
          >
            <span>Ingest Telemetry</span>
            <ArrowRight size={14} />
          </button>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
          gap: "1.25rem",
        }}
      >
        <MetricCard
          title="Critical / High Incidents"
          value={criticalCount}
          subtitle={`${openIncidents} total active incidents requiring response`}
          icon={<AlertTriangle size={22} />}
          accent={criticalCount > 0 ? "rose" : "emerald"}
        />
        <MetricCard
          title="Monitored Assets"
          value={assets.length}
          subtitle="Servers, firewalls & workstations"
          icon={<Server size={22} />}
          accent="cyan"
        />
        <MetricCard
          title="Ingested Events"
          value={events.length}
          subtitle="Real-time telemetry event stream"
          icon={<Activity size={22} />}
          accent="violet"
        />
        <MetricCard
          title="Detection Alerts"
          value={alerts.length}
          subtitle="Correlated rule detections"
          icon={<Bell size={22} />}
          accent="emerald"
        />
      </div>

      {/* Dual Column: Active Incidents & Live Telemetry Stream */}
      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: "1.5rem" }}>
        {/* Incidents Table */}
        <div className="glass-panel" style={{ padding: "1.5rem", display: "flex", flexDirection: "column", gap: "1rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h2 style={{ fontSize: "1rem", fontWeight: 600, color: "#f8fafc" }}>
              Active Security Incidents
            </h2>
            <button
              onClick={() => onNavigateTab("incidents")}
              style={{ background: "none", border: "none", color: "#38bdf8", cursor: "pointer", fontSize: "0.8rem" }}
            >
              View all ({incidents.length}) →
            </button>
          </div>

          {incidents.length === 0 ? (
            <div style={{ textAlign: "center", padding: "2.5rem 1rem", color: "var(--text-muted)" }}>
              <ShieldCheck size={36} style={{ color: "#10b981", margin: "0 auto 0.5rem" }} />
              <p style={{ fontSize: "0.875rem" }}>No active incidents in your tenant workspace.</p>
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
              {incidents.slice(0, 4).map((inc) => (
                <div
                  key={inc.id}
                  style={{
                    padding: "0.85rem 1rem",
                    borderRadius: "8px",
                    background: "rgba(15, 23, 42, 0.6)",
                    border: "1px solid var(--border-color)",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                  }}
                >
                  <div style={{ display: "flex", flexDirection: "column", gap: "0.25rem" }}>
                    <span style={{ fontSize: "0.875rem", fontWeight: 600, color: "#f8fafc" }}>
                      {inc.title}
                    </span>
                    <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                      Risk Score: {inc.risk_score} • Confidence: {Math.round(inc.confidence * 100)}%
                    </span>
                  </div>
                  <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                    <StatusBadge label={inc.severity} variant="severity" />
                    <StatusBadge label={inc.status} variant="status" />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Live Telemetry Stream */}
        <div className="glass-panel" style={{ padding: "1.5rem", display: "flex", flexDirection: "column", gap: "1rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <span className="live-indicator" />
              <h2 style={{ fontSize: "1rem", fontWeight: 600, color: "#f8fafc" }}>
                Live Ingestion Stream
              </h2>
            </div>
            <button
              onClick={() => onNavigateTab("events")}
              style={{ background: "none", border: "none", color: "#38bdf8", cursor: "pointer", fontSize: "0.8rem" }}
            >
              Stream ({events.length}) →
            </button>
          </div>

          {events.length === 0 ? (
            <div style={{ textAlign: "center", padding: "2.5rem 1rem", color: "var(--text-muted)" }}>
              <Activity size={36} style={{ color: "var(--text-muted)", margin: "0 auto 0.5rem" }} />
              <p style={{ fontSize: "0.875rem" }}>Awaiting incoming telemetry events.</p>
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem" }}>
              {events.slice(0, 5).map((evt) => (
                <div
                  key={evt.id}
                  style={{
                    padding: "0.7rem 0.85rem",
                    borderRadius: "6px",
                    background: "rgba(10, 15, 29, 0.7)",
                    border: "1px solid rgba(255, 255, 255, 0.05)",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                  }}
                >
                  <div style={{ display: "flex", flexDirection: "column", gap: "0.15rem" }}>
                    <span className="mono" style={{ fontSize: "0.8rem", color: "#38bdf8", fontWeight: 500 }}>
                      {evt.event_type}
                    </span>
                    <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>
                      Src: {evt.source} {evt.source_ip ? `(${evt.source_ip})` : ""}
                    </span>
                  </div>
                  <StatusBadge label={evt.severity} variant="severity" />
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
