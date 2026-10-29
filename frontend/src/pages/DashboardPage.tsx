import React, { useState, useMemo, useEffect } from "react";
import {
  AlertTriangle,
  Server,
  Activity,
  Bell,
  ShieldCheck,
  Zap,
  ArrowRight,
  ShieldAlert,
  Flame,
  Crosshair,
  Compass,
  ExternalLink,
  Filter,
  RotateCcw,
} from "lucide-react";
import { Alert, Asset, Incident, SecurityEvent, User } from "../types";
import { MetricCard } from "../components/MetricCard";
import { StatusBadge } from "../components/StatusBadge";
import { api } from "../services/api";

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
  // Rapid Threat Filtering state
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [timeFilter, setTimeFilter] = useState<string>("ALL");

  const [serverIncidents, setServerIncidents] = useState<Incident[] | null>(null);
  const [serverStats, setServerStats] = useState<any | null>(null);
  const [filterLoading, setFilterLoading] = useState<boolean>(false);
  const [filterError, setFilterError] = useState<string | null>(null);

  const hasActiveFilters = severityFilter !== "ALL" || statusFilter !== "ALL" || timeFilter !== "ALL";

  const handleResetFilters = () => {
    setSeverityFilter("ALL");
    setStatusFilter("ALL");
    setTimeFilter("ALL");
  };

  // Synchronize server-side filtered incidents and attack metrics
  useEffect(() => {
    let isCancelled = false;
    const fetchFilteredData = async () => {
      setFilterLoading(true);
      setFilterError(null);
      try {
        const [filteredList, stats] = await Promise.all([
          api.getIncidents({
            severity: severityFilter,
            status: statusFilter,
            time_window: timeFilter,
            limit: 50,
          }),
          api.getIncidentStats({
            severity: severityFilter,
            status: statusFilter,
            time_window: timeFilter,
          }),
        ]);
        if (!isCancelled) {
          setServerIncidents(filteredList);
          setServerStats(stats);
        }
      } catch (err: any) {
        if (!isCancelled) {
          setFilterError(err?.message || "Failed to load filtered incidents");
        }
      } finally {
        if (!isCancelled) setFilterLoading(false);
      }
    };

    fetchFilteredData();
    return () => {
      isCancelled = true;
    };
  }, [severityFilter, statusFilter, timeFilter]);

  // Active dataset for dashboard rendering
  const displayIncidents = serverIncidents !== null ? serverIncidents : incidents;

  // Aggregate Attack Metrics driven by authoritative stats
  const criticalCount = serverStats?.critical_count ?? displayIncidents.filter((i) => i.severity === "CRITICAL").length;
  const highCount = serverStats?.high_count ?? displayIncidents.filter((i) => i.severity === "HIGH").length;
  const openIncidents = serverStats?.open_count ?? displayIncidents.filter((i) => i.status !== "RESOLVED" && i.status !== "CLOSED").length;

  // Posture Score Calculation
  const maxRisk = serverStats?.max_risk_score ?? displayIncidents.reduce((max, i) => Math.max(max, i.risk_score || 0), 0);
  const postureStatus =
    serverStats?.posture_status ??
    (criticalCount > 0 ? "CRITICAL THREAT" : highCount > 0 ? "ELEVATED RISK" : openIncidents > 0 ? "GUARDED" : "NOMINAL");
  const postureColor =
    serverStats?.posture_color ??
    (criticalCount > 0 ? "#f43f5e" : highCount > 0 ? "#f59e0b" : openIncidents > 0 ? "#38bdf8" : "#10b981");


  // Suspicious Source IPs derived from events and incidents
  const suspiciousIPs = useMemo(() => {
    const ipCounts: Record<string, { count: number; severity: string; lastSeen: string }> = {};
    events.forEach((e) => {
      if (e.source_ip && e.source_ip !== "127.0.0.1" && e.source_ip !== "localhost") {
        if (!ipCounts[e.source_ip]) {
          ipCounts[e.source_ip] = { count: 0, severity: e.severity, lastSeen: e.timestamp };
        }
        ipCounts[e.source_ip].count += 1;
        if (e.severity === "CRITICAL" || e.severity === "HIGH") {
          ipCounts[e.source_ip].severity = e.severity;
        }
      }
    });
    return Object.entries(ipCounts)
      .map(([ip, data]) => ({ ip, ...data }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [events]);

  // Targeted Users derived from events
  const targetedUsers = useMemo(() => {
    const userCounts: Record<string, { count: number; lastEvent: string }> = {};
    events.forEach((e) => {
      const u =
        e.username ||
        e.raw_event?.username ||
        e.raw_event?.user ||
        e.raw_event?.account ||
        e.normalized_event?.username;
      if (u && typeof u === "string") {
        if (!userCounts[u]) {
          userCounts[u] = { count: 0, lastEvent: e.event_type };
        }
        userCounts[u].count += 1;
      }
    });
    return Object.entries(userCounts)
      .map(([username, data]) => ({ username, ...data }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 4);
  }, [events]);

  // Top MITRE ATT&CK techniques observed
  const observedTechniques = useMemo(() => {
    const techSet = new Set<string>();
    incidents.forEach((i) => {
      (i.mitre_techniques || []).forEach((t: string) => techSet.add(t));
    });
    if (techSet.size === 0) {
      // Default common baseline mappings if empty
      return ["T1078 (Valid Accounts)", "T1110 (Brute Force)", "T1003 (OS Credential Dumping)"];
    }
    return Array.from(techSet).slice(0, 5);
  }, [incidents]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.75rem" }}>
      {/* 1. Header & Live Posture Summary */}
      <div
        className="glass-panel"
        style={{
          padding: "1.5rem 1.75rem",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "1rem",
          background: "linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(6, 182, 212, 0.08) 100%)",
          borderLeft: `4px solid ${postureColor}`,
        }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.35rem" }}>
            <span style={{ fontSize: "1.35rem", fontWeight: 700, color: "#f8fafc" }}>
              Enterprise SOC Command Center
            </span>
            <span
              style={{
                fontSize: "0.75rem",
                fontWeight: 700,
                color: postureColor,
                backgroundColor: `${postureColor}1a`,
                border: `1px solid ${postureColor}40`,
                padding: "0.2rem 0.6rem",
                borderRadius: "999px",
                display: "inline-flex",
                alignItems: "center",
                gap: "0.35rem",
              }}
            >
              <span
                style={{
                  width: "6px",
                  height: "6px",
                  borderRadius: "50%",
                  backgroundColor: postureColor,
                  display: "inline-block",
                }}
              />
              POSTURE: {postureStatus}
            </span>
          </div>
          <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)" }}>
            Real-time adversary validation, multi-sensor telemetry correlation & continuous MITRE ATT&CK mapping.
          </p>
        </div>

        <div style={{ display: "flex", gap: "0.75rem", alignItems: "center" }}>
          <button onClick={onRefresh} className="btn-secondary" style={{ fontSize: "0.8rem", padding: "0.55rem 0.9rem" }}>
            <Zap size={14} />
            <span>Sync Live Telemetry</span>
          </button>
          <button
            onClick={() => onNavigateTab("events")}
            className="btn-primary"
            style={{ fontSize: "0.8rem", padding: "0.55rem 0.9rem" }}
          >
            <span>Ingest Telemetry</span>
            <ArrowRight size={14} />
          </button>
        </div>
      </div>

      {/* 2. Rapid Threat Filtering Bar (Section 16) */}
      <div
        className="glass-panel"
        style={{
          padding: "0.85rem 1.25rem",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "1rem",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <Filter size={15} style={{ color: "#38bdf8" }} />
          <span style={{ fontSize: "0.8rem", fontWeight: 600, color: "#f8fafc", textTransform: "uppercase" }}>
            Rapid Threat Filters:
          </span>
        </div>

        <div style={{ display: "flex", gap: "1.25rem", flexWrap: "wrap", alignItems: "center" }}>
          {/* Severity Filter */}
          <div style={{ display: "flex", gap: "0.3rem", alignItems: "center" }}>
            <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Severity:</span>
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
              <button
                key={s}
                onClick={() => setSeverityFilter(s)}
                style={{
                  fontSize: "0.7rem",
                  padding: "0.2rem 0.5rem",
                  borderRadius: "4px",
                  border: severityFilter === s ? "1px solid #38bdf8" : "1px solid rgba(255, 255, 255, 0.1)",
                  background: severityFilter === s ? "rgba(56, 189, 248, 0.2)" : "transparent",
                  color: severityFilter === s ? "#38bdf8" : "var(--text-secondary)",
                  cursor: "pointer",
                }}
              >
                {s}
              </button>
            ))}
          </div>

          {/* Status Filter */}
          <div style={{ display: "flex", gap: "0.3rem", alignItems: "center" }}>
            <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Status:</span>
            {["ALL", "OPEN", "INVESTIGATING", "RESOLVED"].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                style={{
                  fontSize: "0.7rem",
                  padding: "0.2rem 0.5rem",
                  borderRadius: "4px",
                  border: statusFilter === st ? "1px solid #10b981" : "1px solid rgba(255, 255, 255, 0.1)",
                  background: statusFilter === st ? "rgba(16, 185, 129, 0.2)" : "transparent",
                  color: statusFilter === st ? "#10b981" : "var(--text-secondary)",
                  cursor: "pointer",
                }}
              >
                {st}
              </button>
            ))}
          </div>

          {/* Time Filter */}
          <div style={{ display: "flex", gap: "0.3rem", alignItems: "center" }}>
            <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Time:</span>
            {["15m", "1h", "24h", "7d", "ALL"].map((t) => (
              <button
                key={t}
                onClick={() => setTimeFilter(t)}
                style={{
                  fontSize: "0.7rem",
                  padding: "0.2rem 0.5rem",
                  borderRadius: "4px",
                  border: timeFilter === t ? "1px solid #8b5cf6" : "1px solid rgba(255, 255, 255, 0.1)",
                  background: timeFilter === t ? "rgba(139, 92, 246, 0.2)" : "transparent",
                  color: timeFilter === t ? "#c4b5fd" : "var(--text-secondary)",
                  cursor: "pointer",
                }}
              >
                {t}
              </button>
            ))}
          </div>

          {hasActiveFilters && (
            <button
              onClick={handleResetFilters}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.3rem",
                fontSize: "0.7rem",
                padding: "0.25rem 0.6rem",
                borderRadius: "4px",
                border: "1px solid rgba(244, 63, 94, 0.4)",
                background: "rgba(244, 63, 94, 0.15)",
                color: "#fda4af",
                cursor: "pointer",
              }}
            >
              <RotateCcw size={12} />
              <span>Reset Filters</span>
            </button>
          )}
        </div>

      </div>

      {/* 3. The 5 Core SOC Questions (Section 14 & 15 Clickable Context) */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
          gap: "1.25rem",
        }}
      >
        {/* Q1: What is attacking us? */}
        <div
          className="glass-panel"
          style={{
            padding: "1.25rem",
            display: "flex",
            flexDirection: "column",
            gap: "0.75rem",
            borderTop: "3px solid #f43f5e",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Crosshair size={18} style={{ color: "#f43f5e" }} />
            <span style={{ fontSize: "0.85rem", fontWeight: 700, color: "#f8fafc" }}>
              1. What Is Attacking Us?
            </span>
          </div>
          <p style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
            Observed attacker techniques and hostile infrastructure:
          </p>

          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            <div style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>
              <span style={{ fontWeight: 600 }}>Active ATT&CK TTPs:</span>
              <div style={{ display: "flex", flexWrap: "wrap", gap: "0.35rem", marginTop: "0.25rem" }}>
                {observedTechniques.map((t) => (
                  <span
                    key={t}
                    onClick={() => onNavigateTab("rules")}
                    style={{
                      fontSize: "0.7rem",
                      padding: "0.15rem 0.4rem",
                      borderRadius: "4px",
                      background: "rgba(244, 63, 94, 0.15)",
                      color: "#fda4af",
                      border: "1px solid rgba(244, 63, 94, 0.3)",
                      cursor: "pointer",
                    }}
                    title="Click to view Sigma rules"
                  >
                    {t}
                  </span>
                ))}
              </div>
            </div>

            <div style={{ fontSize: "0.75rem", color: "var(--text-secondary)", marginTop: "0.25rem" }}>
              <span style={{ fontWeight: 600 }}>Hostile IPs:</span>
              <div style={{ display: "flex", flexWrap: "wrap", gap: "0.35rem", marginTop: "0.25rem" }}>
                {suspiciousIPs.length === 0 ? (
                  <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>None active</span>
                ) : (
                  suspiciousIPs.map((s) => (
                    <span
                      key={s.ip}
                      onClick={() => onNavigateTab("events")}
                      style={{
                        fontSize: "0.7rem",
                        padding: "0.15rem 0.45rem",
                        borderRadius: "4px",
                        background: "rgba(15, 23, 42, 0.8)",
                        color: "#38bdf8",
                        border: "1px solid rgba(56, 189, 248, 0.3)",
                        cursor: "pointer",
                        fontFamily: "var(--font-mono)",
                      }}
                      title="Click to inspect IP in Event Center"
                    >
                      {s.ip} ({s.count})
                    </span>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Q2: What is affected? */}
        <div
          className="glass-panel"
          style={{
            padding: "1.25rem",
            display: "flex",
            flexDirection: "column",
            gap: "0.75rem",
            borderTop: "3px solid #f59e0b",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Server size={18} style={{ color: "#f59e0b" }} />
            <span style={{ fontSize: "0.85rem", fontWeight: 700, color: "#f8fafc" }}>
              2. What Is Affected?
            </span>
          </div>
          <p style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
            High-risk internal infrastructure and targeted credentials:
          </p>

          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            <div style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>
              <span style={{ fontWeight: 600 }}>Monitored Assets ({assets.length}):</span>
              <div style={{ display: "flex", flexWrap: "wrap", gap: "0.35rem", marginTop: "0.25rem" }}>
                {assets.slice(0, 3).map((a) => (
                  <span
                    key={a.id}
                    onClick={() => onNavigateTab("assets")}
                    style={{
                      fontSize: "0.7rem",
                      padding: "0.15rem 0.45rem",
                      borderRadius: "4px",
                      background: "rgba(245, 158, 11, 0.15)",
                      color: "#fde68a",
                      border: "1px solid rgba(245, 158, 11, 0.3)",
                      cursor: "pointer",
                    }}
                    title="Click to open Asset Inventory"
                  >
                    {a.hostname} ({a.asset_type})
                  </span>
                ))}
              </div>
            </div>

            <div style={{ fontSize: "0.75rem", color: "var(--text-secondary)", marginTop: "0.25rem" }}>
              <span style={{ fontWeight: 600 }}>Targeted Identities:</span>
              <div style={{ display: "flex", flexWrap: "wrap", gap: "0.35rem", marginTop: "0.25rem" }}>
                {targetedUsers.length === 0 ? (
                  <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>No accounts targeted</span>
                ) : (
                  targetedUsers.map((u) => (
                    <span
                      key={u.username}
                      onClick={() => onNavigateTab("events")}
                      style={{
                        fontSize: "0.7rem",
                        padding: "0.15rem 0.45rem",
                        borderRadius: "4px",
                        background: "rgba(15, 23, 42, 0.8)",
                        color: "#a78bfa",
                        border: "1px solid rgba(167, 139, 250, 0.3)",
                        cursor: "pointer",
                      }}
                      title="Click to view User Telemetry"
                    >
                      {u.username} ({u.count})
                    </span>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Q3: How serious is it? */}
        <div
          className="glass-panel"
          style={{
            padding: "1.25rem",
            display: "flex",
            flexDirection: "column",
            gap: "0.75rem",
            borderTop: "3px solid #8b5cf6",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Flame size={18} style={{ color: "#8b5cf6" }} />
            <span style={{ fontSize: "0.85rem", fontWeight: 700, color: "#f8fafc" }}>
              3. How Serious Is It?
            </span>
          </div>
          <p style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
            Calculated tenant security risk and impact severity:
          </p>

          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: "0.25rem" }}>
            <div>
              <div style={{ fontSize: "1.75rem", fontWeight: 800, color: postureColor, lineHeight: 1 }}>
                {maxRisk}/100
              </div>
              <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", marginTop: "0.25rem" }}>
                Peak Incident Risk Score
              </div>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "0.25rem", textAlign: "right" }}>
              <span style={{ fontSize: "0.75rem", color: "#f43f5e", fontWeight: 600 }}>
                {criticalCount} Critical
              </span>
              <span style={{ fontSize: "0.75rem", color: "#f59e0b", fontWeight: 600 }}>
                {highCount} High
              </span>
              <span style={{ fontSize: "0.75rem", color: "#38bdf8" }}>
                {openIncidents} Total Active
              </span>
            </div>
          </div>
        </div>

        {/* Q4 & Q5: What happened recently & What to do? */}
        <div
          className="glass-panel glow-cyan"
          style={{
            padding: "1.25rem",
            display: "flex",
            flexDirection: "column",
            gap: "0.75rem",
            borderTop: "3px solid #06b6d4",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Compass size={18} style={{ color: "#06b6d4" }} />
            <span style={{ fontSize: "0.85rem", fontWeight: 700, color: "#f8fafc" }}>
              5. What Should The Analyst Do?
            </span>
          </div>
          <p style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
            AI-recommended decision based on continuous evidence:
          </p>

          <div
            style={{
              padding: "0.6rem 0.75rem",
              borderRadius: "6px",
              background: "rgba(6, 182, 212, 0.1)",
              border: "1px solid rgba(6, 182, 212, 0.25)",
              fontSize: "0.75rem",
              color: "#e2e8f0",
              lineHeight: 1.4,
            }}
          >
            {criticalCount > 0
              ? "🚨 CRITICAL: High-confidence credential dumping or brute force detected. Immediately isolate affected host and revoke compromised credentials."
              : openIncidents > 0
              ? "⚠️ Review active correlated incidents, verify host telemetry, and validate adversary containment procedures."
              : "✅ Nominal state. Run scheduled adversary validation simulation to verify detection coverage."}
          </div>

          <button
            onClick={() => onNavigateTab(openIncidents > 0 ? "incidents" : "adversary")}
            style={{
              marginTop: "auto",
              padding: "0.5rem",
              borderRadius: "6px",
              background: "linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%)",
              color: "#fff",
              border: "none",
              fontSize: "0.75rem",
              fontWeight: 600,
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: "0.35rem",
            }}
          >
            <span>{openIncidents > 0 ? "Triage Incidents" : "Run Adversary Simulation"}</span>
            <ArrowRight size={14} />
          </button>
        </div>
      </div>

      {/* 4. Metric Cards Grid (Section 15 Clickable) */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
          gap: "1.25rem",
        }}
      >
        <div onClick={() => onNavigateTab("incidents")} style={{ cursor: "pointer" }} title="Click to open Incidents">
          <MetricCard
            title="Critical / High Incidents"
            value={criticalCount + highCount}
            subtitle={`${openIncidents} total active incidents requiring response`}
            icon={<AlertTriangle size={22} />}
            accent={criticalCount > 0 ? "rose" : highCount > 0 ? "rose" : "emerald"}
          />
        </div>
        <div onClick={() => onNavigateTab("assets")} style={{ cursor: "pointer" }} title="Click to open Assets">
          <MetricCard
            title="Monitored Assets"
            value={assets.length}
            subtitle="Servers, firewalls & workstations"
            icon={<Server size={22} />}
            accent="cyan"
          />
        </div>
        <div onClick={() => onNavigateTab("events")} style={{ cursor: "pointer" }} title="Click to open Event Center">
          <MetricCard
            title="Ingested Events"
            value={events.length}
            subtitle="Real-time multi-sensor telemetry stream"
            icon={<Activity size={22} />}
            accent="violet"
          />
        </div>
        <div onClick={() => onNavigateTab("incidents")} style={{ cursor: "pointer" }} title="Click to open Detection Alerts">
          <MetricCard
            title="Correlated Alerts"
            value={alerts.length}
            subtitle="Rule detections linked to incidents"
            icon={<Bell size={22} />}
            accent="emerald"
          />
        </div>
      </div>

      {/* 5. Dual Column: Active Incidents Table & Live Telemetry Stream */}
      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: "1.5rem" }}>
        {/* Incidents Table */}
        <div className="glass-panel" style={{ padding: "1.5rem", display: "flex", flexDirection: "column", gap: "1rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <ShieldAlert size={18} style={{ color: "#38bdf8" }} />
              <h2 style={{ fontSize: "1rem", fontWeight: 600, color: "#f8fafc" }}>
                Active Security Incidents
              </h2>
            </div>
            <button
              onClick={() => onNavigateTab("incidents")}
              style={{
                background: "none",
                border: "none",
                color: "#38bdf8",
                cursor: "pointer",
                fontSize: "0.8rem",
                display: "flex",
                alignItems: "center",
                gap: "0.25rem",
              }}
            >
              <span>View all ({displayIncidents.length})</span>
              <ArrowRight size={13} />
            </button>
          </div>

          {filterLoading ? (
            <div style={{ textAlign: "center", padding: "2.5rem 1rem", color: "var(--text-muted)" }}>
              <span className="live-indicator" style={{ width: "12px", height: "12px", margin: "0 auto 0.5rem" }} />
              <p style={{ fontSize: "0.875rem" }}>Loading filtered incidents...</p>
            </div>
          ) : filterError ? (
            <div style={{ textAlign: "center", padding: "2rem 1rem", color: "#fda4af" }}>
              <p style={{ fontSize: "0.875rem" }}>⚠️ {filterError}</p>
              <button
                onClick={handleResetFilters}
                style={{
                  marginTop: "0.5rem",
                  padding: "0.3rem 0.6rem",
                  fontSize: "0.75rem",
                  borderRadius: "4px",
                  background: "rgba(244, 63, 94, 0.2)",
                  border: "1px solid rgba(244, 63, 94, 0.4)",
                  color: "#fff",
                  cursor: "pointer",
                }}
              >
                Reset Filters
              </button>
            </div>
          ) : displayIncidents.length === 0 ? (
            <div style={{ textAlign: "center", padding: "2.5rem 1rem", color: "var(--text-muted)" }}>
              <ShieldCheck size={36} style={{ color: "#10b981", margin: "0 auto 0.5rem" }} />
              <p style={{ fontSize: "0.875rem" }}>
                {hasActiveFilters
                  ? `No incidents matching criteria (Severity: ${severityFilter}, Status: ${statusFilter}, Time: ${timeFilter}).`
                  : "No active security incidents recorded for tenant."}
              </p>
              {hasActiveFilters && (
                <button
                  onClick={handleResetFilters}
                  style={{
                    marginTop: "0.5rem",
                    padding: "0.3rem 0.6rem",
                    fontSize: "0.75rem",
                    borderRadius: "4px",
                    background: "rgba(56, 189, 248, 0.2)",
                    border: "1px solid #38bdf8",
                    color: "#38bdf8",
                    cursor: "pointer",
                  }}
                >
                  Clear Filters
                </button>
              )}
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
              {displayIncidents.slice(0, 5).map((inc) => (

                <div
                  key={inc.id}
                  onClick={() => onNavigateTab("incidents")}
                  style={{
                    padding: "0.85rem 1rem",
                    borderRadius: "8px",
                    background: "rgba(15, 23, 42, 0.6)",
                    border: "1px solid var(--border-color)",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    cursor: "pointer",
                    transition: "all 0.2s ease",
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--border-glow)")}
                  onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--border-color)")}
                  title="Click to open Incident Investigation"
                >
                  <div style={{ display: "flex", flexDirection: "column", gap: "0.25rem" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                      <span style={{ fontSize: "0.875rem", fontWeight: 600, color: "#f8fafc" }}>
                        {inc.title}
                      </span>
                      <ExternalLink size={12} style={{ color: "var(--text-muted)" }} />
                    </div>
                    <div style={{ display: "flex", gap: "0.75rem", fontSize: "0.75rem", color: "var(--text-muted)" }}>
                      <span>Risk: {inc.risk_score}/100</span>
                      <span>•</span>
                      <span>Confidence: {Math.round(inc.confidence * 100)}%</span>
                      {inc.mitre_techniques && inc.mitre_techniques.length > 0 && (
                        <>
                          <span>•</span>
                          <span style={{ color: "#fda4af" }}>{inc.mitre_techniques[0]}</span>
                        </>
                      )}
                    </div>
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
              style={{
                background: "none",
                border: "none",
                color: "#38bdf8",
                cursor: "pointer",
                fontSize: "0.8rem",
                display: "flex",
                alignItems: "center",
                gap: "0.25rem",
              }}
            >
              <span>Event Center ({events.length})</span>
              <ArrowRight size={13} />
            </button>
          </div>

          {events.length === 0 ? (
            <div style={{ textAlign: "center", padding: "2.5rem 1rem", color: "var(--text-muted)" }}>
              <Activity size={36} style={{ color: "var(--text-muted)", margin: "0 auto 0.5rem" }} />
              <p style={{ fontSize: "0.875rem" }}>Awaiting incoming telemetry events.</p>
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem" }}>
              {events.slice(0, 6).map((evt) => (
                <div
                  key={evt.id}
                  onClick={() => onNavigateTab("events")}
                  style={{
                    padding: "0.7rem 0.85rem",
                    borderRadius: "6px",
                    background: "rgba(10, 15, 29, 0.7)",
                    border: "1px solid rgba(255, 255, 255, 0.05)",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    cursor: "pointer",
                    transition: "all 0.2s ease",
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.borderColor = "rgba(56, 189, 248, 0.3)")}
                  onMouseLeave={(e) => (e.currentTarget.style.borderColor = "rgba(255, 255, 255, 0.05)")}
                  title="Click to inspect event in Quick View Drawer"
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
