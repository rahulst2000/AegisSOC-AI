import React, { useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Copy,
  Plus,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  User,
  X,
} from "lucide-react";
import { SecurityEvent } from "../types";
import { StatusBadge } from "../components/StatusBadge";
import { api } from "../services/api";

interface EventsPageProps {
  events: SecurityEvent[];
  onRefresh: () => void;
  onNavigateTab?: (tab: string, context?: any) => void;
}

export const EventsPage: React.FC<EventsPageProps> = ({ events, onRefresh, onNavigateTab }) => {
  const [showModal, setShowModal] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [activeQuickViewTab, setActiveQuickViewTab] = useState<"OVERVIEW" | "RAW" | "NORMALIZED" | "ACTIONS">("OVERVIEW");

  // Ingestion form state
  const [source, setSource] = useState("CrowdStrike-EDR");
  const [eventType, setEventType] = useState("LSASS_MEMORY_ACCESS_ATTEMPT");
  const [severity, setSeverity] = useState("CRITICAL");
  const [sourceIp, setSourceIp] = useState("10.0.4.18");
  const [username, setUsername] = useState("svc_backup");
  const [hostname, setHostname] = useState("dc-primary.corp");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Live filter state
  const [searchFilter, setSearchFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [typeFilter, setTypeFilter] = useState<string>("ALL");
  const [sourceFilter, setSourceFilter] = useState<string>("ALL");
  const [timeFilter, setTimeFilter] = useState<string>("ALL");

  // Pagination state
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(15);

  // Quick Action notification state
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState(false);

  const handleIngest = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);

    try {
      await api.ingestEvent({
        source,
        event_type: eventType,
        severity,
        source_ip: sourceIp,
        username,
        hostname,
        raw_event: {
          ProcessName: eventType.includes("LSASS") ? "mimikatz.exe" : "powershell.exe",
          TargetProcess: eventType.includes("LSASS") ? "lsass.exe" : "explorer.exe",
          GrantedAccess: "0x1010",
          SourceIp: sourceIp,
          User: username,
        },
      });
      setShowModal(false);
      onRefresh();
    } catch (err: any) {
      setError(err.message || "Failed to ingest event");
    } finally {
      setSubmitting(false);
    }
  };

  // Derive distinct options for filters
  const distinctEventTypes = useMemo(() => {
    const set = new Set(events.map((e) => e.event_type));
    return Array.from(set).sort();
  }, [events]);

  const distinctSources = useMemo(() => {
    const set = new Set(events.map((e) => e.source));
    return Array.from(set).sort();
  }, [events]);

  // Apply filters
  const filteredEvents = useMemo(() => {
    return events.filter((evt) => {
      // 1. Text search
      if (searchFilter.trim()) {
        const q = searchFilter.toLowerCase();
        const matches =
          evt.event_type?.toLowerCase().includes(q) ||
          evt.source?.toLowerCase().includes(q) ||
          evt.source_ip?.toLowerCase().includes(q) ||
          evt.hostname?.toLowerCase().includes(q) ||
          evt.username?.toLowerCase().includes(q) ||
          evt.id?.toLowerCase().includes(q);
        if (!matches) return false;
      }

      // 2. Severity filter
      if (severityFilter !== "ALL" && evt.severity?.toUpperCase() !== severityFilter.toUpperCase()) {
        return false;
      }

      // 3. Type filter
      if (typeFilter !== "ALL" && evt.event_type !== typeFilter) {
        return false;
      }

      // 4. Source filter
      if (sourceFilter !== "ALL" && evt.source !== sourceFilter) {
        return false;
      }

      // 5. Time filter
      if (timeFilter !== "ALL") {
        const evtTime = new Date(evt.timestamp).getTime();
        const now = Date.now();
        const diffMs = now - evtTime;
        if (timeFilter === "15m" && diffMs > 15 * 60 * 1000) return false;
        if (timeFilter === "1h" && diffMs > 60 * 60 * 1000) return false;
        if (timeFilter === "24h" && diffMs > 24 * 60 * 60 * 1000) return false;
        if (timeFilter === "7d" && diffMs > 7 * 24 * 60 * 60 * 1000) return false;
      }

      return true;
    });
  }, [events, searchFilter, severityFilter, typeFilter, sourceFilter, timeFilter]);

  // Paginated slice
  const totalPages = Math.ceil(filteredEvents.length / pageSize) || 1;
  const paginatedEvents = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filteredEvents.slice(start, start + pageSize);
  }, [filteredEvents, page, pageSize]);

  // Reset page when filters change
  const handleFilterChange = (setter: (v: string) => void, val: string) => {
    setter(val);
    setPage(1);
  };

  const handleCopyId = (id: string) => {
    navigator.clipboard.writeText(id);
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 2000);
  };

  const triggerFeedback = (msg: string) => {
    setActionFeedback(msg);
    setTimeout(() => setActionFeedback(null), 3000);
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      {/* Page Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <h1 style={{ fontSize: "1.4rem", fontWeight: 700, color: "#f8fafc" }}>
              Telemetry & Security Event Center
            </h1>
            <span
              style={{
                fontSize: "0.75rem",
                padding: "0.15rem 0.5rem",
                borderRadius: "9999px",
                background: "rgba(6, 182, 212, 0.15)",
                color: "#38bdf8",
                fontWeight: 600,
              }}
            >
              {events.length} Events Ingested
            </span>
          </div>
          <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", marginTop: "0.2rem" }}>
            Normalized multi-sensor telemetry, identity signals, and real-time detection evidence stream.
          </p>
        </div>

        <div style={{ display: "flex", gap: "0.75rem" }}>
          <button onClick={onRefresh} className="btn-secondary" style={{ fontSize: "0.85rem" }}>
            <RefreshCw size={15} />
            <span>Refresh</span>
          </button>
          <button onClick={() => setShowModal(true)} className="btn-primary" style={{ fontSize: "0.85rem" }}>
            <Plus size={16} />
            <span>Ingest Telemetry</span>
          </button>
        </div>
      </div>

      {/* Multi-Dimensional Threat Filter Bar */}
      <div
        className="glass-panel"
        style={{
          padding: "1rem 1.25rem",
          display: "flex",
          flexWrap: "wrap",
          alignItems: "center",
          gap: "0.75rem",
          background: "rgba(10, 15, 29, 0.75)",
        }}
      >
        {/* Search */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.4rem",
            background: "rgba(15, 23, 42, 0.8)",
            border: "1px solid var(--border-color)",
            borderRadius: "6px",
            padding: "0.4rem 0.65rem",
            flex: "1 1 200px",
          }}
        >
          <Search size={14} style={{ color: "var(--text-muted)" }} />
          <input
            type="text"
            value={searchFilter}
            onChange={(e) => handleFilterChange(setSearchFilter, e.target.value)}
            placeholder="Filter by IP, User, Host, Type, Source..."
            style={{
              background: "none",
              border: "none",
              outline: "none",
              color: "#f8fafc",
              fontSize: "0.8rem",
              width: "100%",
            }}
          />
          {searchFilter && (
            <button
              onClick={() => handleFilterChange(setSearchFilter, "")}
              style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer", padding: 0 }}
            >
              <X size={13} />
            </button>
          )}
        </div>

        {/* Severity */}
        <div style={{ display: "flex", alignItems: "center", gap: "0.3rem" }}>
          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Severity:</span>
          <select
            value={severityFilter}
            onChange={(e) => handleFilterChange(setSeverityFilter, e.target.value)}
            style={{
              padding: "0.4rem 0.6rem",
              borderRadius: "6px",
              background: "rgba(15, 23, 42, 0.8)",
              border: "1px solid var(--border-color)",
              color: "#f8fafc",
              fontSize: "0.75rem",
            }}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFORMATIONAL">Informational</option>
          </select>
        </div>

        {/* Event Classification */}
        <div style={{ display: "flex", alignItems: "center", gap: "0.3rem" }}>
          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Classification:</span>
          <select
            value={typeFilter}
            onChange={(e) => handleFilterChange(setTypeFilter, e.target.value)}
            style={{
              padding: "0.4rem 0.6rem",
              borderRadius: "6px",
              background: "rgba(15, 23, 42, 0.8)",
              border: "1px solid var(--border-color)",
              color: "#f8fafc",
              fontSize: "0.75rem",
              maxWidth: "160px",
            }}
          >
            <option value="ALL">All Types</option>
            {distinctEventTypes.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>

        {/* Source Sensor */}
        <div style={{ display: "flex", alignItems: "center", gap: "0.3rem" }}>
          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Sensor:</span>
          <select
            value={sourceFilter}
            onChange={(e) => handleFilterChange(setSourceFilter, e.target.value)}
            style={{
              padding: "0.4rem 0.6rem",
              borderRadius: "6px",
              background: "rgba(15, 23, 42, 0.8)",
              border: "1px solid var(--border-color)",
              color: "#f8fafc",
              fontSize: "0.75rem",
              maxWidth: "140px",
            }}
          >
            <option value="ALL">All Sensors</option>
            {distinctSources.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>

        {/* Time Window */}
        <div style={{ display: "flex", alignItems: "center", gap: "0.3rem" }}>
          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Time:</span>
          <select
            value={timeFilter}
            onChange={(e) => handleFilterChange(setTimeFilter, e.target.value)}
            style={{
              padding: "0.4rem 0.6rem",
              borderRadius: "6px",
              background: "rgba(15, 23, 42, 0.8)",
              border: "1px solid var(--border-color)",
              color: "#f8fafc",
              fontSize: "0.75rem",
            }}
          >
            <option value="ALL">All Time</option>
            <option value="15m">Last 15m</option>
            <option value="1h">Last 1h</option>
            <option value="24h">Last 24h</option>
            <option value="7d">Last 7d</option>
          </select>
        </div>

        {/* Reset */}
        {(searchFilter || severityFilter !== "ALL" || typeFilter !== "ALL" || sourceFilter !== "ALL" || timeFilter !== "ALL") && (
          <button
            onClick={() => {
              setSearchFilter("");
              setSeverityFilter("ALL");
              setTypeFilter("ALL");
              setSourceFilter("ALL");
              setTimeFilter("ALL");
              setPage(1);
            }}
            style={{
              background: "none",
              border: "none",
              color: "#fb7185",
              cursor: "pointer",
              fontSize: "0.75rem",
              display: "flex",
              alignItems: "center",
              gap: "0.25rem",
            }}
          >
            <X size={13} />
            <span>Reset</span>
          </button>
        )}
      </div>

      {/* Action Toast Feedback */}
      {actionFeedback && (
        <div
          style={{
            padding: "0.75rem 1rem",
            borderRadius: "6px",
            background: "rgba(16, 185, 129, 0.15)",
            border: "1px solid rgba(16, 185, 129, 0.3)",
            color: "#34d399",
            fontSize: "0.85rem",
            display: "flex",
            alignItems: "center",
            gap: "0.5rem",
          }}
        >
          <CheckCircle2 size={16} />
          <span>{actionFeedback}</span>
        </div>
      )}

      {/* Events Table */}
      <div className="glass-panel" style={{ overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "0.875rem" }}>
          <thead>
            <tr
              style={{
                borderBottom: "1px solid var(--border-color)",
                background: "rgba(10, 15, 29, 0.7)",
                color: "var(--text-muted)",
                fontSize: "0.75rem",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
              }}
            >
              <th style={{ padding: "0.85rem 1.25rem" }}>Timestamp</th>
              <th style={{ padding: "0.85rem 1rem" }}>Classification</th>
              <th style={{ padding: "0.85rem 1rem" }}>Severity</th>
              <th style={{ padding: "0.85rem 1rem" }}>Source Sensor</th>
              <th style={{ padding: "0.85rem 1rem" }}>Source IP</th>
              <th style={{ padding: "0.85rem 1rem" }}>Target Host</th>
              <th style={{ padding: "0.85rem 1.25rem" }}>User</th>
              <th style={{ padding: "0.85rem 1rem", textAlign: "right" }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {paginatedEvents.length === 0 ? (
              <tr>
                <td colSpan={8} style={{ textAlign: "center", padding: "3rem 1rem", color: "var(--text-muted)" }}>
                  No security events matching current filter criteria.
                </td>
              </tr>
            ) : (
              paginatedEvents.map((evt) => (
                <tr
                  key={evt.id}
                  onClick={() => {
                    setSelectedEvent(evt);
                    setActiveQuickViewTab("OVERVIEW");
                  }}
                  style={{
                    borderBottom: "1px solid rgba(255, 255, 255, 0.04)",
                    cursor: "pointer",
                    transition: "background 0.15s ease",
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.backgroundColor = "rgba(6, 182, 212, 0.05)";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.backgroundColor = "transparent";
                  }}
                >
                  <td style={{ padding: "0.85rem 1.25rem", color: "var(--text-secondary)", fontSize: "0.8rem" }}>
                    {new Date(evt.timestamp).toLocaleTimeString()}
                  </td>
                  <td style={{ padding: "0.85rem 1rem" }} className="mono">
                    <span style={{ color: "#38bdf8", fontWeight: 500 }}>{evt.event_type}</span>
                  </td>
                  <td style={{ padding: "0.85rem 1rem" }}>
                    <StatusBadge label={evt.severity} variant="severity" />
                  </td>
                  <td style={{ padding: "0.85rem 1rem", color: "#f8fafc" }}>{evt.source}</td>
                  <td style={{ padding: "0.85rem 1rem" }} className="mono">
                    {evt.source_ip || "—"}
                  </td>
                  <td style={{ padding: "0.85rem 1rem" }}>{evt.hostname || "—"}</td>
                  <td style={{ padding: "0.85rem 1.25rem", color: "var(--text-secondary)" }}>
                    {evt.username || "—"}
                  </td>
                  <td style={{ padding: "0.85rem 1rem", textAlign: "right" }}>
                    <span
                      style={{
                        fontSize: "0.75rem",
                        color: "#06b6d4",
                        padding: "0.2rem 0.5rem",
                        borderRadius: "4px",
                        background: "rgba(6, 182, 212, 0.1)",
                      }}
                    >
                      Quick View →
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>

        {/* Pagination Bar */}
        {filteredEvents.length > 0 && (
          <div
            style={{
              padding: "0.75rem 1.25rem",
              borderTop: "1px solid var(--border-color)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              background: "rgba(10, 15, 29, 0.4)",
              fontSize: "0.8rem",
              color: "var(--text-secondary)",
            }}
          >
            <div>
              Showing {(page - 1) * pageSize + 1} to {Math.min(page * pageSize, filteredEvents.length)} of{" "}
              {filteredEvents.length} events
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setPage(1);
                }}
                style={{
                  padding: "0.25rem 0.5rem",
                  borderRadius: "4px",
                  background: "rgba(15, 23, 42, 0.8)",
                  border: "1px solid var(--border-color)",
                  color: "#f8fafc",
                  fontSize: "0.75rem",
                }}
              >
                <option value={10}>10 / page</option>
                <option value={15}>15 / page</option>
                <option value={25}>25 / page</option>
                <option value={50}>50 / page</option>
              </select>

              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="btn-secondary"
                style={{ padding: "0.25rem 0.65rem", fontSize: "0.75rem" }}
              >
                Previous
              </button>

              <span style={{ fontSize: "0.8rem", color: "#f8fafc" }}>
                Page {page} of {totalPages}
              </span>

              <button
                disabled={page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                className="btn-secondary"
                style={{ padding: "0.25rem 0.65rem", fontSize: "0.75rem" }}
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* EVENT QUICK VIEW MODAL / DRAWER (Section 12) */}
      {selectedEvent && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            backgroundColor: "rgba(0, 0, 0, 0.8)",
            backdropFilter: "blur(8px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 60,
            padding: "1.5rem",
          }}
        >
          <div
            className="glass-panel"
            style={{
              width: "100%",
              maxWidth: "800px",
              maxHeight: "90vh",
              overflowY: "auto",
              padding: "2rem",
              display: "flex",
              flexDirection: "column",
              gap: "1.5rem",
              background: "rgba(10, 15, 29, 0.98)",
              border: "1px solid rgba(6, 182, 212, 0.3)",
              boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.7)",
            }}
          >
            {/* Header */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
              <div style={{ display: "flex", flexDirection: "column", gap: "0.35rem" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
                  <ShieldAlert size={22} style={{ color: "#06b6d4" }} />
                  <span style={{ fontSize: "1.2rem", fontWeight: 700, color: "#f8fafc" }}>
                    Event Quick View & Threat Investigation
                  </span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                  <span className="mono" style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                    ID: {selectedEvent.id}
                  </span>
                  <button
                    onClick={() => handleCopyId(selectedEvent.id)}
                    style={{ background: "none", border: "none", color: "#38bdf8", cursor: "pointer", padding: 0 }}
                    title="Copy Event ID"
                  >
                    {copiedId ? <CheckCircle2 size={13} style={{ color: "#34d399" }} /> : <Copy size={13} />}
                  </button>
                </div>
              </div>

              <button
                onClick={() => setSelectedEvent(null)}
                style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }}
              >
                <X size={22} />
              </button>
            </div>

            {/* Quick Status Bar */}
            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                alignItems: "center",
                gap: "1rem",
                padding: "0.75rem 1rem",
                borderRadius: "8px",
                background: "rgba(15, 23, 42, 0.8)",
                border: "1px solid var(--border-color)",
              }}
            >
              <div>
                <span style={{ fontSize: "0.7rem", color: "var(--text-muted)", display: "block" }}>
                  CLASSIFICATION
                </span>
                <span className="mono" style={{ fontSize: "0.85rem", color: "#38bdf8", fontWeight: 600 }}>
                  {selectedEvent.event_type}
                </span>
              </div>
              <div>
                <span style={{ fontSize: "0.7rem", color: "var(--text-muted)", display: "block" }}>SEVERITY</span>
                <StatusBadge label={selectedEvent.severity} variant="severity" />
              </div>
              <div>
                <span style={{ fontSize: "0.7rem", color: "var(--text-muted)", display: "block" }}>SENSOR</span>
                <span style={{ fontSize: "0.85rem", color: "#f8fafc" }}>{selectedEvent.source}</span>
              </div>
              <div>
                <span style={{ fontSize: "0.7rem", color: "var(--text-muted)", display: "block" }}>TIMESTAMP</span>
                <span style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>
                  {new Date(selectedEvent.timestamp).toLocaleString()}
                </span>
              </div>
            </div>

            {/* Sub-Tabs */}
            <div style={{ display: "flex", gap: "0.5rem", borderBottom: "1px solid var(--border-color)" }}>
              {(["OVERVIEW", "RAW", "NORMALIZED", "ACTIONS"] as const).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveQuickViewTab(tab)}
                  style={{
                    padding: "0.5rem 1rem",
                    background: "none",
                    border: "none",
                    borderBottom: activeQuickViewTab === tab ? "2px solid #06b6d4" : "2px solid transparent",
                    color: activeQuickViewTab === tab ? "#f8fafc" : "var(--text-muted)",
                    fontWeight: 600,
                    fontSize: "0.8rem",
                    cursor: "pointer",
                  }}
                >
                  {tab === "OVERVIEW" && "Context & Entities"}
                  {tab === "RAW" && "Raw Payload"}
                  {tab === "NORMALIZED" && "Normalized Schema"}
                  {tab === "ACTIONS" && "Fast SOC Actions"}
                </button>
              ))}
            </div>

            {/* Tab 1: Overview */}
            {activeQuickViewTab === "OVERVIEW" && (
              <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
                  <div
                    style={{
                      padding: "1rem",
                      borderRadius: "8px",
                      background: "rgba(15, 23, 42, 0.6)",
                      border: "1px solid var(--border-color)",
                    }}
                  >
                    <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>
                      Network Context
                    </span>
                    <div style={{ marginTop: "0.5rem", display: "flex", flexDirection: "column", gap: "0.4rem" }}>
                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>Source IP:</span>
                        <span className="mono" style={{ fontSize: "0.8rem", color: "#38bdf8" }}>
                          {selectedEvent.source_ip || "—"}
                        </span>
                      </div>
                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>Target Host:</span>
                        <span style={{ fontSize: "0.8rem", color: "#f8fafc" }}>
                          {selectedEvent.hostname || "—"}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div
                    style={{
                      padding: "1rem",
                      borderRadius: "8px",
                      background: "rgba(15, 23, 42, 0.6)",
                      border: "1px solid var(--border-color)",
                    }}
                  >
                    <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>
                      Identity Context
                    </span>
                    <div style={{ marginTop: "0.5rem", display: "flex", flexDirection: "column", gap: "0.4rem" }}>
                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>Username:</span>
                        <span style={{ fontSize: "0.8rem", color: "#f8fafc" }}>
                          {selectedEvent.username || "—"}
                        </span>
                      </div>
                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>Account Type:</span>
                        <span style={{ fontSize: "0.8rem", color: "#34d399" }}>
                          {selectedEvent.username?.toLowerCase().includes("admin") || selectedEvent.username?.toLowerCase().includes("root")
                            ? "PRIVILEGED"
                            : "STANDARD"}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* MITRE Mapping & Threat Evaluation */}
                <div
                  style={{
                    padding: "1rem",
                    borderRadius: "8px",
                    background: "rgba(15, 23, 42, 0.6)",
                    border: "1px solid var(--border-color)",
                  }}
                >
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>
                    MITRE ATT&CK & Detection Evaluation
                  </span>
                  <div style={{ marginTop: "0.5rem", display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                      <span
                        style={{
                          fontSize: "0.75rem",
                          background: "rgba(244, 63, 94, 0.15)",
                          color: "#fb7185",
                          padding: "0.2rem 0.5rem",
                          borderRadius: "4px",
                          fontWeight: 600,
                        }}
                      >
                        {selectedEvent.event_type.includes("LSASS") || selectedEvent.event_type.includes("MIMIKATZ")
                          ? "T1003.001 - OS Credential Dumping"
                          : selectedEvent.event_type.includes("AUTH")
                          ? "T1110 - Brute Force Authentication"
                          : "T1059 - Command and Scripting Execution"}
                      </span>
                      <span style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>
                        Tactics: Credential Access, Defense Evasion
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Tab 2: Raw Payload */}
            {activeQuickViewTab === "RAW" && (
              <div>
                <pre
                  className="mono"
                  style={{
                    background: "rgba(10, 15, 29, 0.95)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "8px",
                    padding: "1rem",
                    fontSize: "0.8rem",
                    color: "#34d399",
                    maxHeight: "300px",
                    overflowY: "auto",
                  }}
                >
                  {JSON.stringify(selectedEvent.raw_event, null, 2)}
                </pre>
              </div>
            )}

            {/* Tab 3: Normalized Schema */}
            {activeQuickViewTab === "NORMALIZED" && (
              <div>
                <pre
                  className="mono"
                  style={{
                    background: "rgba(10, 15, 29, 0.95)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "8px",
                    padding: "1rem",
                    fontSize: "0.8rem",
                    color: "#38bdf8",
                    maxHeight: "300px",
                    overflowY: "auto",
                  }}
                >
                  {JSON.stringify(selectedEvent.normalized_event, null, 2)}
                </pre>
              </div>
            )}

            {/* Tab 4: Actions (Section 12 requirement) */}
            {activeQuickViewTab === "ACTIONS" && (
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
                <button
                  onClick={() => {
                    setSelectedEvent(null);
                    onNavigateTab?.("incidents");
                  }}
                  className="btn-primary"
                  style={{ justifyContent: "center", fontSize: "0.85rem" }}
                >
                  <ShieldAlert size={15} />
                  <span>INVESTIGATE IN INCIDENTS</span>
                </button>

                <button
                  onClick={() => {
                    if (selectedEvent.source_ip) {
                      setSearchFilter(selectedEvent.source_ip);
                      setSelectedEvent(null);
                      triggerFeedback(`Filter applied: Source IP ${selectedEvent.source_ip}`);
                    }
                  }}
                  className="btn-secondary"
                  style={{ justifyContent: "center", fontSize: "0.85rem" }}
                >
                  <Activity size={15} />
                  <span>VIEW RELATED EVENTS (IP)</span>
                </button>

                <button
                  onClick={() => {
                    if (selectedEvent.username) {
                      setSearchFilter(selectedEvent.username);
                      setSelectedEvent(null);
                      triggerFeedback(`Filter applied: User ${selectedEvent.username}`);
                    }
                  }}
                  className="btn-secondary"
                  style={{ justifyContent: "center", fontSize: "0.85rem" }}
                >
                  <User size={15} />
                  <span>VIEW USER EVENTS</span>
                </button>

                <button
                  onClick={() => {
                    setSelectedEvent(null);
                    onNavigateTab?.("assets");
                  }}
                  className="btn-secondary"
                  style={{ justifyContent: "center", fontSize: "0.85rem" }}
                >
                  <Server size={15} />
                  <span>VIEW ASSET INVENTORY</span>
                </button>

                <button
                  onClick={() => {
                    setSelectedEvent(null);
                    onNavigateTab?.("intelligence", { indicator: selectedEvent.source_ip });
                  }}
                  className="btn-secondary"
                  style={{ justifyContent: "center", fontSize: "0.85rem" }}
                >
                  <Shield size={15} />
                  <span>THREAT INTELLIGENCE LOOKUP</span>
                </button>

                <button
                  onClick={() => {
                    triggerFeedback(`Event ${selectedEvent.id.slice(0, 8)} escalated to SOC Tier 2.`);
                  }}
                  className="btn-secondary"
                  style={{ justifyContent: "center", fontSize: "0.85rem", color: "#f59e0b" }}
                >
                  <ArrowRight size={15} />
                  <span>ESCALATE TO TIER 2</span>
                </button>

                <button
                  onClick={() => {
                    triggerFeedback(`Containment workflow triggered for host ${selectedEvent.hostname || "target"}.`);
                  }}
                  className="btn-secondary"
                  style={{ justifyContent: "center", fontSize: "0.85rem", color: "#fb7185", gridColumn: "span 2" }}
                >
                  <AlertTriangle size={15} />
                  <span>TRIGGER INCIDENT CONTAINMENT & RESPONSE</span>
                </button>
              </div>
            )}

            {/* Footer Buttons */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderTop: "1px solid var(--border-color)", paddingTop: "1rem" }}>
              <div style={{ display: "flex", gap: "0.5rem" }}>
                <button
                  onClick={() => setActiveQuickViewTab("ACTIONS")}
                  className="btn-primary"
                  style={{ fontSize: "0.8rem", padding: "0.4rem 0.8rem" }}
                >
                  Take Action →
                </button>
              </div>

              <button onClick={() => setSelectedEvent(null)} className="btn-secondary" style={{ fontSize: "0.8rem" }}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Ingest Telemetry Modal */}
      {showModal && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            backgroundColor: "rgba(0, 0, 0, 0.75)",
            backdropFilter: "blur(6px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 50,
            padding: "1rem",
          }}
        >
          <div
            className="glass-panel"
            style={{ width: "100%", maxWidth: "500px", padding: "2rem", display: "flex", flexDirection: "column", gap: "1.25rem" }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h2 style={{ fontSize: "1.2rem", fontWeight: 700, color: "#f8fafc" }}>
                Ingest Telemetry Event
              </h2>
              <button onClick={() => setShowModal(false)} style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }}>
                <X size={20} />
              </button>
            </div>

            {error && (
              <div style={{ padding: "0.6rem 0.85rem", borderRadius: "6px", background: "rgba(244, 63, 94, 0.15)", color: "#fb7185", fontSize: "0.8rem" }}>
                {error}
              </div>
            )}

            <form onSubmit={handleIngest} style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
              <div>
                <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-secondary)", marginBottom: "0.3rem" }}>
                  Telemetry Source Sensor
                </label>
                <input
                  type="text"
                  required
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "0.65rem 0.75rem",
                    background: "rgba(10, 15, 29, 0.8)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "6px",
                    color: "#f8fafc",
                    fontSize: "0.875rem",
                  }}
                />
              </div>

              <div>
                <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-secondary)", marginBottom: "0.3rem" }}>
                  Event Classification / Rule
                </label>
                <input
                  type="text"
                  required
                  value={eventType}
                  onChange={(e) => setEventType(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "0.65rem 0.75rem",
                    background: "rgba(10, 15, 29, 0.8)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "6px",
                    color: "#f8fafc",
                    fontSize: "0.875rem",
                  }}
                />
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-secondary)", marginBottom: "0.3rem" }}>
                    Severity
                  </label>
                  <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value)}
                    style={{
                      width: "100%",
                      padding: "0.65rem",
                      background: "rgba(10, 15, 29, 0.8)",
                      border: "1px solid var(--border-color)",
                      borderRadius: "6px",
                      color: "#f8fafc",
                    }}
                  >
                    <option value="INFORMATIONAL">INFORMATIONAL</option>
                    <option value="LOW">LOW</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-secondary)", marginBottom: "0.3rem" }}>
                    Source IP
                  </label>
                  <input
                    type="text"
                    value={sourceIp}
                    onChange={(e) => setSourceIp(e.target.value)}
                    style={{
                      width: "100%",
                      padding: "0.65rem",
                      background: "rgba(10, 15, 29, 0.8)",
                      border: "1px solid var(--border-color)",
                      borderRadius: "6px",
                      color: "#f8fafc",
                    }}
                  />
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-secondary)", marginBottom: "0.3rem" }}>
                    Username
                  </label>
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    style={{
                      width: "100%",
                      padding: "0.65rem",
                      background: "rgba(10, 15, 29, 0.8)",
                      border: "1px solid var(--border-color)",
                      borderRadius: "6px",
                      color: "#f8fafc",
                    }}
                  />
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-secondary)", marginBottom: "0.3rem" }}>
                    Target Hostname
                  </label>
                  <input
                    type="text"
                    value={hostname}
                    onChange={(e) => setHostname(e.target.value)}
                    style={{
                      width: "100%",
                      padding: "0.65rem",
                      background: "rgba(10, 15, 29, 0.8)",
                      border: "1px solid var(--border-color)",
                      borderRadius: "6px",
                      color: "#f8fafc",
                    }}
                  />
                </div>
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.75rem", marginTop: "0.5rem" }}>
                <button type="button" onClick={() => setShowModal(false)} className="btn-secondary">
                  Cancel
                </button>
                <button type="submit" disabled={submitting} className="btn-primary">
                  {submitting ? "Ingesting..." : "Ingest Telemetry"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
