import React, { useState } from "react";
import { Plus, X, Terminal } from "lucide-react";
import { SecurityEvent } from "../types";
import { StatusBadge } from "../components/StatusBadge";
import { api } from "../services/api";

interface EventsPageProps {
  events: SecurityEvent[];
  onRefresh: () => void;
}

export const EventsPage: React.FC<EventsPageProps> = ({ events, onRefresh }) => {
  const [showModal, setShowModal] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  const [source, setSource] = useState("CrowdStrike-EDR");
  const [eventType, setEventType] = useState("LSASS_MEMORY_ACCESS_ATTEMPT");
  const [severity, setSeverity] = useState("CRITICAL");
  const [sourceIp, setSourceIp] = useState("10.0.4.18");
  const [username, setUsername] = useState("svc_backup");
  const [hostname, setHostname] = useState("dc-primary.corp");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
          ProcessName: "mimikatz.exe",
          TargetProcess: "lsass.exe",
          GrantedAccess: "0x1010",
          SourceIp: sourceIp,
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

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h1 style={{ fontSize: "1.4rem", fontWeight: 700, color: "#f8fafc" }}>
            Telemetry & Security Events
          </h1>
          <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)" }}>
            Normalized multi-source sensor events, authentication logs, and threat detections.
          </p>
        </div>

        <button onClick={() => setShowModal(true)} className="btn-primary">
          <Plus size={16} />
          <span>Ingest Telemetry</span>
        </button>
      </div>

      <div className="glass-panel" style={{ overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "0.875rem" }}>
          <thead>
            <tr
              style={{
                borderBottom: "1px solid var(--border-color)",
                background: "rgba(10, 15, 29, 0.5)",
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
            </tr>
          </thead>
          <tbody>
            {events.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: "center", padding: "3rem 1rem", color: "var(--text-muted)" }}>
                  No security events recorded in this tenant partition.
                </td>
              </tr>
            ) : (
              events.map((evt) => (
                <tr
                  key={evt.id}
                  onClick={() => setSelectedEvent(evt)}
                  style={{
                    borderBottom: "1px solid rgba(255, 255, 255, 0.04)",
                    cursor: "pointer",
                    transition: "background 0.15s ease",
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = "rgba(6, 182, 212, 0.04)"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = "transparent"; }}
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
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Raw Payload Inspection Modal */}
      {selectedEvent && (
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
            style={{ width: "100%", maxWidth: "650px", padding: "2rem", display: "flex", flexDirection: "column", gap: "1.25rem" }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <Terminal size={18} style={{ color: "#06b6d4" }} />
                <h2 style={{ fontSize: "1.1rem", fontWeight: 700, color: "#f8fafc" }}>
                  Event Telemetry Payload
                </h2>
              </div>
              <button onClick={() => setSelectedEvent(null)} style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }}>
                <X size={20} />
              </button>
            </div>

            <div style={{ display: "flex", gap: "0.5rem" }}>
              <StatusBadge label={selectedEvent.severity} variant="severity" />
              <span className="mono" style={{ fontSize: "0.85rem", color: "#38bdf8" }}>{selectedEvent.event_type}</span>
            </div>

            <div>
              <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>
                Raw JSON Telemetry
              </span>
              <pre
                className="mono"
                style={{
                  background: "rgba(10, 15, 29, 0.9)",
                  border: "1px solid var(--border-color)",
                  borderRadius: "8px",
                  padding: "1rem",
                  fontSize: "0.8rem",
                  color: "#34d399",
                  maxHeight: "280px",
                  overflowY: "auto",
                  marginTop: "0.35rem",
                }}
              >
                {JSON.stringify(selectedEvent.raw_event, null, 2)}
              </pre>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end" }}>
              <button onClick={() => setSelectedEvent(null)} className="btn-secondary">
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Ingest Event Modal */}
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
