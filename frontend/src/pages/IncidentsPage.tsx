import React, { useState } from "react";
import { Plus, X } from "lucide-react";
import { Incident } from "../types";
import { StatusBadge } from "../components/StatusBadge";
import { api } from "../services/api";

interface IncidentsPageProps {
  incidents: Incident[];
  onRefresh: () => void;
}

export const IncidentsPage: React.FC<IncidentsPageProps> = ({ incidents, onRefresh }) => {
  const [showModal, setShowModal] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState("HIGH");
  const [riskScore, setRiskScore] = useState(75.0);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await api.createIncident({
        title,
        description,
        severity,
        risk_score: riskScore,
        confidence: 0.95,
        status: "OPEN",
      });
      setShowModal(false);
      setTitle("");
      setDescription("");
      onRefresh();
    } catch (err: any) {
      setError(err.message || "Failed to create incident");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h1 style={{ fontSize: "1.4rem", fontWeight: 700, color: "#f8fafc" }}>
            Security Incidents
          </h1>
          <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)" }}>
            Tenant-isolated triage, forensic investigation, and risk tracking.
          </p>
        </div>

        <button onClick={() => setShowModal(true)} className="btn-primary">
          <Plus size={16} />
          <span>New Incident</span>
        </button>
      </div>

      {/* Incidents Table */}
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
              <th style={{ padding: "0.85rem 1.25rem" }}>Incident Title</th>
              <th style={{ padding: "0.85rem 1rem" }}>Severity</th>
              <th style={{ padding: "0.85rem 1rem" }}>Status</th>
              <th style={{ padding: "0.85rem 1rem" }}>Risk Score</th>
              <th style={{ padding: "0.85rem 1rem" }}>Confidence</th>
              <th style={{ padding: "0.85rem 1.25rem" }}>Detected At</th>
            </tr>
          </thead>
          <tbody>
            {incidents.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ textAlign: "center", padding: "3rem 1rem", color: "var(--text-muted)" }}>
                  No security incidents recorded in this tenant partition.
                </td>
              </tr>
            ) : (
              incidents.map((inc) => (
                <tr
                  key={inc.id}
                  onClick={() => setSelectedIncident(inc)}
                  style={{
                    borderBottom: "1px solid rgba(255, 255, 255, 0.04)",
                    cursor: "pointer",
                    transition: "background 0.15s ease",
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = "rgba(6, 182, 212, 0.04)"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = "transparent"; }}
                >
                  <td style={{ padding: "1rem 1.25rem" }}>
                    <div style={{ fontWeight: 600, color: "#f8fafc" }}>{inc.title}</div>
                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.2rem" }}>
                      {inc.description.length > 80 ? `${inc.description.substring(0, 80)}...` : inc.description}
                    </div>
                  </td>
                  <td style={{ padding: "1rem 1rem" }}>
                    <StatusBadge label={inc.severity} variant="severity" />
                  </td>
                  <td style={{ padding: "1rem 1rem" }}>
                    <StatusBadge label={inc.status} variant="status" />
                  </td>
                  <td style={{ padding: "1rem 1rem" }} className="mono">
                    <span style={{ color: inc.risk_score >= 80 ? "#fb7185" : "#38bdf8", fontWeight: 600 }}>
                      {inc.risk_score}
                    </span>
                  </td>
                  <td style={{ padding: "1rem 1rem" }} className="mono">
                    {Math.round(inc.confidence * 100)}%
                  </td>
                  <td style={{ padding: "1rem 1.25rem", color: "var(--text-secondary)", fontSize: "0.8rem" }}>
                    {new Date(inc.created_at).toLocaleString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Incident Detail Drawer/Modal */}
      {selectedIncident && (
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
            className="glass-panel glow-cyan"
            style={{ width: "100%", maxWidth: "600px", padding: "2rem", display: "flex", flexDirection: "column", gap: "1.25rem" }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
              <div>
                <div style={{ display: "flex", gap: "0.5rem", marginBottom: "0.5rem" }}>
                  <StatusBadge label={selectedIncident.severity} variant="severity" />
                  <StatusBadge label={selectedIncident.status} variant="status" />
                </div>
                <h2 style={{ fontSize: "1.25rem", fontWeight: 700, color: "#f8fafc" }}>
                  {selectedIncident.title}
                </h2>
              </div>
              <button
                onClick={() => setSelectedIncident(null)}
                style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }}
              >
                <X size={20} />
              </button>
            </div>

            <div style={{ background: "rgba(10, 15, 29, 0.7)", padding: "1rem", borderRadius: "8px", border: "1px solid var(--border-color)" }}>
              <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>Description</span>
              <p style={{ fontSize: "0.875rem", color: "var(--text-secondary)", marginTop: "0.35rem", lineHeight: 1.5 }}>
                {selectedIncident.description}
              </p>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
              <div style={{ background: "rgba(10, 15, 29, 0.7)", padding: "0.85rem", borderRadius: "8px", border: "1px solid var(--border-color)" }}>
                <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>Incident ID</span>
                <div className="mono" style={{ fontSize: "0.75rem", color: "#38bdf8", marginTop: "0.25rem" }}>
                  {selectedIncident.id}
                </div>
              </div>
              <div style={{ background: "rgba(10, 15, 29, 0.7)", padding: "0.85rem", borderRadius: "8px", border: "1px solid var(--border-color)" }}>
                <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>Tenant ID</span>
                <div className="mono" style={{ fontSize: "0.75rem", color: "#10b981", marginTop: "0.25rem" }}>
                  {selectedIncident.tenant_id}
                </div>
              </div>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: "0.5rem" }}>
              <button onClick={() => setSelectedIncident(null)} className="btn-secondary">
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* New Incident Modal */}
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
            style={{ width: "100%", maxWidth: "520px", padding: "2rem", display: "flex", flexDirection: "column", gap: "1.25rem" }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h2 style={{ fontSize: "1.2rem", fontWeight: 700, color: "#f8fafc" }}>
                Create Security Incident
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

            <form onSubmit={handleCreate} style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
              <div>
                <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-secondary)", marginBottom: "0.3rem" }}>
                  Incident Title
                </label>
                <input
                  type="text"
                  required
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="e.g. Unauthorized Lateral Movement via WMI"
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
                  Description & Forensic Observations
                </label>
                <textarea
                  required
                  rows={3}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Describe indicators of compromise, affected hostnames, or observed malicious commands..."
                  style={{
                    width: "100%",
                    padding: "0.65rem 0.75rem",
                    background: "rgba(10, 15, 29, 0.8)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "6px",
                    color: "#f8fafc",
                    fontSize: "0.875rem",
                    resize: "none",
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
                    <option value="LOW">LOW</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-secondary)", marginBottom: "0.3rem" }}>
                    Calculated Risk Score (0-100)
                  </label>
                  <input
                    type="number"
                    min={0}
                    max={100}
                    value={riskScore}
                    onChange={(e) => setRiskScore(parseFloat(e.target.value) || 0)}
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
                  {submitting ? "Creating..." : "Save Incident"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
