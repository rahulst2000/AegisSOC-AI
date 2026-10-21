import React, { useState } from "react";
import {
  ArrowRight,
  FileSearch,
  Plus,
  RefreshCw,
  ShieldAlert,
  X,
} from "lucide-react";
import {
  ActionRecommendation,
  ActionRequest,
  Incident,
  Investigation,
  L2Escalation,
  TimelineItem,
} from "../types";
import { StatusBadge } from "../components/StatusBadge";
import { api } from "../services/api";

interface IncidentsPageProps {
  incidents: Incident[];
  onRefresh: () => void;
}

export const IncidentsPage: React.FC<IncidentsPageProps> = ({ incidents, onRefresh }) => {
  const [showModal, setShowModal] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [activeTab, setActiveTab] = useState<"TIMELINE" | "INVESTIGATION" | "ACTIONS" | "ESCALATION">("TIMELINE");

  // New Incident Form State
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState("HIGH");
  const [riskScore, setRiskScore] = useState(75.0);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Modal State
  const [timeline, setTimeline] = useState<TimelineItem[]>([]);
  const [loadingTimeline, setLoadingTimeline] = useState(false);
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [loadingInvestigation, setLoadingInvestigation] = useState(false);
  const [recommendations, setRecommendations] = useState<ActionRecommendation[]>([]);
  const [actions, setActions] = useState<ActionRequest[]>([]);
  const [escalation, setEscalation] = useState<L2Escalation | null>(null);
  const [actionProcessing, setActionProcessing] = useState(false);
  const [escalationReason, setEscalationReason] = useState("");

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

  const openIncidentModal = async (inc: Incident) => {
    setSelectedIncident(inc);
    setActiveTab("TIMELINE");
    setTimeline([]);
    setInvestigation(null);
    setRecommendations([]);
    setActions([]);
    setEscalation(null);
    setLoadingTimeline(true);

    try {
      const items = await api.getIncidentTimeline(inc.id);
      setTimeline(items);
    } catch {
      // Timeline optional
    } finally {
      setLoadingTimeline(false);
    }

    // Try fetching existing investigation & escalation
    try {
      const existingInv = await api.getInvestigation(inc.id);
      setInvestigation(existingInv);
    } catch {
      // Investigation may not have run yet
    }

    try {
      const existingEsc = await api.getIncidentEscalation(inc.id);
      setEscalation(existingEsc);
    } catch {
      // Escalation may not exist
    }

    try {
      const acts = await api.getActions(inc.id);
      setActions(acts);
    } catch {
      // Actions may be empty
    }
  };

  const runInvestigation = async () => {
    if (!selectedIncident) return;
    setLoadingInvestigation(true);
    try {
      const inv = await api.investigateIncident(selectedIncident.id, true);
      setInvestigation(inv);
      const recs = await api.getIncidentRecommendations(selectedIncident.id);
      setRecommendations(recs);
      const acts = await api.getActions(selectedIncident.id);
      setActions(acts);
    } catch (err: any) {
      alert("Investigation failed: " + (err.message || "Unknown error"));
    } finally {
      setLoadingInvestigation(false);
    }
  };

  const handleRequestAction = async (rec: ActionRecommendation) => {
    if (!selectedIncident) return;
    setActionProcessing(true);
    try {
      await api.createAction({
        incident_id: selectedIncident.id,
        action_type: rec.action_type,
        target_entity: rec.target_entity,
        target_type: rec.target_type,
        playbook_id: rec.playbook_id,
        investigation_id: investigation?.id,
      });
      const acts = await api.getActions(selectedIncident.id);
      setActions(acts);
    } catch (err: any) {
      alert("Failed to request action: " + (err.message || "Unknown error"));
    } finally {
      setActionProcessing(false);
    }
  };

  const handleApproveAction = async (actionId: string) => {
    setActionProcessing(true);
    try {
      await api.approveAction(actionId, "Approved by SOC Analyst in review portal");
      if (selectedIncident) {
        const acts = await api.getActions(selectedIncident.id);
        setActions(acts);
      }
    } catch (err: any) {
      alert("Approval failed: " + (err.message || "Unknown error"));
    } finally {
      setActionProcessing(false);
    }
  };

  const handleRejectAction = async (actionId: string) => {
    const reason = prompt("Enter rejection reason (mandatory):");
    if (!reason) return;
    setActionProcessing(true);
    try {
      await api.rejectAction(actionId, reason);
      if (selectedIncident) {
        const acts = await api.getActions(selectedIncident.id);
        setActions(acts);
      }
    } catch (err: any) {
      alert("Rejection failed: " + (err.message || "Unknown error"));
    } finally {
      setActionProcessing(false);
    }
  };

  const handleExecuteAction = async (actionId: string) => {
    setActionProcessing(true);
    try {
      await api.executeAction(actionId);
      if (selectedIncident) {
        const acts = await api.getActions(selectedIncident.id);
        setActions(acts);
      }
    } catch (err: any) {
      alert("Execution failed: " + (err.message || "Unknown error"));
    } finally {
      setActionProcessing(false);
    }
  };

  const handleEscalateIncident = async () => {
    if (!selectedIncident) return;
    const reason = escalationReason || prompt("Enter escalation justification for Tier-2 SOC:");
    if (!reason) return;
    setActionProcessing(true);
    try {
      const esc = await api.escalateIncident(selectedIncident.id, reason, "HIGH");
      setEscalation(esc);
      onRefresh();
    } catch (err: any) {
      alert("Escalation failed: " + (err.message || "Unknown error"));
    } finally {
      setActionProcessing(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h1 style={{ fontSize: "1.4rem", fontWeight: 700, color: "#f8fafc" }}>
            Security Incidents & Autonomous Investigation
          </h1>
          <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)" }}>
            Evidence-grounded AI analysis, hypothesis evaluation, controlled playbooks, and Tier-2 escalation.
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
              <th style={{ padding: "0.85rem 1rem" }}>Risk / Confidence</th>
              <th style={{ padding: "0.85rem 1rem" }}>MITRE Techniques</th>
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
                  onClick={() => openIncidentModal(inc)}
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
                    <span style={{ color: "var(--text-muted)", marginLeft: "0.35rem", fontSize: "0.75rem" }}>
                      ({Math.round(inc.confidence * 100)}%)
                    </span>
                  </td>
                  <td style={{ padding: "1rem 1rem" }}>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "0.25rem" }}>
                      {inc.mitre_techniques && inc.mitre_techniques.length > 0 ? (
                        inc.mitre_techniques.map((tech) => (
                          <span
                            key={tech}
                            style={{
                              backgroundColor: "rgba(239, 68, 68, 0.15)",
                              color: "#f87171",
                              padding: "0.15rem 0.4rem",
                              borderRadius: "4px",
                              fontSize: "0.7rem",
                              fontFamily: "monospace",
                              fontWeight: 600,
                            }}
                          >
                            {tech}
                          </span>
                        ))
                      ) : (
                        <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>None</span>
                      )}
                    </div>
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

      {/* Incident Forensic & Autonomous Investigation Modal */}
      {selectedIncident && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            backgroundColor: "rgba(0, 0, 0, 0.8)",
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
            style={{
              width: "100%",
              maxWidth: "880px",
              maxHeight: "92vh",
              overflowY: "auto",
              padding: "2rem",
              display: "flex",
              flexDirection: "column",
              gap: "1.25rem",
            }}
          >
            {/* Modal Header */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
              <div>
                <div style={{ display: "flex", gap: "0.5rem", marginBottom: "0.5rem" }}>
                  <StatusBadge label={selectedIncident.severity} variant="severity" />
                  <StatusBadge label={selectedIncident.status} variant="status" />
                  <span className="mono" style={{ fontSize: "0.75rem", padding: "0.2rem 0.5rem", borderRadius: "4px", background: "rgba(6, 182, 212, 0.1)", color: "#38bdf8" }}>
                    Risk: {selectedIncident.risk_score} | Conf: {Math.round(selectedIncident.confidence * 100)}%
                  </span>
                </div>
                <h2 style={{ fontSize: "1.3rem", fontWeight: 700, color: "#f8fafc", margin: 0 }}>
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

            {/* Navigation Tabs */}
            <div style={{ display: "flex", borderBottom: "1px solid var(--border-color)", gap: "0.5rem" }}>
              <button
                onClick={() => setActiveTab("TIMELINE")}
                style={{
                  padding: "0.6rem 1rem",
                  background: "none",
                  border: "none",
                  borderBottom: activeTab === "TIMELINE" ? "2px solid #06b6d4" : "2px solid transparent",
                  color: activeTab === "TIMELINE" ? "#38bdf8" : "var(--text-muted)",
                  fontWeight: 600,
                  fontSize: "0.85rem",
                  cursor: "pointer",
                }}
              >
                Timeline & Scope
              </button>
              <button
                onClick={() => {
                  setActiveTab("INVESTIGATION");
                  if (!investigation) runInvestigation();
                }}
                style={{
                  padding: "0.6rem 1rem",
                  background: "none",
                  border: "none",
                  borderBottom: activeTab === "INVESTIGATION" ? "2px solid #06b6d4" : "2px solid transparent",
                  color: activeTab === "INVESTIGATION" ? "#38bdf8" : "var(--text-muted)",
                  fontWeight: 600,
                  fontSize: "0.85rem",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: "0.4rem",
                }}
              >
                <FileSearch size={15} />
                <span>AI Investigation</span>
              </button>
              <button
                onClick={() => setActiveTab("ACTIONS")}
                style={{
                  padding: "0.6rem 1rem",
                  background: "none",
                  border: "none",
                  borderBottom: activeTab === "ACTIONS" ? "2px solid #06b6d4" : "2px solid transparent",
                  color: activeTab === "ACTIONS" ? "#38bdf8" : "var(--text-muted)",
                  fontWeight: 600,
                  fontSize: "0.85rem",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: "0.4rem",
                }}
              >
                <ShieldAlert size={15} />
                <span>Response Playbooks ({actions.length})</span>
              </button>
              <button
                onClick={() => setActiveTab("ESCALATION")}
                style={{
                  padding: "0.6rem 1rem",
                  background: "none",
                  border: "none",
                  borderBottom: activeTab === "ESCALATION" ? "2px solid #06b6d4" : "2px solid transparent",
                  color: activeTab === "ESCALATION" ? "#38bdf8" : "var(--text-muted)",
                  fontWeight: 600,
                  fontSize: "0.85rem",
                  cursor: "pointer",
                }}
              >
                Tier-2 Escalation {escalation ? "✓" : ""}
              </button>
            </div>

            {/* TAB 1: Timeline & Scope */}
            {activeTab === "TIMELINE" && (
              <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                <div style={{ background: "rgba(10, 15, 29, 0.7)", padding: "1rem", borderRadius: "8px", border: "1px solid var(--border-color)" }}>
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>Description</span>
                  <p style={{ fontSize: "0.875rem", color: "var(--text-secondary)", marginTop: "0.35rem", lineHeight: 1.5 }}>
                    {selectedIncident.description}
                  </p>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
                  <div style={{ background: "rgba(10, 15, 29, 0.7)", padding: "0.85rem", borderRadius: "8px", border: "1px solid var(--border-color)" }}>
                    <span style={{ fontSize: "0.7rem", color: "var(--text-muted)", textTransform: "uppercase" }}>MITRE Techniques</span>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "0.35rem", marginTop: "0.4rem" }}>
                      {selectedIncident.mitre_techniques && selectedIncident.mitre_techniques.length > 0 ? (
                        selectedIncident.mitre_techniques.map((tech) => (
                          <span
                            key={tech}
                            style={{
                              backgroundColor: "rgba(239, 68, 68, 0.2)",
                              color: "#f87171",
                              border: "1px solid rgba(239, 68, 68, 0.4)",
                              padding: "0.2rem 0.5rem",
                              borderRadius: "4px",
                              fontSize: "0.75rem",
                              fontFamily: "monospace",
                              fontWeight: 600,
                            }}
                          >
                            {tech}
                          </span>
                        ))
                      ) : (
                        <span style={{ fontSize: "0.75rem", color: "#64748b" }}>None</span>
                      )}
                    </div>
                  </div>

                  <div style={{ background: "rgba(10, 15, 29, 0.7)", padding: "0.85rem", borderRadius: "8px", border: "1px solid var(--border-color)" }}>
                    <span style={{ fontSize: "0.7rem", color: "var(--text-muted)", textTransform: "uppercase" }}>Entity Scope</span>
                    <div style={{ fontSize: "0.75rem", color: "var(--text-secondary)", marginTop: "0.4rem", display: "flex", flexDirection: "column", gap: "0.25rem" }}>
                      <div><strong>Source IPs:</strong> {selectedIncident.source_ips?.join(", ") || "N/A"}</div>
                      <div><strong>Affected Users:</strong> {selectedIncident.affected_users?.join(", ") || "N/A"}</div>
                      <div><strong>Affected Assets:</strong> {selectedIncident.affected_assets?.join(", ") || "N/A"}</div>
                    </div>
                  </div>
                </div>

                <div>
                  <h3 style={{ fontSize: "0.95rem", fontWeight: 600, color: "#f8fafc", marginBottom: "0.75rem" }}>
                    Forensic Timeline (Evidence-Grounded)
                  </h3>
                  {loadingTimeline ? (
                    <div style={{ padding: "1.5rem", textAlign: "center", color: "var(--text-muted)" }}>
                      Loading chronological timeline...
                    </div>
                  ) : timeline.length === 0 ? (
                    <div style={{ padding: "1rem", background: "rgba(10, 15, 29, 0.7)", borderRadius: "8px", color: "var(--text-muted)", fontSize: "0.8rem", textAlign: "center" }}>
                      No chronological events recorded for this incident.
                    </div>
                  ) : (
                    <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem", maxHeight: "260px", overflowY: "auto" }}>
                      {timeline.map((item, idx) => (
                        <div
                          key={idx}
                          style={{
                            display: "flex",
                            alignItems: "flex-start",
                            gap: "0.75rem",
                            padding: "0.6rem 0.85rem",
                            borderRadius: "6px",
                            background: item.item_type === "DETECTION"
                              ? "rgba(59, 130, 246, 0.1)"
                              : item.item_type === "EVIDENCE"
                              ? "rgba(16, 185, 129, 0.1)"
                              : "rgba(30, 41, 59, 0.4)",
                            borderLeft: `3px solid ${
                              item.item_type === "DETECTION"
                                ? "#3b82f6"
                                : item.item_type === "EVIDENCE"
                                ? "#10b981"
                                : "#64748b"
                            }`,
                            fontSize: "0.8rem",
                          }}
                        >
                          <div className="mono" style={{ color: "var(--text-muted)", fontSize: "0.7rem", minWidth: "100px" }}>
                            {new Date(item.timestamp).toLocaleTimeString()}
                          </div>
                          <div style={{ flex: 1 }}>
                            <div style={{ fontWeight: 600, color: "#f8fafc" }}>{item.title}</div>
                            <div style={{ color: "var(--text-secondary)", fontSize: "0.75rem", marginTop: "0.15rem" }}>
                              {item.description}
                            </div>
                            {item.metadata?.integrity_hash && (
                              <div className="mono" style={{ color: "#34d399", fontSize: "0.65rem", marginTop: "0.2rem" }}>
                                SHA-256: {item.metadata.integrity_hash}
                              </div>
                            )}
                          </div>
                          <span style={{ fontSize: "0.65rem", fontWeight: 600, padding: "0.15rem 0.4rem", borderRadius: "4px", backgroundColor: "rgba(255,255,255,0.05)", color: "var(--text-muted)" }}>
                            {item.item_type}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* TAB 2: AI Investigation */}
            {activeTab === "INVESTIGATION" && (
              <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div style={{ fontSize: "0.85rem", color: "var(--text-secondary)" }}>
                    Evidence-grounded hypothesis testing with prompt-injection defense shielding.
                  </div>
                  <button onClick={runInvestigation} disabled={loadingInvestigation} className="btn-secondary" style={{ display: "flex", alignItems: "center", gap: "0.4rem", fontSize: "0.75rem", padding: "0.4rem 0.75rem" }}>
                    <RefreshCw size={14} className={loadingInvestigation ? "animate-spin" : ""} />
                    <span>{loadingInvestigation ? "Investigating..." : "Re-Run Investigation"}</span>
                  </button>
                </div>

                {loadingInvestigation ? (
                  <div style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)" }}>
                    Analyzing forensic evidence and evaluating hypotheses H1-H8...
                  </div>
                ) : !investigation ? (
                  <div style={{ padding: "2rem", textAlign: "center", color: "var(--text-muted)" }}>
                    Click &quot;Re-Run Investigation&quot; to synthesize evidence into hypotheses and findings.
                  </div>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                    {/* Executive Summary */}
                    <div style={{ background: "rgba(10, 15, 29, 0.7)", padding: "1rem", borderRadius: "8px", border: "1px solid var(--border-color)" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
                        <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 600 }}>Executive Summary</span>
                        <div style={{ display: "flex", gap: "0.5rem" }}>
                          <span style={{ fontSize: "0.7rem", padding: "0.2rem 0.5rem", borderRadius: "4px", background: "rgba(6, 182, 212, 0.15)", color: "#38bdf8", fontWeight: 600 }}>
                            Decision: {investigation.l1_decision}
                          </span>
                          {investigation.l2_escalation_recommended && (
                            <span style={{ fontSize: "0.7rem", padding: "0.2rem 0.5rem", borderRadius: "4px", background: "rgba(244, 63, 94, 0.15)", color: "#fb7185", fontWeight: 600 }}>
                              L2 Escalation Recommended
                            </span>
                          )}
                        </div>
                      </div>
                      <p style={{ fontSize: "0.85rem", color: "#f8fafc", lineHeight: 1.5 }}>
                        {investigation.executive_summary}
                      </p>
                    </div>

                    {/* Attack Chain */}
                    {investigation.attack_chain && investigation.attack_chain.length > 0 && (
                      <div style={{ background: "rgba(10, 15, 29, 0.7)", padding: "1rem", borderRadius: "8px", border: "1px solid var(--border-color)" }}>
                        <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 600 }}>Attack Progression Chain</span>
                        <div style={{ display: "flex", flexDirection: "column", gap: "0.4rem", marginTop: "0.5rem" }}>
                          {investigation.attack_chain.map((step, sIdx) => (
                            <div key={sIdx} style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontSize: "0.8rem", color: "var(--text-secondary)" }}>
                              <ArrowRight size={14} style={{ color: "#38bdf8", flexShrink: 0 }} />
                              <span>{step}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Hypotheses H1 - H8 */}
                    <div>
                      <h4 style={{ fontSize: "0.9rem", fontWeight: 600, color: "#f8fafc", marginBottom: "0.6rem" }}>
                        Evaluated Security Hypotheses
                      </h4>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.6rem" }}>
                        {investigation.hypotheses.map((hyp) => (
                          <div
                            key={hyp.hypothesis_id}
                            style={{
                              padding: "0.75rem",
                              borderRadius: "6px",
                              background: "rgba(10, 15, 29, 0.7)",
                              border: `1px solid ${
                                hyp.status === "CONFIRMED"
                                  ? "rgba(16, 185, 129, 0.4)"
                                  : hyp.status === "LIKELY"
                                  ? "rgba(59, 130, 246, 0.4)"
                                  : hyp.status === "DISPROVED"
                                  ? "rgba(100, 116, 139, 0.3)"
                                  : "rgba(234, 179, 8, 0.3)"
                              }`,
                            }}
                          >
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.3rem" }}>
                              <span style={{ fontWeight: 600, fontSize: "0.8rem", color: "#f8fafc" }}>
                                {hyp.hypothesis_id}: {hyp.title}
                              </span>
                              <span
                                style={{
                                  fontSize: "0.65rem",
                                  fontWeight: 700,
                                  padding: "0.15rem 0.4rem",
                                  borderRadius: "4px",
                                  color: hyp.status === "CONFIRMED" ? "#34d399" : hyp.status === "LIKELY" ? "#60a5fa" : hyp.status === "DISPROVED" ? "#94a3b8" : "#facc15",
                                  background: hyp.status === "CONFIRMED" ? "rgba(16, 185, 129, 0.15)" : hyp.status === "LIKELY" ? "rgba(59, 130, 246, 0.15)" : "rgba(100, 116, 139, 0.15)",
                                }}
                              >
                                {hyp.status} ({Math.round(hyp.confidence * 100)}%)
                              </span>
                            </div>
                            <p style={{ fontSize: "0.75rem", color: "var(--text-muted)", margin: 0 }}>
                              {hyp.description}
                            </p>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Verified Findings */}
                    <div>
                      <h4 style={{ fontSize: "0.9rem", fontWeight: 600, color: "#f8fafc", marginBottom: "0.6rem" }}>
                        Verified Forensic Findings ({investigation.findings.length})
                      </h4>
                      <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                        {investigation.findings.map((f, fIdx) => (
                          <div
                            key={fIdx}
                            style={{
                              padding: "0.6rem 0.85rem",
                              borderRadius: "6px",
                              background: "rgba(10, 15, 29, 0.7)",
                              border: "1px solid var(--border-color)",
                              fontSize: "0.8rem",
                            }}
                          >
                            <div style={{ display: "flex", justifyContent: "space-between", color: "#f8fafc", fontWeight: 500 }}>
                              <span>{f.finding}</span>
                              <span style={{ color: "#34d399", fontSize: "0.75rem" }}>{Math.round(f.confidence * 100)}%</span>
                            </div>
                            <div style={{ color: "var(--text-muted)", fontSize: "0.7rem", marginTop: "0.2rem" }}>
                              {f.reasoning_summary}
                            </div>
                            {f.evidence_ids && f.evidence_ids.length > 0 && (
                              <div className="mono" style={{ fontSize: "0.65rem", color: "#38bdf8", marginTop: "0.25rem" }}>
                                Evidence IDs: {f.evidence_ids.join(", ")}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* TAB 3: Response Playbooks & Approvals */}
            {activeTab === "ACTIONS" && (
              <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                <div style={{ fontSize: "0.85rem", color: "var(--text-secondary)" }}>
                  Controlled semi-autonomous response workflows. Policy enforcement and human approval gate execution.
                </div>

                {/* AI Recommendations */}
                {recommendations.length > 0 && (
                  <div style={{ background: "rgba(6, 182, 212, 0.05)", padding: "1rem", borderRadius: "8px", border: "1px solid rgba(6, 182, 212, 0.2)" }}>
                    <h4 style={{ fontSize: "0.85rem", fontWeight: 600, color: "#38bdf8", marginBottom: "0.5rem" }}>
                      AI Action Recommendations (Grounded in Verified Telemetry)
                    </h4>
                    <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                      {recommendations.map((rec, rIdx) => (
                        <div key={rIdx} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", background: "rgba(10, 15, 29, 0.7)", padding: "0.6rem 0.85rem", borderRadius: "6px" }}>
                          <div>
                            <div style={{ fontSize: "0.8rem", fontWeight: 600, color: "#f8fafc" }}>
                              {rec.action_type}: {rec.target_entity} ({rec.playbook_id})
                            </div>
                            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>{rec.reason}</div>
                          </div>
                          <button
                            onClick={() => handleRequestAction(rec)}
                            disabled={actionProcessing}
                            className="btn-primary"
                            style={{ fontSize: "0.75rem", padding: "0.3rem 0.7rem" }}
                          >
                            Request Action
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Action Requests Queue */}
                <div>
                  <h4 style={{ fontSize: "0.9rem", fontWeight: 600, color: "#f8fafc", marginBottom: "0.6rem" }}>
                    Action Requests & Human Approvals
                  </h4>
                  {actions.length === 0 ? (
                    <div style={{ padding: "1.5rem", background: "rgba(10, 15, 29, 0.7)", borderRadius: "8px", color: "var(--text-muted)", textAlign: "center", fontSize: "0.8rem" }}>
                      No action requests created yet. Run an investigation or request a recommended playbook above.
                    </div>
                  ) : (
                    <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                      {actions.map((act) => (
                        <div
                          key={act.id}
                          style={{
                            background: "rgba(10, 15, 29, 0.7)",
                            padding: "1rem",
                            borderRadius: "8px",
                            border: `1px solid ${
                              act.verification_status === "VERIFIED"
                                ? "rgba(16, 185, 129, 0.4)"
                                : act.verification_status === "VERIFICATION_FAILED"
                                ? "rgba(244, 63, 94, 0.4)"
                                : "var(--border-color)"
                            }`,
                            display: "flex",
                            flexDirection: "column",
                            gap: "0.5rem",
                          }}
                        >
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                            <div>
                              <div style={{ fontWeight: 600, color: "#f8fafc", fontSize: "0.9rem" }}>
                                {act.action_type} on {act.target_type}: {act.target_entity}
                              </div>
                              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.15rem" }}>
                                Playbook: {act.playbook_id} | Requires: {act.required_approval_role}
                              </div>
                            </div>
                            <div style={{ display: "flex", gap: "0.4rem" }}>
                              <span style={{ fontSize: "0.7rem", padding: "0.2rem 0.5rem", borderRadius: "4px", background: "rgba(255,255,255,0.05)", color: "#f8fafc" }}>
                                Approval: {act.approval_status}
                              </span>
                              <span style={{ fontSize: "0.7rem", padding: "0.2rem 0.5rem", borderRadius: "4px", background: act.verification_status === "VERIFIED" ? "rgba(16, 185, 129, 0.2)" : "rgba(255,255,255,0.05)", color: act.verification_status === "VERIFIED" ? "#34d399" : "var(--text-muted)" }}>
                                Verification: {act.verification_status}
                              </span>
                            </div>
                          </div>

                          {/* Approval / Execution Buttons */}
                          <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.25rem" }}>
                            {act.approval_status === "REQUESTED" && (
                              <>
                                <button
                                  onClick={() => handleApproveAction(act.id)}
                                  disabled={actionProcessing}
                                  className="btn-primary"
                                  style={{ fontSize: "0.75rem", padding: "0.3rem 0.75rem", background: "#10b981", borderColor: "#10b981" }}
                                >
                                  [APPROVE]
                                </button>
                                <button
                                  onClick={() => handleRejectAction(act.id)}
                                  disabled={actionProcessing}
                                  className="btn-secondary"
                                  style={{ fontSize: "0.75rem", padding: "0.3rem 0.75rem", color: "#fb7185" }}
                                >
                                  [REJECT]
                                </button>
                              </>
                            )}
                            {act.approval_status === "APPROVED" && act.execution_status === "PENDING" && (
                              <button
                                onClick={() => handleExecuteAction(act.id)}
                                disabled={actionProcessing}
                                className="btn-primary"
                                style={{ fontSize: "0.75rem", padding: "0.3rem 0.75rem" }}
                              >
                                [EXECUTE ACTION]
                              </button>
                            )}
                          </div>

                          {/* Verification State Inspection */}
                          {act.verification_status !== "PENDING" && (
                            <div style={{ background: "rgba(0, 0, 0, 0.3)", padding: "0.6rem", borderRadius: "6px", fontSize: "0.75rem", marginTop: "0.25rem" }}>
                              <div style={{ fontWeight: 600, color: act.verification_status === "VERIFIED" ? "#34d399" : "#fb7185" }}>
                                {act.verification_status === "VERIFIED" ? "✓ Containment Verified" : "✗ Verification Failed"}
                              </div>
                              <div className="mono" style={{ color: "var(--text-muted)", fontSize: "0.7rem", marginTop: "0.2rem" }}>
                                Before: {JSON.stringify(act.evidence_before)} &rarr; After: {JSON.stringify(act.evidence_after)}
                              </div>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* TAB 4: Tier-2 SOC Escalation */}
            {activeTab === "ESCALATION" && (
              <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                <div style={{ fontSize: "0.85rem", color: "var(--text-secondary)" }}>
                  Tier-2 SOC Escalation packages forensic context, evidence artifacts, timeline, and recommended next steps for Senior Analysts.
                </div>

                {!escalation ? (
                  <div style={{ background: "rgba(10, 15, 29, 0.7)", padding: "1.25rem", borderRadius: "8px", border: "1px solid var(--border-color)", display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                    <h4 style={{ fontSize: "0.9rem", fontWeight: 600, color: "#f8fafc", margin: 0 }}>
                      Escalate Incident to Tier-2 Queue
                    </h4>
                    <textarea
                      value={escalationReason}
                      onChange={(e) => setEscalationReason(e.target.value)}
                      placeholder="Specify escalation justification (e.g. Critical multi-host spread, privileged account compromise exceeding L1 remit)..."
                      rows={3}
                      style={{
                        width: "100%",
                        padding: "0.6rem",
                        borderRadius: "6px",
                        background: "rgba(0, 0, 0, 0.4)",
                        border: "1px solid var(--border-color)",
                        color: "#f8fafc",
                        fontSize: "0.8rem",
                      }}
                    />
                    <button
                      onClick={handleEscalateIncident}
                      disabled={actionProcessing}
                      className="btn-primary"
                      style={{ alignSelf: "flex-start", background: "#f43f5e", borderColor: "#f43f5e" }}
                    >
                      [ESCALATE TO L2 ANALYST]
                    </button>
                  </div>
                ) : (
                  <div style={{ background: "rgba(10, 15, 29, 0.7)", padding: "1.25rem", borderRadius: "8px", border: "1px solid rgba(244, 63, 94, 0.4)", display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span style={{ fontWeight: 700, color: "#fb7185", fontSize: "0.9rem" }}>
                        Active L2 Escalation Package (Status: {escalation.status})
                      </span>
                      <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                        Urgency: {escalation.urgency}
                      </span>
                    </div>
                    <div style={{ fontSize: "0.8rem", color: "#f8fafc" }}>
                      <strong>Why Escalated:</strong> {escalation.reason}
                    </div>

                    <div style={{ background: "rgba(0, 0, 0, 0.3)", padding: "0.75rem", borderRadius: "6px" }}>
                      <span style={{ fontSize: "0.7rem", color: "var(--text-muted)", textTransform: "uppercase" }}>Recommended Next Investigation</span>
                      <ul style={{ margin: "0.3rem 0 0 1rem", padding: 0, fontSize: "0.75rem", color: "var(--text-secondary)" }}>
                        {(escalation.l2_package?.recommended_next_investigation || []).map((step: string, sIdx: number) => (
                          <li key={sIdx}>{step}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                )}
              </div>
            )}

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
                    fontSize: "0.85rem",
                  }}
                />
              </div>

              <div>
                <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-secondary)", marginBottom: "0.3rem" }}>
                  Description
                </label>
                <textarea
                  required
                  rows={3}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Detailed description of adversary activity or triage notes..."
                  style={{
                    width: "100%",
                    padding: "0.65rem 0.75rem",
                    background: "rgba(10, 15, 29, 0.8)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "6px",
                    color: "#f8fafc",
                    fontSize: "0.85rem",
                    resize: "vertical",
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
                      padding: "0.65rem 0.75rem",
                      background: "rgba(10, 15, 29, 0.8)",
                      border: "1px solid var(--border-color)",
                      borderRadius: "6px",
                      color: "#f8fafc",
                      fontSize: "0.85rem",
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
                    Calculated Risk Score
                  </label>
                  <input
                    type="number"
                    min="0"
                    max="100"
                    value={riskScore}
                    onChange={(e) => setRiskScore(parseFloat(e.target.value))}
                    style={{
                      width: "100%",
                      padding: "0.65rem 0.75rem",
                      background: "rgba(10, 15, 29, 0.8)",
                      border: "1px solid var(--border-color)",
                      borderRadius: "6px",
                      color: "#f8fafc",
                      fontSize: "0.85rem",
                    }}
                  />
                </div>
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.75rem", marginTop: "0.5rem" }}>
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="btn-secondary"
                  disabled={submitting}
                >
                  Cancel
                </button>
                <button type="submit" className="btn-primary" disabled={submitting}>
                  {submitting ? "Creating..." : "Create Incident"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
