import React, { useEffect, useState } from "react";
import { DetectionRule, User } from "../types";
import { api } from "../services/api";
import { StatusBadge } from "../components/StatusBadge";

interface RulesPageProps {
  currentUser?: User | null;
}

const RulesPage: React.FC<RulesPageProps> = ({ currentUser }) => {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [showCreateModal, setShowCreateModal] = useState(false);

  // Form State
  const [newRuleId, setNewRuleId] = useState("");
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [newSeverity, setNewSeverity] = useState<"LOW" | "MEDIUM" | "HIGH" | "CRITICAL">("HIGH");
  const [newConfidence, setNewConfidence] = useState(0.95);
  const [newTechniques, setNewTechniques] = useState("T1110.001");
  const [newEventType, setNewEventType] = useState("AUTH_FAILURE");
  const [submitting, setSubmitting] = useState(false);

  const isEngineerOrAdmin =
    currentUser?.role &&
    ["TENANT_ADMIN", "SECURITY_ENGINEER", "SECURITY_MANAGER", "CISO"].includes(currentUser.role);

  const fetchRules = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getDetectionRules();
      setRules(data);
    } catch (err: any) {
      setError(err.message || "Failed to load detection rules.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleToggleRule = async (rule: DetectionRule) => {
    if (!isEngineerOrAdmin) {
      alert("Insufficient permissions: Only Security Engineers and Admins may toggle rules.");
      return;
    }
    if (!rule.tenant_id) {
      alert("Global system rules are read-only baseline definitions. Create a tenant-specific rule to customize.");
      return;
    }
    try {
      const updated = await api.updateDetectionRule(rule.rule_id, {
        enabled: !rule.enabled,
      });
      setRules((prev) => prev.map((r) => (r.rule_id === updated.rule_id ? updated : r)));
    } catch (err: any) {
      alert(`Error toggling rule: ${err.message}`);
    }
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSubmitting(true);
      const techList = newTechniques
        .split(",")
        .map((t) => t.trim().toUpperCase())
        .filter(Boolean);

      const created = await api.createDetectionRule({
        rule_id: newRuleId.trim(),
        name: newName.trim(),
        description: newDesc.trim(),
        severity: newSeverity,
        confidence: Number(newConfidence),
        enabled: true,
        event_types: [newEventType.trim().toUpperCase()],
        conditions: {
          selections: {
            selection: {
              event_type: newEventType.trim().toUpperCase(),
            },
          },
          condition: "selection",
        },
        mitre_tactics: ["Credential Access"],
        mitre_techniques: techList,
        tags: ["custom", "tenant-created"],
      });

      setRules((prev) => [created, ...prev]);
      setShowCreateModal(false);
      // Reset
      setNewRuleId("");
      setNewName("");
      setNewDesc("");
    } catch (err: any) {
      alert(`Failed to create rule: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const filteredRules = rules.filter((r) => {
    const matchesSearch =
      r.rule_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      r.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (r.mitre_techniques && r.mitre_techniques.some((t) => t.toLowerCase().includes(searchTerm.toLowerCase())));
    const matchesSeverity = severityFilter === "ALL" || r.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="container" style={{ padding: "2rem 0" }}>
      {/* Header Banner */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "2rem",
          flexWrap: "wrap",
          gap: "1rem",
        }}
      >
        <div>
          <h1 style={{ fontSize: "1.75rem", fontWeight: 700, margin: 0, color: "#f8fafc" }}>
            Detection Engineering & Rules
          </h1>
          <p style={{ color: "#94a3b8", fontSize: "0.875rem", margin: "0.25rem 0 0 0" }}>
            Authoritative Sigma-compatible detections mapped to MITRE ATT&CK techniques with tenant boundary isolation.
          </p>
        </div>
        <div style={{ display: "flex", gap: "0.75rem" }}>
          {isEngineerOrAdmin && (
            <button
              onClick={() => setShowCreateModal(true)}
              style={{
                backgroundColor: "#3b82f6",
                color: "#ffffff",
                border: "none",
                borderRadius: "6px",
                padding: "0.6rem 1.2rem",
                fontWeight: 600,
                fontSize: "0.875rem",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                gap: "0.5rem",
              }}
            >
              <span>+</span> Create Custom Rule
            </button>
          )}
          <button
            onClick={fetchRules}
            style={{
              backgroundColor: "#1e293b",
              color: "#94a3b8",
              border: "1px solid #334155",
              borderRadius: "6px",
              padding: "0.6rem 1rem",
              fontSize: "0.875rem",
              cursor: "pointer",
            }}
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div
        className="glass-card"
        style={{
          display: "flex",
          gap: "1rem",
          padding: "1rem 1.25rem",
          marginBottom: "1.5rem",
          alignItems: "center",
          flexWrap: "wrap",
        }}
      >
        <div style={{ flex: 1, minWidth: "240px" }}>
          <input
            type="text"
            placeholder="Search by rule ID, title, or MITRE technique (e.g. T1110)..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              width: "100%",
              padding: "0.6rem 0.85rem",
              backgroundColor: "#0f172a",
              border: "1px solid #334155",
              borderRadius: "6px",
              color: "#f8fafc",
              fontSize: "0.875rem",
            }}
          />
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <span style={{ fontSize: "0.8rem", color: "#94a3b8" }}>Severity:</span>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            style={{
              padding: "0.55rem 0.85rem",
              backgroundColor: "#0f172a",
              border: "1px solid #334155",
              borderRadius: "6px",
              color: "#f8fafc",
              fontSize: "0.875rem",
            }}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {/* Rules Table */}
      {loading ? (
        <div className="glass-card" style={{ padding: "3rem", textAlign: "center", color: "#94a3b8" }}>
          Loading active detection rules...
        </div>
      ) : error ? (
        <div
          className="glass-card"
          style={{ padding: "2rem", color: "#ef4444", border: "1px solid #ef4444", textAlign: "center" }}
        >
          {error}
        </div>
      ) : filteredRules.length === 0 ? (
        <div className="glass-card" style={{ padding: "3rem", textAlign: "center", color: "#94a3b8" }}>
          No detection rules match your query.
        </div>
      ) : (
        <div className="glass-card" style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #334155", color: "#94a3b8", fontSize: "0.75rem", textTransform: "uppercase" }}>
                <th style={{ padding: "1rem" }}>Rule ID</th>
                <th style={{ padding: "1rem" }}>Rule Name & Description</th>
                <th style={{ padding: "1rem" }}>Severity</th>
                <th style={{ padding: "1rem" }}>Confidence</th>
                <th style={{ padding: "1rem" }}>MITRE ATT&CK</th>
                <th style={{ padding: "1rem" }}>Scope</th>
                <th style={{ padding: "1rem" }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredRules.map((rule) => (
                <tr
                  key={rule.id}
                  style={{
                    borderBottom: "1px solid #1e293b",
                    fontSize: "0.875rem",
                    transition: "background-color 0.15s ease",
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = "rgba(30, 41, 59, 0.5)")}
                  onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = "transparent")}
                >
                  <td style={{ padding: "1rem", fontFamily: "monospace", color: "#60a5fa", fontWeight: 600 }}>
                    {rule.rule_id}
                  </td>
                  <td style={{ padding: "1rem", maxWidth: "340px" }}>
                    <div style={{ fontWeight: 600, color: "#f8fafc", marginBottom: "0.25rem" }}>{rule.name}</div>
                    <div style={{ color: "#94a3b8", fontSize: "0.8rem", lineHeight: 1.4 }}>{rule.description}</div>
                  </td>
                  <td style={{ padding: "1rem" }}>
                    <StatusBadge label={rule.severity} variant="severity" />
                  </td>
                  <td style={{ padding: "1rem", color: "#38bdf8", fontWeight: 600 }}>
                    {Math.round(rule.confidence * 100)}%
                  </td>
                  <td style={{ padding: "1rem" }}>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "0.35rem" }}>
                      {rule.mitre_techniques && rule.mitre_techniques.length > 0 ? (
                        rule.mitre_techniques.map((t) => (
                          <span
                            key={t}
                            style={{
                              backgroundColor: "rgba(239, 68, 68, 0.15)",
                              color: "#f87171",
                              border: "1px solid rgba(239, 68, 68, 0.3)",
                              padding: "0.15rem 0.45rem",
                              borderRadius: "4px",
                              fontSize: "0.75rem",
                              fontWeight: 600,
                              fontFamily: "monospace",
                            }}
                          >
                            {t}
                          </span>
                        ))
                      ) : (
                        <span style={{ color: "#64748b", fontSize: "0.75rem" }}>None</span>
                      )}
                    </div>
                  </td>
                  <td style={{ padding: "1rem" }}>
                    {rule.tenant_id ? (
                      <span
                        style={{
                          backgroundColor: "rgba(59, 130, 246, 0.15)",
                          color: "#60a5fa",
                          border: "1px solid rgba(59, 130, 246, 0.3)",
                          padding: "0.2rem 0.5rem",
                          borderRadius: "4px",
                          fontSize: "0.75rem",
                          fontWeight: 500,
                        }}
                      >
                        Custom Tenant
                      </span>
                    ) : (
                      <span
                        style={{
                          backgroundColor: "rgba(16, 185, 129, 0.15)",
                          color: "#34d399",
                          border: "1px solid rgba(16, 185, 129, 0.3)",
                          padding: "0.2rem 0.5rem",
                          borderRadius: "4px",
                          fontSize: "0.75rem",
                          fontWeight: 500,
                        }}
                      >
                        Global System
                      </span>
                    )}
                  </td>
                  <td style={{ padding: "1rem" }}>
                    <button
                      onClick={() => handleToggleRule(rule)}
                      title={rule.tenant_id ? "Click to toggle" : "Global rule (read-only)"}
                      style={{
                        backgroundColor: rule.enabled ? "rgba(16, 185, 129, 0.2)" : "rgba(100, 116, 139, 0.2)",
                        color: rule.enabled ? "#34d399" : "#94a3b8",
                        border: `1px solid ${rule.enabled ? "rgba(16, 185, 129, 0.4)" : "#475569"}`,
                        padding: "0.3rem 0.75rem",
                        borderRadius: "12px",
                        fontSize: "0.75rem",
                        fontWeight: 600,
                        cursor: rule.tenant_id ? "pointer" : "default",
                      }}
                    >
                      {rule.enabled ? "ACTIVE" : "DISABLED"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Modal: Create Custom Rule */}
      {showCreateModal && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: "rgba(0, 0, 0, 0.75)",
            backdropFilter: "blur(4px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
          }}
        >
          <div
            className="glass-card"
            style={{
              width: "100%",
              maxWidth: "540px",
              padding: "2rem",
              borderRadius: "12px",
              boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.5)",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.25rem" }}>
              <h2 style={{ fontSize: "1.25rem", fontWeight: 700, margin: 0, color: "#f8fafc" }}>
                Create Custom Detection Rule
              </h2>
              <button
                onClick={() => setShowCreateModal(false)}
                style={{
                  background: "transparent",
                  border: "none",
                  color: "#94a3b8",
                  fontSize: "1.25rem",
                  cursor: "pointer",
                }}
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateRule} style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
              <div>
                <label style={{ display: "block", fontSize: "0.8rem", color: "#94a3b8", marginBottom: "0.35rem" }}>
                  Rule Identifier (e.g. CUSTOM-SSH-MONITOR)
                </label>
                <input
                  type="text"
                  required
                  placeholder="CUSTOM-RULE-01"
                  value={newRuleId}
                  onChange={(e) => setNewRuleId(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "0.6rem 0.85rem",
                    backgroundColor: "#0f172a",
                    border: "1px solid #334155",
                    borderRadius: "6px",
                    color: "#f8fafc",
                    fontSize: "0.875rem",
                  }}
                />
              </div>

              <div>
                <label style={{ display: "block", fontSize: "0.8rem", color: "#94a3b8", marginBottom: "0.35rem" }}>
                  Rule Name
                </label>
                <input
                  type="text"
                  required
                  placeholder="Suspicious Access Anomaly"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "0.6rem 0.85rem",
                    backgroundColor: "#0f172a",
                    border: "1px solid #334155",
                    borderRadius: "6px",
                    color: "#f8fafc",
                    fontSize: "0.875rem",
                  }}
                />
              </div>

              <div>
                <label style={{ display: "block", fontSize: "0.8rem", color: "#94a3b8", marginBottom: "0.35rem" }}>
                  Description
                </label>
                <textarea
                  required
                  rows={2}
                  placeholder="Detailed detection rationale and forensic scope..."
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "0.6rem 0.85rem",
                    backgroundColor: "#0f172a",
                    border: "1px solid #334155",
                    borderRadius: "6px",
                    color: "#f8fafc",
                    fontSize: "0.875rem",
                  }}
                />
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "#94a3b8", marginBottom: "0.35rem" }}>
                    Severity
                  </label>
                  <select
                    value={newSeverity}
                    onChange={(e: any) => setNewSeverity(e.target.value)}
                    style={{
                      width: "100%",
                      padding: "0.6rem 0.85rem",
                      backgroundColor: "#0f172a",
                      border: "1px solid #334155",
                      borderRadius: "6px",
                      color: "#f8fafc",
                      fontSize: "0.875rem",
                    }}
                  >
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "#94a3b8", marginBottom: "0.35rem" }}>
                    Confidence (0.1 - 1.0)
                  </label>
                  <input
                    type="number"
                    step="0.05"
                    min="0.1"
                    max="1.0"
                    value={newConfidence}
                    onChange={(e) => setNewConfidence(parseFloat(e.target.value))}
                    style={{
                      width: "100%",
                      padding: "0.6rem 0.85rem",
                      backgroundColor: "#0f172a",
                      border: "1px solid #334155",
                      borderRadius: "6px",
                      color: "#f8fafc",
                      fontSize: "0.875rem",
                    }}
                  />
                </div>
              </div>

              <div>
                <label style={{ display: "block", fontSize: "0.8rem", color: "#94a3b8", marginBottom: "0.35rem" }}>
                  Target Event Type (e.g. AUTH_FAILURE, PROCESS_CREATE)
                </label>
                <input
                  type="text"
                  required
                  placeholder="AUTH_FAILURE"
                  value={newEventType}
                  onChange={(e) => setNewEventType(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "0.6rem 0.85rem",
                    backgroundColor: "#0f172a",
                    border: "1px solid #334155",
                    borderRadius: "6px",
                    color: "#f8fafc",
                    fontSize: "0.875rem",
                  }}
                />
              </div>

              <div>
                <label style={{ display: "block", fontSize: "0.8rem", color: "#94a3b8", marginBottom: "0.35rem" }}>
                  MITRE ATT&CK Techniques (comma-separated, e.g. T1110, T1078)
                </label>
                <input
                  type="text"
                  required
                  placeholder="T1110, T1110.001"
                  value={newTechniques}
                  onChange={(e) => setNewTechniques(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "0.6rem 0.85rem",
                    backgroundColor: "#0f172a",
                    border: "1px solid #334155",
                    borderRadius: "6px",
                    color: "#f8fafc",
                    fontSize: "0.875rem",
                  }}
                />
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.75rem", marginTop: "1rem" }}>
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  style={{
                    backgroundColor: "transparent",
                    color: "#94a3b8",
                    border: "1px solid #334155",
                    padding: "0.6rem 1.25rem",
                    borderRadius: "6px",
                    fontSize: "0.875rem",
                    cursor: "pointer",
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  style={{
                    backgroundColor: "#3b82f6",
                    color: "#ffffff",
                    border: "none",
                    padding: "0.6rem 1.25rem",
                    borderRadius: "6px",
                    fontSize: "0.875rem",
                    fontWeight: 600,
                    cursor: submitting ? "not-allowed" : "pointer",
                  }}
                >
                  {submitting ? "Creating..." : "Save Rule"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default RulesPage;
