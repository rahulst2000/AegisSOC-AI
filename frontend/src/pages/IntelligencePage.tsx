import React, { useEffect, useState } from "react";
import {
  Brain,
  Network,
  GitCommit,
  HelpCircle,
  PlayCircle,
  Cpu,
  Layers,
  Shield,
  RefreshCw,
  Search,
} from "lucide-react";
import { api } from "../services/api";
import {
  AttackGraphResponse,
  AttackTrajectoryReport,
  BlastRadiusReport,
  CounterfactualResult,
  ExecutivePostureResponse,
  GrcControlItem,
  SecurityStateRecord,
  ThreatIntelResult,
  WhyNowReport,
  Incident,
} from "../types";

interface IntelligencePageProps {
  incidents: Incident[];
}

export const IntelligencePage: React.FC<IntelligencePageProps> = ({ incidents }) => {
  const [activeSubTab, setActiveSubTab] = useState<
    "state" | "trajectory" | "graph" | "reasoning" | "counterfactual" | "twin" | "intel" | "posture"
  >("state");

  const [loading, setLoading] = useState(false);
  const [stateRecord, setStateRecord] = useState<SecurityStateRecord | null>(null);
  const [graphData, setGraphData] = useState<AttackGraphResponse | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>(incidents[0]?.id || "");
  const [trajectory, setTrajectory] = useState<AttackTrajectoryReport | null>(null);
  const [whyNow, setWhyNow] = useState<WhyNowReport | null>(null);

  // Counterfactual
  const [cfScenario, setCfScenario] = useState<string>("ISOLATE_HOST");
  const [cfResult, setCfResult] = useState<CounterfactualResult | null>(null);

  // Blast Radius
  const [blastTarget, setBlastTarget] = useState<string>("lab-host-alpha");
  const [blastResult, setBlastResult] = useState<BlastRadiusReport | null>(null);

  // Threat Intel
  const [tiIndicator, setTiIndicator] = useState<string>("198.51.100.44");
  const [tiType, setTiType] = useState<string>("ip");
  const [tiResult, setTiResult] = useState<ThreatIntelResult | null>(null);

  // Posture & GRC
  const [posture, setPosture] = useState<ExecutivePostureResponse | null>(null);
  const [grcControls, setGrcControls] = useState<GrcControlItem[]>([]);

  // Candidates
  const [candidates, setCandidates] = useState<any[]>([]);

  const loadState = async () => {
    try {
      const res = await api.getSecurityState();
      setStateRecord(res);
    } catch {
      // Ignored in demo if not populated
    }
  };

  const loadGraph = async () => {
    try {
      const res = await api.getAttackGraph();
      setGraphData(res);
    } catch {
      // Handled
    }
  };

  const loadPostureAndGrc = async () => {
    try {
      const [pos, grc, cand] = await Promise.all([
        api.getExecutivePosture().catch(() => null),
        api.getGrcControls().catch(() => []),
        api.getImprovementCandidates().catch(() => []),
      ]);
      setPosture(pos);
      setGrcControls(grc);
      setCandidates(cand);
    } catch {
      // Handled
    }
  };

  const loadIncidentIntelligence = async (incId: string) => {
    if (!incId) return;
    setLoading(true);
    try {
      const [traj, wn] = await Promise.all([
        api.getAttackTrajectory(incId).catch(() => null),
        api.getWhyNow(incId).catch(() => null),
      ]);
      setTrajectory(traj);
      setWhyNow(wn);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadState();
    loadGraph();
    loadPostureAndGrc();
  }, []);

  useEffect(() => {
    if (selectedIncidentId) {
      loadIncidentIntelligence(selectedIncidentId);
    }
  }, [selectedIncidentId]);

  const handleSimulateCounterfactual = async () => {
    if (!selectedIncidentId) return;
    setLoading(true);
    try {
      const res = await api.runCounterfactual(selectedIncidentId, cfScenario);
      setCfResult(res);
    } finally {
      setLoading(false);
    }
  };

  const handleCalculateBlastRadius = async () => {
    setLoading(true);
    try {
      const res = await api.getBlastRadius(blastTarget);
      setBlastResult(res);
    } finally {
      setLoading(false);
    }
  };

  const handleLookupThreatIntel = async () => {
    setLoading(true);
    try {
      const res = await api.getThreatIntel(tiType, tiIndicator);
      setTiResult(res);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      {/* Top Banner */}
      <div
        className="glass-panel"
        style={{
          padding: "1.5rem",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          background: "linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(99, 102, 241, 0.1) 100%)",
          border: "1px solid rgba(99, 102, 241, 0.25)",
        }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", marginBottom: "0.25rem" }}>
            <Brain size={24} style={{ color: "#818cf8" }} />
            <h2 style={{ fontSize: "1.35rem", fontWeight: 700, color: "#f8fafc", margin: 0 }}>
              Advanced Security Intelligence & Digital Twin
            </h2>
            <span
              style={{
                fontSize: "0.75rem",
                padding: "0.2rem 0.5rem",
                borderRadius: "4px",
                background: "rgba(99, 102, 241, 0.15)",
                color: "#a5b4fc",
                fontWeight: 600,
                border: "1px solid rgba(99, 102, 241, 0.3)",
              }}
            >
              Phase 5B Verified
            </span>
          </div>
          <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", margin: 0 }}>
            Dynamic security state modeling, evidence-based attack trajectory, tenant-isolated graphs, and counterfactual simulation.
          </p>
        </div>

        <button
          onClick={() => {
            loadState();
            loadGraph();
            loadPostureAndGrc();
            if (selectedIncidentId) loadIncidentIntelligence(selectedIncidentId);
          }}
          className="btn-secondary"
          style={{ display: "flex", alignItems: "center", gap: "0.4rem", fontSize: "0.85rem" }}
        >
          <RefreshCw size={14} className={loading ? "spin" : ""} />
          Refresh Intelligence
        </button>
      </div>

      {/* Sub Tabs */}
      <div
        style={{
          display: "flex",
          gap: "0.5rem",
          borderBottom: "1px solid var(--border-color)",
          paddingBottom: "0.5rem",
          overflowX: "auto",
        }}
      >
        {[
          { id: "state", label: "5B-01 Security State (t)", icon: <Cpu size={16} /> },
          { id: "trajectory", label: "5B-02 Attack Trajectory", icon: <GitCommit size={16} /> },
          { id: "graph", label: "5B-03 Attack Graph", icon: <Network size={16} /> },
          { id: "reasoning", label: "5B-04/05 Why Now & Baseline", icon: <HelpCircle size={16} /> },
          { id: "counterfactual", label: "5B-06 Counterfactual Sim", icon: <PlayCircle size={16} /> },
          { id: "twin", label: "5B-07 Digital Twin & Blast", icon: <Layers size={16} /> },
          { id: "intel", label: "5B-09/10 Threat Intel & CI", icon: <Search size={16} /> },
          { id: "posture", label: "5B-12/14 Posture & GRC", icon: <Shield size={16} /> },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveSubTab(tab.id as any)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.45rem",
              padding: "0.55rem 0.95rem",
              borderRadius: "6px",
              border: "none",
              fontSize: "0.85rem",
              fontWeight: activeSubTab === tab.id ? 600 : 400,
              cursor: "pointer",
              background: activeSubTab === tab.id ? "rgba(99, 102, 241, 0.2)" : "transparent",
              color: activeSubTab === tab.id ? "#a5b4fc" : "var(--text-secondary)",
              transition: "all 0.15s ease",
            }}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* 5B-01: Dynamic Security State */}
      {activeSubTab === "state" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
          <div className="glass-panel" style={{ padding: "1.25rem" }}>
            <h3 style={{ fontSize: "1.05rem", fontWeight: 600, color: "#f8fafc", marginBottom: "0.75rem" }}>
              Dynamic Security State Model — SecurityState(t)
            </h3>
            <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", marginBottom: "1rem" }}>
              Cryptographically verified security posture snapshots. Every state transition requires immutable SHA-256 evidence linking.
            </p>

            {stateRecord ? (
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
                  gap: "1rem",
                  marginBottom: "1rem",
                }}
              >
                <div style={{ padding: "1rem", background: "rgba(15, 23, 42, 0.6)", borderRadius: "6px" }}>
                  <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>CURRENT POSTURE</div>
                  <div style={{ fontSize: "1.2rem", fontWeight: 700, color: "#38bdf8", marginTop: "0.25rem" }}>
                    {stateRecord.security_posture}
                  </div>
                </div>
                <div style={{ padding: "1rem", background: "rgba(15, 23, 42, 0.6)", borderRadius: "6px" }}>
                  <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>POSTURE RISK SCORE</div>
                  <div style={{ fontSize: "1.2rem", fontWeight: 700, color: "#f59e0b", marginTop: "0.25rem" }}>
                    {stateRecord.risk_score.toFixed(1)} / 100
                  </div>
                </div>
                <div style={{ padding: "1rem", background: "rgba(15, 23, 42, 0.6)", borderRadius: "6px" }}>
                  <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>ACTIVE INCIDENTS</div>
                  <div style={{ fontSize: "1.2rem", fontWeight: 700, color: "#f8fafc", marginTop: "0.25rem" }}>
                    {stateRecord.active_incidents_count}
                  </div>
                </div>
                <div style={{ padding: "1rem", background: "rgba(15, 23, 42, 0.6)", borderRadius: "6px" }}>
                  <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>STATE HASH (SHA-256)</div>
                  <div
                    style={{
                      fontSize: "0.75rem",
                      fontFamily: "monospace",
                      color: "#94a3b8",
                      marginTop: "0.4rem",
                      wordBreak: "break-all",
                    }}
                  >
                    {stateRecord.state_hash}
                  </div>
                </div>
              </div>
            ) : (
              <div style={{ padding: "1.5rem", textAlign: "center", color: "var(--text-muted)" }}>
                Click Refresh or ingest events to compute dynamic SecurityState(t).
              </div>
            )}
          </div>
        </div>
      )}

      {/* 5B-02: Attack Trajectory */}
      {activeSubTab === "trajectory" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
          <div className="glass-panel" style={{ padding: "1.25rem" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
              <div>
                <h3 style={{ fontSize: "1.05rem", fontWeight: 600, color: "#f8fafc", margin: 0 }}>
                  Probabilistic Evidence-Based Attack Trajectory
                </h3>
                <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                  Models progression from NORMAL to CONTAINED. All predictions are probabilistic with zero fabricated certainty.
                </span>
              </div>

              <select
                value={selectedIncidentId}
                onChange={(e) => setSelectedIncidentId(e.target.value)}
                style={{
                  background: "#0f172a",
                  color: "#f8fafc",
                  border: "1px solid var(--border-color)",
                  borderRadius: "6px",
                  padding: "0.4rem 0.75rem",
                  fontSize: "0.85rem",
                }}
              >
                {incidents.map((inc) => (
                  <option key={inc.id} value={inc.id}>
                    {inc.title} ({inc.severity})
                  </option>
                ))}
              </select>
            </div>

            {trajectory ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "1fr 1fr 1fr",
                    gap: "1rem",
                    background: "rgba(15, 23, 42, 0.6)",
                    padding: "1rem",
                    borderRadius: "6px",
                  }}
                >
                  <div>
                    <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>CURRENT STAGE</span>
                    <div style={{ fontSize: "1.1rem", fontWeight: 700, color: "#ef4444", marginTop: "0.2rem" }}>
                      {trajectory.current_stage}
                    </div>
                  </div>
                  <div>
                    <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>PREDICTED NEXT STAGE</span>
                    <div style={{ fontSize: "1.1rem", fontWeight: 700, color: "#f59e0b", marginTop: "0.2rem" }}>
                      {trajectory.predicted_next_stage}
                    </div>
                  </div>
                  <div>
                    <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>PREDICTION CONFIDENCE</span>
                    <div style={{ fontSize: "1.1rem", fontWeight: 700, color: "#38bdf8", marginTop: "0.2rem" }}>
                      {(trajectory.prediction_confidence * 100).toFixed(0)}%
                    </div>
                  </div>
                </div>

                <h4 style={{ fontSize: "0.9rem", color: "#f8fafc", margin: "0.5rem 0 0.25rem 0" }}>
                  Observed Evidence Progression
                </h4>
                <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                  {trajectory.observed_progression.map((stage, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: "0.75rem 1rem",
                        background: "rgba(15, 23, 42, 0.4)",
                        borderRadius: "6px",
                        borderLeft: "3px solid #6366f1",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                      }}
                    >
                      <div>
                        <span style={{ fontWeight: 600, color: "#e2e8f0", fontSize: "0.85rem" }}>{stage.stage}</span>
                        <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.2rem" }}>
                          Linked Event IDs: {stage.evidence_event_ids.join(", ") || "Baseline"}
                        </div>
                      </div>
                      <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>{stage.timestamp}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div style={{ padding: "1.5rem", textAlign: "center", color: "var(--text-muted)" }}>
                No active incident selected or no trajectory data available.
              </div>
            )}
          </div>
        </div>
      )}

      {/* 5B-03: Attack Graph */}
      {activeSubTab === "graph" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
          <div className="glass-panel" style={{ padding: "1.25rem" }}>
            <h3 style={{ fontSize: "1.05rem", fontWeight: 600, color: "#f8fafc", marginBottom: "0.5rem" }}>
              Tenant-Isolated Attack & Evidence Graph
            </h3>
            <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", marginBottom: "1rem" }}>
              Strict multi-tenant topology connecting SOURCE_IP → USER → HOST → PROCESS → MITRE Technique.
            </p>

            {graphData ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                <div style={{ display: "flex", gap: "1rem" }}>
                  <div style={{ padding: "0.5rem 1rem", background: "rgba(15, 23, 42, 0.6)", borderRadius: "6px" }}>
                    <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>GRAPH NODES: </span>
                    <span style={{ fontWeight: 700, color: "#38bdf8" }}>{graphData.nodes.length}</span>
                  </div>
                  <div style={{ padding: "0.5rem 1rem", background: "rgba(15, 23, 42, 0.6)", borderRadius: "6px" }}>
                    <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>RELATIONSHIP EDGES: </span>
                    <span style={{ fontWeight: 700, color: "#818cf8" }}>{graphData.edges.length}</span>
                  </div>
                </div>

                <div
                  style={{
                    maxHeight: "350px",
                    overflowY: "auto",
                    background: "rgba(10, 15, 29, 0.8)",
                    padding: "1rem",
                    borderRadius: "6px",
                    border: "1px solid var(--border-color)",
                    fontFamily: "monospace",
                    fontSize: "0.8rem",
                  }}
                >
                  <div style={{ color: "#38bdf8", marginBottom: "0.5rem", fontWeight: 600 }}>// VERIFIED EDGES</div>
                  {graphData.edges.map((edge, idx) => (
                    <div key={idx} style={{ padding: "0.3rem 0", color: "#cbd5e1" }}>
                      <span style={{ color: "#a5b4fc" }}>[{edge.source}]</span>
                      <span style={{ color: "#f59e0b" }}> --({edge.relationship})--&gt; </span>
                      <span style={{ color: "#38bdf8" }}>[{edge.target}]</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div style={{ padding: "1.5rem", textAlign: "center", color: "var(--text-muted)" }}>
                Loading attack graph...
              </div>
            )}
          </div>
        </div>
      )}

      {/* 5B-04 & 5B-05: Why Now & Baseline Reasoning */}
      {activeSubTab === "reasoning" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
          <div className="glass-panel" style={{ padding: "1.25rem" }}>
            <h3 style={{ fontSize: "1.05rem", fontWeight: 600, color: "#f8fafc", marginBottom: "0.5rem" }}>
              Why Now Engine — State Transition Root Cause
            </h3>
            <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", marginBottom: "1rem" }}>
              Explains why the security state elevated from baseline to incident using concrete evidence and confidence.
            </p>

            {whyNow ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                <div style={{ padding: "0.85rem", background: "rgba(15, 23, 42, 0.6)", borderRadius: "6px" }}>
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: 700 }}>WHAT CHANGED</span>
                  <ul style={{ margin: "0.4rem 0 0 1.2rem", padding: 0, fontSize: "0.85rem", color: "#f1f5f9" }}>
                    {whyNow.what_changed.map((change, idx) => (
                      <li key={idx}>{change}</li>
                    ))}
                  </ul>
                </div>

                <div style={{ padding: "0.85rem", background: "rgba(15, 23, 42, 0.6)", borderRadius: "6px" }}>
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: 700 }}>WHY IT MATTERS</span>
                  <p style={{ margin: "0.3rem 0 0 0", fontSize: "0.85rem", color: "#cbd5e1" }}>
                    {whyNow.why_it_matters}
                  </p>
                </div>

                <div style={{ display: "flex", gap: "1rem" }}>
                  <div style={{ padding: "0.5rem 1rem", background: "rgba(15, 23, 42, 0.6)", borderRadius: "6px" }}>
                    <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>CONFIDENCE: </span>
                    <span style={{ fontWeight: 700, color: "#38bdf8" }}>{(whyNow.confidence * 100).toFixed(0)}%</span>
                  </div>
                  <div style={{ padding: "0.5rem 1rem", background: "rgba(15, 23, 42, 0.6)", borderRadius: "6px" }}>
                    <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>EVIDENCE EVENT COUNT: </span>
                    <span style={{ fontWeight: 700, color: "#818cf8" }}>{whyNow.evidence_event_ids.length}</span>
                  </div>
                </div>
              </div>
            ) : (
              <div style={{ padding: "1.5rem", textAlign: "center", color: "var(--text-muted)" }}>
                Select an incident to evaluate "Why Now" reasoning.
              </div>
            )}
          </div>
        </div>
      )}

      {/* 5B-06: Counterfactual Security Analysis */}
      {activeSubTab === "counterfactual" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
          <div className="glass-panel" style={{ padding: "1.25rem" }}>
            <h3 style={{ fontSize: "1.05rem", fontWeight: 600, color: "#f8fafc", marginBottom: "0.5rem" }}>
              Counterfactual Security Analysis — Controlled Simulation
            </h3>
            <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", marginBottom: "1rem" }}>
              Simulates state transitions without executing real production actions. Answers: "What happens if we do nothing vs isolate host?"
            </p>

            <div style={{ display: "flex", gap: "0.75rem", alignItems: "center", marginBottom: "1rem" }}>
              <select
                value={cfScenario}
                onChange={(e) => setCfScenario(e.target.value)}
                style={{
                  background: "#0f172a",
                  color: "#f8fafc",
                  border: "1px solid var(--border-color)",
                  borderRadius: "6px",
                  padding: "0.45rem 0.75rem",
                  fontSize: "0.85rem",
                }}
              >
                <option value="DO_NOTHING">Scenario: DO_NOTHING (Passive)</option>
                <option value="ISOLATE_HOST">Scenario: ISOLATE_HOST (Host Quarantine)</option>
                <option value="REVOKE_SESSION">Scenario: REVOKE_SESSION (Identity Kill)</option>
                <option value="DISABLE_ACCOUNT">Scenario: DISABLE_ACCOUNT (Account Lock)</option>
              </select>

              <button
                onClick={handleSimulateCounterfactual}
                className="btn-primary"
                style={{ fontSize: "0.85rem", padding: "0.45rem 1rem" }}
              >
                Run Simulation
              </button>
            </div>

            {cfResult && (
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
                  gap: "1rem",
                  background: "rgba(15, 23, 42, 0.6)",
                  padding: "1rem",
                  borderRadius: "6px",
                }}
              >
                <div>
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>CURRENT STATE</span>
                  <div style={{ fontSize: "1.1rem", fontWeight: 700, color: "#f8fafc", marginTop: "0.2rem" }}>
                    {cfResult.current_state}
                  </div>
                </div>
                <div>
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>SIMULATED STATE</span>
                  <div style={{ fontSize: "1.1rem", fontWeight: 700, color: "#38bdf8", marginTop: "0.2rem" }}>
                    {cfResult.predicted_state}
                  </div>
                </div>
                <div>
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>ESTIMATED RISK CHANGE</span>
                  <div
                    style={{
                      fontSize: "1.2rem",
                      fontWeight: 700,
                      color: cfResult.risk_change <= 0 ? "#10b981" : "#ef4444",
                      marginTop: "0.2rem",
                    }}
                  >
                    {cfResult.risk_change > 0 ? `+${cfResult.risk_change.toFixed(1)}` : cfResult.risk_change.toFixed(1)}
                  </div>
                </div>
                <div>
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>BUSINESS IMPACT</span>
                  <div style={{ fontSize: "0.9rem", fontWeight: 500, color: "#a5b4fc", marginTop: "0.2rem" }}>
                    {cfResult.business_impact}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 5B-07: Digital Twin & Blast Radius */}
      {activeSubTab === "twin" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
          <div className="glass-panel" style={{ padding: "1.25rem" }}>
            <h3 style={{ fontSize: "1.05rem", fontWeight: 600, color: "#f8fafc", marginBottom: "0.5rem" }}>
              Security Digital Twin & Blast Radius Analysis
            </h3>
            <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", marginBottom: "1rem" }}>
              Calculates transitive reachability and lateral movement potential across enterprise assets.
            </p>

            <div style={{ display: "flex", gap: "0.75rem", alignItems: "center", marginBottom: "1rem" }}>
              <input
                type="text"
                placeholder="Target Hostname or Asset ID"
                value={blastTarget}
                onChange={(e) => setBlastTarget(e.target.value)}
                style={{
                  background: "#0f172a",
                  color: "#f8fafc",
                  border: "1px solid var(--border-color)",
                  borderRadius: "6px",
                  padding: "0.45rem 0.75rem",
                  fontSize: "0.85rem",
                }}
              />
              <button
                onClick={handleCalculateBlastRadius}
                className="btn-primary"
                style={{ fontSize: "0.85rem", padding: "0.45rem 1rem" }}
              >
                Compute Blast Radius
              </button>
            </div>

            {blastResult && (
              <div style={{ padding: "1rem", background: "rgba(15, 23, 42, 0.6)", borderRadius: "6px" }}>
                <div style={{ display: "flex", gap: "2rem", marginBottom: "0.75rem" }}>
                  <div>
                    <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>AFFECTED ASSETS: </span>
                    <span style={{ fontWeight: 700, color: "#f59e0b" }}>{blastResult.total_affected_assets}</span>
                  </div>
                  <div>
                    <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>PROPAGATION DEPTH: </span>
                    <span style={{ fontWeight: 700, color: "#38bdf8" }}>{blastResult.propagation_depth} hops</span>
                  </div>
                </div>
                <div style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>
                  Affected Entities: {blastResult.affected_assets.join(", ")}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 5B-09 & 5B-10: Threat Intel & Continuous Improvement */}
      {activeSubTab === "intel" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
          <div className="glass-panel" style={{ padding: "1.25rem" }}>
            <h3 style={{ fontSize: "1.05rem", fontWeight: 600, color: "#f8fafc", marginBottom: "0.5rem" }}>
              Hybrid Threat Intelligence Lookup
            </h3>
            <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", marginBottom: "1rem" }}>
              Evaluates indicators through provider abstraction combined with local telemetry and asset criticality.
            </p>

            <div style={{ display: "flex", gap: "0.75rem", alignItems: "center", marginBottom: "1rem" }}>
              <select
                value={tiType}
                onChange={(e) => setTiType(e.target.value)}
                style={{
                  background: "#0f172a",
                  color: "#f8fafc",
                  border: "1px solid var(--border-color)",
                  borderRadius: "6px",
                  padding: "0.45rem 0.75rem",
                  fontSize: "0.85rem",
                }}
              >
                <option value="ip">IP Address</option>
                <option value="domain">Domain Name</option>
                <option value="hash">SHA-256 Hash</option>
              </select>

              <input
                type="text"
                value={tiIndicator}
                onChange={(e) => setTiIndicator(e.target.value)}
                style={{
                  background: "#0f172a",
                  color: "#f8fafc",
                  border: "1px solid var(--border-color)",
                  borderRadius: "6px",
                  padding: "0.45rem 0.75rem",
                  fontSize: "0.85rem",
                  width: "220px",
                }}
              />

              <button
                onClick={handleLookupThreatIntel}
                className="btn-primary"
                style={{ fontSize: "0.85rem", padding: "0.45rem 1rem" }}
              >
                Query Threat Intel
              </button>
            </div>

            {tiResult && (
              <div style={{ padding: "1rem", background: "rgba(15, 23, 42, 0.6)", borderRadius: "6px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.75rem" }}>
                  <div>
                    <span style={{ fontWeight: 700, color: "#f8fafc", fontSize: "0.95rem" }}>
                      {tiResult.indicator_value}
                    </span>
                    <span
                      style={{
                        marginLeft: "0.5rem",
                        fontSize: "0.75rem",
                        padding: "0.2rem 0.4rem",
                        borderRadius: "4px",
                        background: tiResult.is_malicious ? "rgba(239, 68, 68, 0.2)" : "rgba(16, 185, 129, 0.2)",
                        color: tiResult.is_malicious ? "#ef4444" : "#10b981",
                        fontWeight: 600,
                      }}
                    >
                      {tiResult.is_malicious ? "KNOWN THREAT" : "BENIGN"}
                    </span>
                  </div>
                  <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                    Source: {tiResult.source_provider}
                  </span>
                </div>

                <div style={{ fontSize: "0.85rem", color: "#cbd5e1", marginTop: "0.5rem" }}>
                  <strong>Advisory:</strong> {tiResult.hybrid_evaluation?.action_advisory || "Standard monitoring"}
                </div>
              </div>
            )}

            <h4 style={{ fontSize: "0.95rem", color: "#f8fafc", marginTop: "1.5rem", marginBottom: "0.5rem" }}>
              5B-10: Continuous Improvement Candidates ({candidates.length})
            </h4>
            <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
              {candidates.length > 0 ? (
                candidates.map((cand, idx) => (
                  <div
                    key={idx}
                    style={{
                      padding: "0.75rem",
                      background: "rgba(15, 23, 42, 0.4)",
                      borderRadius: "6px",
                      border: "1px solid var(--border-color)",
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 600, color: "#f8fafc", fontSize: "0.85rem" }}>{cand.title}</div>
                      <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>{cand.rationale}</div>
                    </div>
                    <span
                      style={{
                        fontSize: "0.75rem",
                        padding: "0.2rem 0.5rem",
                        borderRadius: "4px",
                        background: cand.status === "DEPLOYED" ? "rgba(16, 185, 129, 0.2)" : "rgba(245, 158, 11, 0.2)",
                        color: cand.status === "DEPLOYED" ? "#10b981" : "#f59e0b",
                        fontWeight: 600,
                      }}
                    >
                      {cand.status}
                    </span>
                  </div>
                ))
              ) : (
                <div style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                  No pending detection improvement candidates in queue.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 5B-12/13/14: Executive Posture & GRC Intelligence */}
      {activeSubTab === "posture" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
          <div className="glass-panel" style={{ padding: "1.25rem" }}>
            <h3 style={{ fontSize: "1.05rem", fontWeight: 600, color: "#f8fafc", marginBottom: "0.5rem" }}>
              Executive Security Posture & GRC Assurance
            </h3>
            <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", marginBottom: "1rem" }}>
              Auditable compliance mapping to NIST CSF, ISO 27001, CIS Controls, SOC 2, and PCI DSS.
            </p>

            {posture ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                <div style={{ display: "flex", gap: "1.5rem" }}>
                  <div style={{ padding: "0.85rem 1.25rem", background: "rgba(15, 23, 42, 0.6)", borderRadius: "6px" }}>
                    <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>OVERALL POSTURE SCORE</span>
                    <div style={{ fontSize: "1.4rem", fontWeight: 700, color: "#10b981", marginTop: "0.2rem" }}>
                      {posture.overall_posture_score.toFixed(1)}%
                    </div>
                  </div>
                  <div style={{ padding: "0.85rem 1.25rem", background: "rgba(15, 23, 42, 0.6)", borderRadius: "6px" }}>
                    <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>ASSURANCE LEVEL</span>
                    <div style={{ fontSize: "1.4rem", fontWeight: 700, color: "#38bdf8", marginTop: "0.2rem" }}>
                      {posture.assurance_level}
                    </div>
                  </div>
                </div>

                <h4 style={{ fontSize: "0.9rem", color: "#f8fafc", margin: "0.5rem 0 0.25rem 0" }}>
                  Domain Scores (9 Executive Domains)
                </h4>
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
                    gap: "0.75rem",
                  }}
                >
                  {posture.domains.map((dom, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: "0.75rem",
                        background: "rgba(15, 23, 42, 0.5)",
                        borderRadius: "6px",
                        border: "1px solid var(--border-color)",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontSize: "0.8rem", fontWeight: 600, color: "#f1f5f9" }}>{dom.domain}</span>
                        <span style={{ fontSize: "0.85rem", fontWeight: 700, color: "#38bdf8" }}>{dom.score}%</span>
                      </div>
                      <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.25rem" }}>
                        Status: {dom.status} ({dom.evidence_count} evidence records)
                      </div>
                    </div>
                  ))}
                </div>

                <h4 style={{ fontSize: "0.9rem", color: "#f8fafc", margin: "1rem 0 0.25rem 0" }}>
                  5B-13: GRC Controls Coverage ({grcControls.length} Controls Mapped)
                </h4>
                <div style={{ maxHeight: "250px", overflowY: "auto" }}>
                  <table style={{ width: "100%", fontSize: "0.8rem", textAlign: "left", borderCollapse: "collapse" }}>
                    <thead>
                      <tr style={{ color: "var(--text-muted)", borderBottom: "1px solid var(--border-color)" }}>
                        <th style={{ padding: "0.5rem" }}>CONTROL ID</th>
                        <th style={{ padding: "0.5rem" }}>FRAMEWORK</th>
                        <th style={{ padding: "0.5rem" }}>TITLE</th>
                        <th style={{ padding: "0.5rem" }}>STATUS</th>
                        <th style={{ padding: "0.5rem" }}>EVIDENCE</th>
                      </tr>
                    </thead>
                    <tbody>
                      {grcControls.map((c, i) => (
                        <tr key={i} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                          <td style={{ padding: "0.5rem", color: "#38bdf8", fontWeight: 600 }}>{c.control_id}</td>
                          <td style={{ padding: "0.5rem", color: "#a5b4fc" }}>{c.framework}</td>
                          <td style={{ padding: "0.5rem", color: "#f8fafc" }}>{c.title}</td>
                          <td style={{ padding: "0.5rem", color: "#10b981" }}>{c.status}</td>
                          <td style={{ padding: "0.5rem", color: "var(--text-muted)" }}>{c.evidence_count} items</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <div style={{ padding: "1.5rem", textAlign: "center", color: "var(--text-muted)" }}>
                Loading executive posture data...
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
