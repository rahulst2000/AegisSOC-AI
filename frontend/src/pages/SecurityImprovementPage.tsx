import React, { useEffect, useState } from "react";
import { api } from "../services/api";
import {
  DetectionGapReport,
  MitreCoverageItem,
  SecurityFinding,
  SecurityPostureReport,
} from "../types";

export const SecurityImprovementPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<"posture" | "gaps" | "coverage" | "findings" | "tuning">("posture");
  const [posture, setPosture] = useState<SecurityPostureReport | null>(null);
  const [gaps, setGaps] = useState<DetectionGapReport[]>([]);
  const [coverage, setCoverage] = useState<MitreCoverageItem[]>([]);
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [tuningRecommendations, setTuningRecommendations] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Remediation Modal State
  const [selectedFinding, setSelectedFinding] = useState<SecurityFinding | null>(null);
  const [showRemediateModal, setShowRemediateModal] = useState<boolean>(false);
  const [proposedChange, setProposedChange] = useState<string>("");
  const [changeType, setChangeType] = useState<string>("RULE_UPDATE");

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [pos, gapData, covData, findData, tuneData] = await Promise.all([
        api.getPosture(),
        api.getGaps(),
        api.getCoverage(),
        api.getFindings(),
        api.getTuningRecommendations(),
      ]);
      setPosture(pos);
      setGaps(gapData);
      setCoverage(covData);
      setFindings(findData);
      setTuningRecommendations(tuneData);
    } catch (err: any) {
      if (err?.isAuthError || err?.status === 401) {
        setError("Authentication expired — please sign in again.");
      } else if (err?.isForbidden || err?.status === 403) {
        setError("Access denied — your role does not have permission for continuous security improvement.");
      } else {
        setError(err.message || "Failed to load continuous improvement data.");
      }
    } finally {
      setLoading(false);
    }
  };


  useEffect(() => {
    loadData();
  }, []);

  const handleProposeRemediation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFinding) return;
    setActionLoading(true);
    setError(null);
    try {
      await api.remediateFinding(selectedFinding.id, {
        proposed_change: proposedChange,
        change_type: changeType,
      });
      setSuccessMsg("Remediation proposed! Requires human sign-off before application.");
      setShowRemediateModal(false);
      setProposedChange("");
      await loadData();
    } catch (err: any) {
      setError(err.message || "Failed to propose remediation");
    } finally {
      setActionLoading(false);
    }
  };

  const handleApproveRemediation = async (remediationId: string) => {
    setActionLoading(true);
    setError(null);
    try {
      await api.approveRemediation(remediationId);
      setSuccessMsg("Remediation approved and marked ready for retest verification.");
      await loadData();
    } catch (err: any) {
      setError(err.message || "Approval failed");
    } finally {
      setActionLoading(false);
    }
  };

  const handleRetestFinding = async (findingId: string) => {
    setActionLoading(true);
    setError(null);
    try {
      const res = await api.retestFinding(findingId);
      setSuccessMsg(
        `Retest complete! Status: ${res.after_status} (Detection: ${res.detection_status}, Regression Passed: ${res.regression_passed})`
      );
      await loadData();
    } catch (err: any) {
      setError(err.message || "Retest failed");
    } finally {
      setActionLoading(false);
    }
  };

  const getStatusBadge = (status: string) => {
    const map: Record<string, string> = {
      OPEN: "bg-rose-500/20 text-rose-300 border-rose-500/40",
      UNDER_REMEDIATION: "bg-amber-500/20 text-amber-300 border-amber-500/40",
      PARTIALLY_REMEDIATED: "bg-purple-500/20 text-purple-300 border-purple-500/40",
      REMEDIATION_FAILED: "bg-rose-900/40 text-rose-300 border-rose-700",
      VERIFIED: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
      CLOSED: "bg-slate-700 text-slate-300 border-slate-600",
    };
    return (
      <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border ${map[status] || "bg-slate-700 text-slate-300"}`}>
        {status}
      </span>
    );
  };

  const getPill = (val: string) => {
    const map: Record<string, string> = {
      PASS: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
      FAIL: "bg-rose-500/20 text-rose-300 border-rose-500/40",
      PARTIAL: "bg-amber-500/20 text-amber-300 border-amber-500/40",
      NOT_TESTED: "bg-slate-800 text-slate-400 border-slate-700",
    };
    return (
      <span className={`px-2 py-0.5 rounded text-xs font-mono font-medium border ${map[val] || "bg-slate-800 text-slate-400"}`}>
        {val}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-slate-900/80 backdrop-blur-md p-6 rounded-2xl border border-slate-800 shadow-xl flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-white">Continuous Security Improvement</h1>
            <span className="bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-xs px-2.5 py-1 rounded-full font-semibold">
              CLOSED-LOOP
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Grounded adversary gap discovery, human-approved remediation tracking, and automated regression-protected retesting.
          </p>
        </div>

        {/* Tab Navigation */}
        <div className="flex flex-wrap gap-1 bg-slate-950 p-1.5 rounded-xl border border-slate-800 text-xs">
          <button
            onClick={() => setActiveTab("posture")}
            className={`px-3 py-1.5 rounded-lg font-medium transition-all ${
              activeTab === "posture" ? "bg-slate-800 text-white shadow" : "text-slate-400 hover:text-white"
            }`}
          >
            Posture
          </button>
          <button
            onClick={() => setActiveTab("gaps")}
            className={`px-3 py-1.5 rounded-lg font-medium transition-all ${
              activeTab === "gaps" ? "bg-slate-800 text-white shadow" : "text-slate-400 hover:text-white"
            }`}
          >
            Gaps ({gaps.length})
          </button>
          <button
            onClick={() => setActiveTab("coverage")}
            className={`px-3 py-1.5 rounded-lg font-medium transition-all ${
              activeTab === "coverage" ? "bg-slate-800 text-white shadow" : "text-slate-400 hover:text-white"
            }`}
          >
            ATT&CK Matrix
          </button>
          <button
            onClick={() => setActiveTab("findings")}
            className={`px-3 py-1.5 rounded-lg font-medium transition-all ${
              activeTab === "findings" ? "bg-slate-800 text-white shadow" : "text-slate-400 hover:text-white"
            }`}
          >
            Findings ({findings.length})
          </button>
          <button
            onClick={() => setActiveTab("tuning")}
            className={`px-3 py-1.5 rounded-lg font-medium transition-all ${
              activeTab === "tuning" ? "bg-slate-800 text-white shadow" : "text-slate-400 hover:text-white"
            }`}
          >
            Tuning ({tuningRecommendations.length})
          </button>
        </div>
      </div>

      {/* Notifications */}
      {error && (
        <div className="p-4 bg-rose-950/40 border border-rose-800/60 rounded-xl text-rose-200 text-sm flex justify-between items-center">
          <span>⚠️ {error}</span>
          <button onClick={() => setError(null)} className="text-rose-400 hover:text-white">✕</button>
        </div>
      )}
      {successMsg && (
        <div className="p-4 bg-emerald-950/40 border border-emerald-800/60 rounded-xl text-emerald-200 text-sm flex justify-between items-center">
          <span>✓ {successMsg}</span>
          <button onClick={() => setSuccessMsg(null)} className="text-emerald-400 hover:text-white">✕</button>
        </div>
      )}

      {loading ? (
        <div className="p-12 text-center text-slate-500 bg-slate-900/40 rounded-2xl border border-slate-800">
          Loading security posture & findings...
        </div>
      ) : (
        <>
          {/* TAB 1: POSTURE */}
          {activeTab === "posture" && !posture && (
            <div className="p-12 text-center text-slate-500 bg-slate-900/40 rounded-2xl border border-slate-800">
              No empirical security posture established yet. Execute adversary validation assessments to calculate baseline posture.
            </div>
          )}
          {activeTab === "posture" && posture && (
            <div className="space-y-6">

              {/* Executive Summary Metrics */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div className="bg-slate-900/80 p-5 rounded-2xl border border-slate-800">
                  <span className="text-slate-400 text-xs font-medium uppercase tracking-wider block">Overall Posture Score</span>
                  <div className="text-3xl font-extrabold text-white mt-2">
                    {posture.overall_posture_score} <span className="text-xs font-normal text-slate-400">/ 100</span>
                  </div>
                </div>
                <div className="bg-slate-900/80 p-5 rounded-2xl border border-slate-800">
                  <span className="text-slate-400 text-xs font-medium uppercase tracking-wider block">Adversary Test Coverage</span>
                  <div className="text-3xl font-extrabold text-cyan-400 mt-2">
                    {posture.test_coverage_percentage}%
                  </div>
                </div>
                <div className="bg-slate-900/80 p-5 rounded-2xl border border-slate-800">
                  <span className="text-slate-400 text-xs font-medium uppercase tracking-wider block">Open Findings</span>
                  <div className="text-3xl font-extrabold text-rose-400 mt-2">
                    {posture.total_findings_open}
                  </div>
                </div>
                <div className="bg-slate-900/80 p-5 rounded-2xl border border-slate-800">
                  <span className="text-slate-400 text-xs font-medium uppercase tracking-wider block">Remediated & Verified</span>
                  <div className="text-3xl font-extrabold text-emerald-400 mt-2">
                    {posture.total_findings_remediated}
                  </div>
                </div>
                <div className="bg-slate-900/80 p-5 rounded-2xl border border-slate-800">
                  <span className="text-slate-400 text-xs font-medium uppercase tracking-wider block">Remediation Rate</span>
                  <div className="text-3xl font-extrabold text-purple-400 mt-2">
                    {posture.remediation_success_rate}%
                  </div>
                </div>
              </div>

              {/* Category Breakdown */}
              <div className="bg-slate-900/80 backdrop-blur-md p-6 rounded-2xl border border-slate-800 space-y-4">
                <h3 className="text-base font-bold text-white">Operational Posture Categories</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {posture.categories.map((cat) => (
                    <div key={cat.category} className="p-4 bg-slate-950/60 rounded-xl border border-slate-800/80 space-y-2">
                      <div className="flex justify-between items-center">
                        <span className="font-semibold text-white text-sm">{cat.category}</span>
                        {getPill(cat.status)}
                      </div>
                      <div className="flex justify-between text-xs text-slate-400">
                        <span>Techniques Tested: {cat.tested_techniques}</span>
                        <span>Pass: {cat.successful_detections}</span>
                      </div>
                      <div className="w-full bg-slate-900 h-2 rounded-full overflow-hidden">
                        <div
                          className="bg-gradient-to-r from-cyan-500 to-emerald-500 h-full rounded-full"
                          style={{ width: `${cat.coverage_percentage}%` }}
                        />
                      </div>
                      <div className="text-right text-[11px] font-mono text-slate-300">
                        {cat.coverage_percentage}% Effective
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: DETECTION GAPS */}
          {activeTab === "gaps" && (
            <div className="bg-slate-900/80 backdrop-blur-md p-6 rounded-2xl border border-slate-800 space-y-4">
              <h3 className="text-base font-bold text-white">Discovered Security & Detection Gaps</h3>
              {gaps.length === 0 ? (
                <div className="p-8 text-center text-slate-500 bg-slate-950/30 rounded-xl border border-slate-800/50">
                  No detection gaps detected across recent adversary validations.
                </div>
              ) : (
                <div className="space-y-3">
                  {gaps.map((g, idx) => (
                    <div key={idx} className="p-4 bg-slate-950/70 rounded-xl border border-slate-800/80 space-y-2">
                      <div className="flex justify-between items-start gap-2">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 bg-rose-500/20 text-rose-300 border border-rose-500/30 rounded text-xs font-mono font-bold">
                            {g.gap_type}
                          </span>
                          <span className="font-mono text-xs text-slate-300 font-semibold">{g.technique_id}</span>
                          <span className="text-xs text-slate-500">on {g.target}</span>
                        </div>
                        <span className="text-xs font-semibold text-rose-400">{g.severity}</span>
                      </div>
                      <p className="text-xs text-slate-300">{g.summary}</p>
                      <div className="p-2.5 bg-slate-900 rounded-lg text-xs text-slate-400 border border-slate-800/60 flex items-start gap-2">
                        <span className="text-amber-400">💡</span>
                        <span><strong>Recommendation:</strong> {g.recommendation}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 3: ATT&CK MATRIX */}
          {activeTab === "coverage" && (
            <div className="bg-slate-900/80 backdrop-blur-md p-6 rounded-2xl border border-slate-800 space-y-4">
              <h3 className="text-base font-bold text-white">Validated MITRE ATT&CK Matrix</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs text-slate-300">
                  <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                    <tr>
                      <th className="p-3">Technique</th>
                      <th className="p-3">Name</th>
                      <th className="p-3">Simulation</th>
                      <th className="p-3">Detection</th>
                      <th className="p-3">Correlation</th>
                      <th className="p-3">Investigation</th>
                      <th className="p-3">Response</th>
                      <th className="p-3">Verify</th>
                      <th className="p-3">Overall</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {coverage.map((c) => (
                      <tr key={c.technique_id} className="hover:bg-slate-800/30">
                        <td className="p-3 font-bold text-white">{c.technique_id}</td>
                        <td className="p-3 font-sans text-slate-200">{c.technique_name}</td>
                        <td className="p-3">{getPill(c.simulation)}</td>
                        <td className="p-3">{getPill(c.detection)}</td>
                        <td className="p-3">{getPill(c.correlation)}</td>
                        <td className="p-3">{getPill(c.investigation)}</td>
                        <td className="p-3">{getPill(c.response)}</td>
                        <td className="p-3">{getPill(c.verification)}</td>
                        <td className="p-3 font-bold">{getPill(c.overall)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 4: FINDINGS & REMEDIATION */}
          {activeTab === "findings" && (
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <h3 className="text-base font-bold text-white">Security Findings Lifecycle ({findings.length})</h3>
              </div>

              {findings.length === 0 ? (
                <div className="p-8 text-center text-slate-500 bg-slate-900/40 rounded-2xl border border-slate-800">
                  No active security findings. Validation gaps will automatically appear here.
                </div>
              ) : (
                <div className="space-y-4">
                  {findings.map((f) => (
                    <div key={f.id} className="bg-slate-900/80 p-5 rounded-2xl border border-slate-800 space-y-3">
                      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 border-b border-slate-800/60 pb-3">
                        <div>
                          <div className="flex items-center gap-3">
                            <h4 className="font-bold text-white text-sm">{f.title}</h4>
                            {getStatusBadge(f.status)}
                            <span className="text-xs font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                              {f.priority}
                            </span>
                          </div>
                          <div className="text-xs text-slate-400 mt-1 font-mono">
                            Asset: <span className="text-slate-200">{f.asset}</span> | Technique: <span className="text-slate-200">{f.technique}</span> | Owner: {f.owner}
                          </div>
                        </div>

                        {/* Finding Actions */}
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => {
                              setSelectedFinding(f);
                              setShowRemediateModal(true);
                            }}
                            className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold"
                          >
                            Propose Fix
                          </button>
                          <button
                            onClick={() => handleRetestFinding(f.id)}
                            disabled={actionLoading}
                            className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold flex items-center gap-1"
                          >
                            <span>↻</span> Retest
                          </button>
                        </div>
                      </div>

                      <p className="text-xs text-slate-300">{f.description}</p>

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs bg-slate-950/50 p-3 rounded-xl border border-slate-800/60">
                        <div>
                          <span className="text-slate-500 block font-semibold mb-0.5">Root Cause:</span>
                          <span className="text-slate-300">{f.root_cause}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 block font-semibold mb-0.5">Guidance:</span>
                          <span className="text-slate-300">{f.recommendation}</span>
                        </div>
                      </div>

                      {/* Associated Remediations */}
                      {f.remediations && f.remediations.length > 0 && (
                        <div className="pt-2 border-t border-slate-800/60 space-y-2">
                          <span className="text-xs font-semibold text-slate-400 block">Proposed Remediation Actions:</span>
                          {f.remediations.map((rem) => (
                            <div key={rem.id} className="p-3 bg-slate-950 rounded-xl border border-slate-800 flex justify-between items-center text-xs">
                              <div>
                                <span className="font-semibold text-slate-200">{rem.proposed_change}</span>
                                <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                                  Type: {rem.change_type} | Status: <strong className="text-amber-400">{rem.approval_status}</strong>
                                </div>
                              </div>
                              {rem.approval_status === "PENDING" && (
                                <button
                                  onClick={() => handleApproveRemediation(rem.id)}
                                  disabled={actionLoading}
                                  className="px-3 py-1 bg-purple-600 hover:bg-purple-500 text-white font-semibold rounded-lg text-xs"
                                >
                                  Human Sign-off
                                </button>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 5: FALSE POSITIVE TUNING */}
          {activeTab === "tuning" && (
            <div className="bg-slate-900/80 backdrop-blur-md p-6 rounded-2xl border border-slate-800 space-y-4">
              <div>
                <h3 className="text-base font-bold text-white">False Positive Reduction & Tuning</h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Automated analysis of benign alerts proposing asset allowlists and rule threshold tuning. Never applied silently.
                </p>
              </div>

              {tuningRecommendations.length === 0 ? (
                <div className="p-8 text-center text-slate-500 bg-slate-950/30 rounded-xl border border-slate-800/50">
                  No false positive patterns observed yet.
                </div>
              ) : (
                <div className="space-y-3">
                  {tuningRecommendations.map((t, idx) => (
                    <div key={idx} className="p-4 bg-slate-950/70 rounded-xl border border-slate-800/80 space-y-2">
                      <div className="flex justify-between items-center">
                        <span className="font-mono text-xs font-bold text-amber-400">{t.rule_target}</span>
                        <span className="text-xs bg-slate-800 px-2 py-0.5 rounded text-slate-400">
                          {t.observation_count} Benign Triggers
                        </span>
                      </div>
                      <p className="text-xs text-slate-300">{t.current_behavior}</p>
                      <div className="p-3 bg-slate-900 rounded-lg text-xs text-slate-300 border border-slate-800 flex justify-between items-center">
                        <span><strong>Recommendation:</strong> {t.recommendation}</span>
                        <span className="text-rose-400 text-[11px] font-semibold whitespace-nowrap ml-4">
                          Requires Approval
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* Propose Remediation Modal */}
      {showRemediateModal && selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 max-w-lg w-full space-y-5 shadow-2xl">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <h3 className="font-bold text-lg text-white">Propose Finding Remediation</h3>
              <button onClick={() => setShowRemediateModal(false)} className="text-slate-400 hover:text-white">✕</button>
            </div>
            <form onSubmit={handleProposeRemediation} className="space-y-4 text-xs">
              <div>
                <label className="text-slate-300 block mb-1 font-medium">Finding</label>
                <div className="p-2.5 bg-slate-950 rounded-xl text-slate-300 font-semibold border border-slate-800">
                  {selectedFinding.title}
                </div>
              </div>

              <div>
                <label className="text-slate-300 block mb-1 font-medium">Remediation Change Type</label>
                <select
                  value={changeType}
                  onChange={(e) => setChangeType(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="RULE_UPDATE">RULE_UPDATE (Sigma Detection Rule Adjustment)</option>
                  <option value="POLICY_UPDATE">POLICY_UPDATE (Access Control or Policy Adjustment)</option>
                  <option value="ASSET_CONFIG">ASSET_CONFIG (Host Hardening or Allowlist Configuration)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-300 block mb-1 font-medium">Proposed Change Description</label>
                <textarea
                  value={proposedChange}
                  onChange={(e) => setProposedChange(e.target.value)}
                  placeholder="e.g. Deploy Sigma rule SIGMA-SSH-BRUTEFORCE with 5 failures/120s threshold on asset..."
                  rows={4}
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="p-3 bg-blue-950/20 border border-blue-900/30 rounded-xl text-slate-400">
                <span className="text-blue-400 font-semibold block mb-0.5">Closed-Loop Integrity:</span>
                Changes are saved in PENDING status. Human sign-off is mandatory before marking ready for retest.
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowRemediateModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionLoading}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-semibold shadow"
                >
                  Submit Proposal
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
