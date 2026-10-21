import React, { useEffect, useState } from "react";
import { api } from "../services/api";
import { AdversaryAssessment, AssessmentResult, AuthorizedScope } from "../types";

export const AdversaryPage: React.FC = () => {
  const [assessments, setAssessments] = useState<AdversaryAssessment[]>([]);
  const [selectedAssessment, setSelectedAssessment] = useState<AdversaryAssessment | null>(null);
  const [results, setResults] = useState<AssessmentResult[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Modal State
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [newName, setNewName] = useState<string>("Lab Validation Assessment");
  const [newScenario, setNewScenario] = useState<string>("SCENARIO-001");
  const [targetAsset, setTargetAsset] = useState<string>("lab-server-01");
  const [targetIp, setTargetIp] = useState<string>("10.0.0.45");

  const loadAssessments = async () => {
    try {
      setLoading(true);
      const data = await api.getAssessments();
      setAssessments(data);
      if (data.length > 0 && !selectedAssessment) {
        setSelectedAssessment(data[0]);
        loadResults(data[0].id);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load assessments");
    } finally {
      setLoading(false);
    }
  };

  const loadResults = async (assessmentId: string) => {
    try {
      const res = await api.getAssessmentResults(assessmentId);
      setResults(res);
    } catch (err: any) {
      console.error("Error loading results:", err);
    }
  };

  useEffect(() => {
    loadAssessments();
  }, []);

  const handleSelectAssessment = (a: AdversaryAssessment) => {
    setSelectedAssessment(a);
    loadResults(a.id);
  };

  const handleCreateAssessment = async (e: React.FormEvent) => {
    e.preventDefault();
    setActionLoading(true);
    setError(null);
    try {
      const scope: AuthorizedScope = {
        environment: "LAB",
        assets: [targetAsset],
        ips: targetIp ? [targetIp] : [],
        allowed_techniques: ["T1110.001", "T1110.003", "T1078", "T1078.003"],
        prohibited_techniques: ["persistence", "data_exfiltration", "destructive_actions"],
        expires_at: new Date(Date.now() + 4 * 3600 * 1000).toISOString(),
      };
      const created = await api.createAssessment({
        name: newName,
        environment: "LAB",
        scenario: newScenario,
        authorized_scope: scope,
      });
      setSuccessMsg(`Assessment created in DRAFT status: ${created.id}`);
      setShowCreateModal(false);
      await loadAssessments();
      setSelectedAssessment(created);
    } catch (err: any) {
      setError(err.message || "Failed to create assessment");
    } finally {
      setActionLoading(false);
    }
  };

  const handleAuthorize = async () => {
    if (!selectedAssessment) return;
    setActionLoading(true);
    setError(null);
    try {
      const updated = await api.authorizeAssessment(selectedAssessment.id);
      setSuccessMsg(`Assessment ${updated.name} authorized for execution in LAB scope.`);
      setSelectedAssessment(updated);
      await loadAssessments();
    } catch (err: any) {
      setError(err.message || "Authorization failed");
    } finally {
      setActionLoading(false);
    }
  };

  const handleStartSimulation = async () => {
    if (!selectedAssessment) return;
    setActionLoading(true);
    setError(null);
    try {
      const res = await api.startAssessment(selectedAssessment.id);
      setSuccessMsg(`Adversary validation executed! Result: ${res.overall_result}`);
      await loadAssessments();
      await loadResults(selectedAssessment.id);
    } catch (err: any) {
      setError(err.message || "Simulation execution failed");
    } finally {
      setActionLoading(false);
    }
  };

  const handleCancel = async () => {
    if (!selectedAssessment) return;
    setActionLoading(true);
    setError(null);
    try {
      const updated = await api.cancelAssessment(selectedAssessment.id);
      setSuccessMsg(`Assessment cancelled and cleaned up.`);
      setSelectedAssessment(updated);
      await loadAssessments();
    } catch (err: any) {
      setError(err.message || "Cancellation failed");
    } finally {
      setActionLoading(false);
    }
  };

  const getStatusBadge = (status: string) => {
    const map: Record<string, string> = {
      DRAFT: "bg-amber-500/20 text-amber-300 border-amber-500/40",
      AUTHORIZED: "bg-blue-500/20 text-blue-300 border-blue-500/40",
      RUNNING: "bg-purple-500/20 text-purple-300 border-purple-500/40 animate-pulse",
      COMPLETED: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
      FAILED: "bg-rose-500/20 text-rose-300 border-rose-500/40",
      CANCELLED: "bg-slate-500/20 text-slate-400 border-slate-500/40",
    };
    return (
      <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border ${map[status] || "bg-slate-700 text-slate-300"}`}>
        {status}
      </span>
    );
  };

  const getResultPill = (val: string) => {
    const map: Record<string, string> = {
      PASS: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
      FAIL: "bg-rose-500/20 text-rose-300 border-rose-500/40",
      PARTIAL: "bg-amber-500/20 text-amber-300 border-amber-500/40",
      CLEANED: "bg-cyan-500/20 text-cyan-300 border-cyan-500/40",
      NOT_TESTED: "bg-slate-700/40 text-slate-400 border-slate-700",
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
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-slate-900/80 backdrop-blur-md p-6 rounded-2xl border border-slate-800 shadow-xl">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-white">AegisRed Adversary Validation</h1>
            <span className="bg-rose-500/20 text-rose-300 border border-rose-500/30 text-xs px-2.5 py-1 rounded-full font-semibold">
              LAB ENVIRONMENT ONLY
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Controlled, evidence-grounded simulation verifying detection, correlation, investigation, and response.
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="px-4 py-2 bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white font-medium rounded-xl shadow-lg shadow-red-900/20 transition-all text-sm flex items-center gap-2"
        >
          <span>+</span> New Assessment
        </button>
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

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Assessments List */}
        <div className="lg:col-span-5 space-y-3">
          <div className="text-sm font-semibold uppercase tracking-wider text-slate-400 px-1">
            Assessments ({assessments.length})
          </div>
          {loading ? (
            <div className="p-8 text-center text-slate-500 bg-slate-900/40 rounded-xl border border-slate-800">
              Loading assessments...
            </div>
          ) : assessments.length === 0 ? (
            <div className="p-8 text-center text-slate-500 bg-slate-900/40 rounded-xl border border-slate-800">
              No adversary assessments found. Click &quot;New Assessment&quot; to initialize.
            </div>
          ) : (
            <div className="space-y-3 max-h-[700px] overflow-y-auto pr-1">
              {assessments.map((a) => {
                const isSelected = selectedAssessment?.id === a.id;
                return (
                  <div
                    key={a.id}
                    onClick={() => handleSelectAssessment(a)}
                    className={`p-4 rounded-xl border cursor-pointer transition-all ${
                      isSelected
                        ? "bg-slate-800/90 border-red-500/50 shadow-lg shadow-red-950/20 ring-1 ring-red-500/30"
                        : "bg-slate-900/60 border-slate-800 hover:bg-slate-800/50"
                    }`}
                  >
                    <div className="flex justify-between items-start gap-2">
                      <h3 className="font-semibold text-white text-sm">{a.name}</h3>
                      {getStatusBadge(a.status)}
                    </div>
                    <div className="flex items-center gap-3 mt-2 text-xs text-slate-400">
                      <span className="font-mono bg-slate-800 px-1.5 py-0.5 rounded text-slate-300">
                        {a.scenario}
                      </span>
                      <span>Env: <strong className="text-emerald-400">{a.environment}</strong></span>
                      <span>Target: {a.authorized_scope?.assets?.[0] || "lab-server-01"}</span>
                    </div>
                    <div className="text-[11px] text-slate-500 mt-2 font-mono truncate">
                      ID: {a.id}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right: Selected Assessment Execution & Results */}
        <div className="lg:col-span-7">
          {selectedAssessment ? (
            <div className="bg-slate-900/80 backdrop-blur-md rounded-2xl border border-slate-800 p-6 space-y-6 shadow-xl">
              {/* Header Details */}
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 pb-4 border-b border-slate-800">
                <div>
                  <div className="flex items-center gap-3">
                    <h2 className="text-xl font-bold text-white">{selectedAssessment.name}</h2>
                    {getStatusBadge(selectedAssessment.status)}
                  </div>
                  <p className="text-xs text-slate-400 mt-1 font-mono">
                    ID: {selectedAssessment.id}
                  </p>
                </div>

                {/* Action Buttons */}
                <div className="flex items-center gap-2">
                  {selectedAssessment.status === "DRAFT" && (
                    <button
                      onClick={handleAuthorize}
                      disabled={actionLoading}
                      className="px-3.5 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold shadow transition-all"
                    >
                      Authorize Scope
                    </button>
                  )}
                  {selectedAssessment.status === "AUTHORIZED" && (
                    <button
                      onClick={handleStartSimulation}
                      disabled={actionLoading}
                      className="px-3.5 py-1.5 bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold shadow-lg shadow-red-950/30 transition-all flex items-center gap-1.5"
                    >
                      <span>▶</span> Run Simulation
                    </button>
                  )}
                  {["AUTHORIZED", "RUNNING"].includes(selectedAssessment.status) && (
                    <button
                      onClick={handleCancel}
                      disabled={actionLoading}
                      className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-semibold border border-slate-700 transition-all"
                    >
                      Cancel
                    </button>
                  )}
                </div>
              </div>

              {/* Scope Boundary Verification */}
              <div className="bg-slate-950/50 p-4 rounded-xl border border-slate-800/80 space-y-2">
                <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  Authorized Scope Parameters
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                  <div>
                    <span className="text-slate-500 block">Environment</span>
                    <span className="text-emerald-400 font-semibold">{selectedAssessment.environment}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Target Asset</span>
                    <span className="text-slate-200 font-mono">
                      {selectedAssessment.authorized_scope?.assets?.[0] || "N/A"}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Allowed MITRE</span>
                    <span className="text-slate-200 font-mono">
                      {selectedAssessment.authorized_scope?.allowed_techniques?.join(", ") || "All Lab"}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Prohibited</span>
                    <span className="text-rose-400 font-mono text-[11px]">Destructive, Persist</span>
                  </div>
                </div>
              </div>

              {/* Validation Lifecycle Results */}
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                    Attack Validation Results ({results.length})
                  </h3>
                  {results.length > 0 && (
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-slate-400">Overall Result:</span>
                      {getResultPill(results[0].overall_result)}
                    </div>
                  )}
                </div>

                {results.length === 0 ? (
                  <div className="p-8 text-center text-slate-500 bg-slate-950/30 rounded-xl border border-slate-800/50">
                    No execution results yet. Authorize and Run Simulation to execute the validation pipeline.
                  </div>
                ) : (
                  <div className="space-y-4">
                    {results.map((res) => (
                      <div key={res.id} className="p-5 bg-slate-950/70 rounded-xl border border-slate-800 space-y-4">
                        <div className="flex flex-wrap justify-between items-center gap-2 border-b border-slate-800/60 pb-3">
                          <div>
                            <span className="text-xs font-mono font-bold text-red-400">{res.scenario_id}</span>
                            <span className="text-slate-500 mx-2">|</span>
                            <span className="text-xs font-mono text-slate-300">MITRE: {res.technique_id}</span>
                            <span className="text-slate-500 mx-2">|</span>
                            <span className="text-xs text-slate-400">Target: {res.target}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs text-slate-400">Overall:</span>
                            {getResultPill(res.overall_result)}
                          </div>
                        </div>

                        {/* Lifecycle Stages */}
                        <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-7 gap-2 text-center text-xs">
                          <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800/80">
                            <span className="text-slate-500 block text-[10px] uppercase mb-1">1. Simulation</span>
                            {getResultPill(res.simulation_status)}
                          </div>
                          <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800/80">
                            <span className="text-slate-500 block text-[10px] uppercase mb-1">2. Detection</span>
                            {getResultPill(res.detection_status)}
                          </div>
                          <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800/80">
                            <span className="text-slate-500 block text-[10px] uppercase mb-1">3. Correlation</span>
                            {getResultPill(res.correlation_status)}
                          </div>
                          <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800/80">
                            <span className="text-slate-500 block text-[10px] uppercase mb-1">4. Investigation</span>
                            {getResultPill(res.investigation_status)}
                          </div>
                          <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800/80">
                            <span className="text-slate-500 block text-[10px] uppercase mb-1">5. Response</span>
                            {getResultPill(res.response_status)}
                          </div>
                          <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800/80">
                            <span className="text-slate-500 block text-[10px] uppercase mb-1">6. Verify</span>
                            {getResultPill(res.verification_status)}
                          </div>
                          <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800/80">
                            <span className="text-slate-500 block text-[10px] uppercase mb-1">7. Cleanup</span>
                            {getResultPill(res.cleanup_status)}
                          </div>
                        </div>

                        {/* Evidence & Details */}
                        <div className="text-xs space-y-1.5 pt-2 border-t border-slate-800/60 text-slate-400">
                          <div className="flex justify-between">
                            <span>Evidence IDs Collected:</span>
                            <span className="font-mono text-slate-300 font-semibold">{res.evidence_ids?.length || 0} records</span>
                          </div>
                          {res.details && Object.keys(res.details).length > 0 && (
                            <div className="bg-slate-900 p-3 rounded-lg text-[11px] font-mono overflow-x-auto text-slate-300">
                              <pre>{JSON.stringify(res.details, null, 2)}</pre>
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-slate-500 bg-slate-900/40 rounded-2xl border border-slate-800">
              Select an assessment from the left to view details and execute validation.
            </div>
          )}
        </div>
      </div>

      {/* Modal: New Assessment */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 max-w-lg w-full space-y-5 shadow-2xl">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <h3 className="font-bold text-lg text-white">Create Authorized Adversary Assessment</h3>
              <button onClick={() => setShowCreateModal(false)} className="text-slate-400 hover:text-white">✕</button>
            </div>
            <form onSubmit={handleCreateAssessment} className="space-y-4 text-xs">
              <div>
                <label className="text-slate-300 block mb-1 font-medium">Assessment Name</label>
                <input
                  type="text"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-red-500"
                />
              </div>

              <div>
                <label className="text-slate-300 block mb-1 font-medium">Attack Simulation Scenario</label>
                <select
                  value={newScenario}
                  onChange={(e) => setNewScenario(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-red-500"
                >
                  <option value="SCENARIO-001">SCENARIO-001: SSH Brute Force (T1110.001)</option>
                  <option value="SCENARIO-002">SCENARIO-002: Password Spraying (T1110.003)</option>
                  <option value="SCENARIO-003">SCENARIO-003: Failure → Success Compromise (T1078)</option>
                  <option value="SCENARIO-004">SCENARIO-004: Privileged Login Telemetry (T1078.003)</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-300 block mb-1 font-medium">Target Lab Asset</label>
                  <input
                    type="text"
                    value={targetAsset}
                    onChange={(e) => setTargetAsset(e.target.value)}
                    required
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-red-500"
                  />
                </div>
                <div>
                  <label className="text-slate-300 block mb-1 font-medium">Target Lab IP</label>
                  <input
                    type="text"
                    value={targetIp}
                    onChange={(e) => setTargetIp(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-red-500"
                  />
                </div>
              </div>

              <div className="p-3 bg-red-950/20 border border-red-900/30 rounded-xl text-slate-400 space-y-1">
                <span className="text-red-400 font-semibold block">Safety Enforcement:</span>
                <p>Simulations strictly restricted to LAB environment. Production assets, persistence, destructive actions, and data exfiltration are prohibited and automatically rejected.</p>
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionLoading}
                  className="px-4 py-2 bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white rounded-xl font-semibold shadow-lg shadow-red-950/20"
                >
                  Create Assessment
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
