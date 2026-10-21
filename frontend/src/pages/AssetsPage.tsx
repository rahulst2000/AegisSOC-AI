import React, { useState } from "react";
import { Plus, Server, X } from "lucide-react";
import { Asset } from "../types";
import { StatusBadge } from "../components/StatusBadge";
import { api } from "../services/api";

interface AssetsPageProps {
  assets: Asset[];
  onRefresh: () => void;
}

export const AssetsPage: React.FC<AssetsPageProps> = ({ assets, onRefresh }) => {
  const [showModal, setShowModal] = useState(false);
  const [hostname, setHostname] = useState("");
  const [ipAddress, setIpAddress] = useState("");
  const [assetType, setAssetType] = useState("SERVER");
  const [criticality, setCriticality] = useState("MEDIUM");
  const [environment, setEnvironment] = useState("PRODUCTION");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);

    try {
      await api.createAsset({
        hostname,
        ip_address: ipAddress,
        asset_type: assetType,
        criticality,
        environment,
      });
      setShowModal(false);
      setHostname("");
      setIpAddress("");
      onRefresh();
    } catch (err: any) {
      setError(err.message || "Failed to register asset");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h1 style={{ fontSize: "1.4rem", fontWeight: 700, color: "#f8fafc" }}>
            Asset Inventory
          </h1>
          <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)" }}>
            Monitored hosts, network appliances, and cloud compute nodes.
          </p>
        </div>

        <button onClick={() => setShowModal(true)} className="btn-primary">
          <Plus size={16} />
          <span>Add Asset</span>
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
              <th style={{ padding: "0.85rem 1.25rem" }}>Hostname / FQDN</th>
              <th style={{ padding: "0.85rem 1rem" }}>IP Address</th>
              <th style={{ padding: "0.85rem 1rem" }}>Type</th>
              <th style={{ padding: "0.85rem 1rem" }}>Criticality</th>
              <th style={{ padding: "0.85rem 1rem" }}>Environment</th>
              <th style={{ padding: "0.85rem 1rem" }}>Status</th>
              <th style={{ padding: "0.85rem 1.25rem" }}>Tenant ID</th>
            </tr>
          </thead>
          <tbody>
            {assets.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: "center", padding: "3rem 1rem", color: "var(--text-muted)" }}>
                  No assets currently cataloged for your tenant.
                </td>
              </tr>
            ) : (
              assets.map((asset) => (
                <tr
                  key={asset.id}
                  style={{
                    borderBottom: "1px solid rgba(255, 255, 255, 0.04)",
                    transition: "background 0.15s ease",
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = "rgba(6, 182, 212, 0.04)"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = "transparent"; }}
                >
                  <td style={{ padding: "1rem 1.25rem", fontWeight: 600, color: "#f8fafc" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                      <Server size={15} style={{ color: "#38bdf8" }} />
                      <span>{asset.hostname}</span>
                    </div>
                  </td>
                  <td style={{ padding: "1rem 1rem" }} className="mono">
                    {asset.ip_address}
                  </td>
                  <td style={{ padding: "1rem 1rem" }}>{asset.asset_type}</td>
                  <td style={{ padding: "1rem 1rem" }}>
                    <StatusBadge label={asset.criticality} variant="severity" />
                  </td>
                  <td style={{ padding: "1rem 1rem" }}>{asset.environment}</td>
                  <td style={{ padding: "1rem 1rem" }}>
                    <StatusBadge label={asset.status} variant="status" />
                  </td>
                  <td style={{ padding: "1rem 1.25rem" }} className="mono">
                    <span style={{ fontSize: "0.75rem", color: "#10b981" }}>
                      {asset.tenant_id.substring(0, 8)}...
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

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
            style={{ width: "100%", maxWidth: "480px", padding: "2rem", display: "flex", flexDirection: "column", gap: "1.25rem" }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h2 style={{ fontSize: "1.2rem", fontWeight: 700, color: "#f8fafc" }}>
                Add Monitored Asset
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
                  Hostname / FQDN
                </label>
                <input
                  type="text"
                  required
                  value={hostname}
                  onChange={(e) => setHostname(e.target.value)}
                  placeholder="e.g. k8s-worker-node-01.aegis.internal"
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
                  IPv4 / IPv6 Address
                </label>
                <input
                  type="text"
                  required
                  value={ipAddress}
                  onChange={(e) => setIpAddress(e.target.value)}
                  placeholder="e.g. 10.0.12.44"
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
                    Asset Type
                  </label>
                  <select
                    value={assetType}
                    onChange={(e) => setAssetType(e.target.value)}
                    style={{
                      width: "100%",
                      padding: "0.65rem",
                      background: "rgba(10, 15, 29, 0.8)",
                      border: "1px solid var(--border-color)",
                      borderRadius: "6px",
                      color: "#f8fafc",
                    }}
                  >
                    <option value="SERVER">SERVER</option>
                    <option value="WORKSTATION">WORKSTATION</option>
                    <option value="FIREWALL">FIREWALL</option>
                    <option value="CLOUD_RESOURCE">CLOUD_RESOURCE</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-secondary)", marginBottom: "0.3rem" }}>
                    Criticality
                  </label>
                  <select
                    value={criticality}
                    onChange={(e) => setCriticality(e.target.value)}
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
              </div>

              <div>
                <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-secondary)", marginBottom: "0.3rem" }}>
                  Environment
                </label>
                <select
                  value={environment}
                  onChange={(e) => setEnvironment(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "0.65rem",
                    background: "rgba(10, 15, 29, 0.8)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "6px",
                    color: "#f8fafc",
                  }}
                >
                  <option value="PRODUCTION">PRODUCTION</option>
                  <option value="STAGING">STAGING</option>
                  <option value="DEVELOPMENT">DEVELOPMENT</option>
                  <option value="LAB">LAB</option>
                </select>
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.75rem", marginTop: "0.5rem" }}>
                <button type="button" onClick={() => setShowModal(false)} className="btn-secondary">
                  Cancel
                </button>
                <button type="submit" disabled={submitting} className="btn-primary">
                  {submitting ? "Adding..." : "Register Asset"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
