import React from "react";
import { Shield, Lock, Database, Cpu, CheckCircle } from "lucide-react";

export const DocsPage: React.FC = () => {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.75rem", maxWidth: "900px" }}>
      <div>
        <h1 style={{ fontSize: "1.5rem", fontWeight: 700, color: "#f8fafc" }}>
          AegisSOC AI — Architecture & Security Model
        </h1>
        <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)" }}>
          Defensive platform design principles, cryptographic safeguards, and tenant isolation architecture.
        </p>
      </div>

      <div className="glass-panel" style={{ padding: "1.5rem", display: "flex", flexDirection: "column", gap: "1rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <Shield size={20} style={{ color: "#06b6d4" }} />
          <h2 style={{ fontSize: "1.1rem", fontWeight: 600, color: "#f8fafc" }}>
            1. Strict Multi-Tenant Isolation
          </h2>
        </div>
        <p style={{ fontSize: "0.875rem", color: "var(--text-secondary)", lineHeight: 1.6 }}>
          Every database record (assets, events, alerts, incidents, evidence, audit logs) is strictly tagged with an immutable <code className="mono" style={{ color: "#38bdf8" }}>tenant_id</code>. Tenant context is derived solely from cryptographic server-side JWT claims, and never accepted from untrusted client input. Any cross-tenant read or mutation attempt fails securely with HTTP 404/403.
        </p>
      </div>

      <div className="glass-panel" style={{ padding: "1.5rem", display: "flex", flexDirection: "column", gap: "1rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <Lock size={20} style={{ color: "#10b981" }} />
          <h2 style={{ fontSize: "1.1rem", fontWeight: 600, color: "#f8fafc" }}>
            2. Role-Based Access Control (RBAC)
          </h2>
        </div>
        <ul style={{ listStyle: "none", display: "flex", flexDirection: "column", gap: "0.5rem", fontSize: "0.875rem", color: "var(--text-secondary)" }}>
          <li style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <CheckCircle size={15} style={{ color: "#10b981" }} />
            <span><strong style={{ color: "#f8fafc" }}>TENANT_ADMIN & CISO:</strong> Full tenant governance, user management, and tenant provisioning.</span>
          </li>
          <li style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <CheckCircle size={15} style={{ color: "#10b981" }} />
            <span><strong style={{ color: "#f8fafc" }}>SECURITY_ENGINEER & SOC_L2:</strong> Asset management, telemetry ingestion, incident investigation.</span>
          </li>
          <li style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <CheckCircle size={15} style={{ color: "#10b981" }} />
            <span><strong style={{ color: "#f8fafc" }}>SOC_L1:</strong> Alert triage and event monitoring. Restricted from administrative and asset modifications.</span>
          </li>
        </ul>
      </div>

      <div className="glass-panel" style={{ padding: "1.5rem", display: "flex", flexDirection: "column", gap: "1rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <Database size={20} style={{ color: "#8b5cf6" }} />
          <h2 style={{ fontSize: "1.1rem", fontWeight: 600, color: "#f8fafc" }}>
            3. Immutable Forensics & Audit Logging
          </h2>
        </div>
        <p style={{ fontSize: "0.875rem", color: "var(--text-secondary)", lineHeight: 1.6 }}>
          All evidence items incorporate cryptographic SHA-256 integrity hashes to preserve chain-of-custody. Security actions (logins, tenant operations, asset registration, incident creation) are written to an append-only audit log table with correlation IDs.
        </p>
      </div>

      <div className="glass-panel" style={{ padding: "1.5rem", display: "flex", flexDirection: "column", gap: "1rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <Cpu size={20} style={{ color: "#f43f5e" }} />
          <h2 style={{ fontSize: "1.1rem", fontWeight: 600, color: "#f8fafc" }}>
            4. AI Safety & Separation of Concerns
          </h2>
        </div>
        <p style={{ fontSize: "0.875rem", color: "var(--text-secondary)", lineHeight: 1.6 }}>
          Phase 1 explicitly establishes the foundation. Future AI recommendations and adversary validation capabilities are strictly decoupled from operational execution paths, requiring human-in-the-loop validation and audit confirmation before any containment action.
        </p>
      </div>
    </div>
  );
};
