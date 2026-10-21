import React, { useState } from "react";
import { Shield, Lock, Mail, Building } from "lucide-react";
import { api } from "../services/api";
import { AuthResponse } from "../types";

interface LoginPageProps {
  onAuthSuccess: (authData: AuthResponse) => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({ onAuthSuccess }) => {
  const [isRegister, setIsRegister] = useState(false);
  const [orgName, setOrgName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("TENANT_ADMIN");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (isRegister) {
        const res = await api.register({
          organization_name: orgName,
          email,
          password,
          role,
        });
        onAuthSuccess(res);
      } else {
        const res = await api.login({ email, password });
        onAuthSuccess(res);
      }
    } catch (err: any) {
      setError(err.message || "Authentication failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "1.5rem",
      }}
    >
      <div
        className="glass-panel glow-cyan"
        style={{
          width: "100%",
          maxWidth: "460px",
          padding: "2.5rem",
          display: "flex",
          flexDirection: "column",
          gap: "1.5rem",
        }}
      >
        <div style={{ textAlign: "center" }}>
          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
              width: "56px",
              height: "56px",
              borderRadius: "14px",
              background: "rgba(6, 182, 212, 0.15)",
              border: "1px solid rgba(6, 182, 212, 0.3)",
              color: "#06b6d4",
              marginBottom: "1rem",
            }}
          >
            <Shield size={32} />
          </div>
          <h1 style={{ fontSize: "1.6rem", fontWeight: 700, color: "#f8fafc", marginBottom: "0.25rem" }}>
            AegisSOC AI
          </h1>
          <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)" }}>
            Evidence-Grounded Autonomous Security Operations
          </p>
        </div>

        {error && (
          <div
            style={{
              padding: "0.75rem 1rem",
              borderRadius: "8px",
              background: "rgba(244, 63, 94, 0.15)",
              border: "1px solid rgba(244, 63, 94, 0.3)",
              color: "#fb7185",
              fontSize: "0.85rem",
            }}
          >
            {error}
          </div>
        )}

        {/* Tab Toggle */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "0.5rem",
            background: "rgba(15, 23, 42, 0.8)",
            padding: "0.3rem",
            borderRadius: "8px",
            border: "1px solid var(--border-color)",
          }}
        >
          <button
            type="button"
            onClick={() => { setIsRegister(false); setError(null); }}
            style={{
              padding: "0.5rem",
              borderRadius: "6px",
              border: "none",
              background: !isRegister ? "rgba(6, 182, 212, 0.2)" : "transparent",
              color: !isRegister ? "#38bdf8" : "var(--text-muted)",
              fontWeight: 600,
              fontSize: "0.85rem",
              cursor: "pointer",
            }}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => { setIsRegister(true); setError(null); }}
            style={{
              padding: "0.5rem",
              borderRadius: "6px",
              border: "none",
              background: isRegister ? "rgba(6, 182, 212, 0.2)" : "transparent",
              color: isRegister ? "#38bdf8" : "var(--text-muted)",
              fontWeight: 600,
              fontSize: "0.85rem",
              cursor: "pointer",
            }}
          >
            Onboard Tenant
          </button>
        </div>

        <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          {isRegister && (
            <>
              <div>
                <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-secondary)", marginBottom: "0.35rem" }}>
                  Organization / Tenant Name
                </label>
                <div style={{ position: "relative" }}>
                  <Building size={16} style={{ position: "absolute", left: "12px", top: "12px", color: "var(--text-muted)" }} />
                  <input
                    type="text"
                    required
                    value={orgName}
                    onChange={(e) => setOrgName(e.target.value)}
                    placeholder="e.g. Lockheed Cyber Operations"
                    style={{
                      width: "100%",
                      padding: "0.65rem 0.75rem 0.65rem 2.25rem",
                      background: "rgba(15, 23, 42, 0.8)",
                      border: "1px solid var(--border-color)",
                      borderRadius: "8px",
                      color: "#f8fafc",
                      fontSize: "0.875rem",
                      outline: "none",
                    }}
                  />
                </div>
              </div>

              <div>
                <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-secondary)", marginBottom: "0.35rem" }}>
                  Initial Security Role
                </label>
                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "0.65rem 0.75rem",
                    background: "rgba(15, 23, 42, 0.8)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "8px",
                    color: "#f8fafc",
                    fontSize: "0.875rem",
                    outline: "none",
                  }}
                >
                  <option value="TENANT_ADMIN">TENANT_ADMIN (Full Administrative Control)</option>
                  <option value="CISO">CISO (Executive Oversight & Governance)</option>
                  <option value="SECURITY_MANAGER">SECURITY_MANAGER (SOC Operations Lead)</option>
                  <option value="SECURITY_ENGINEER">SECURITY_ENGINEER (Telemetry & Threat Hunting)</option>
                  <option value="SOC_L2">SOC_L2 (Incident Investigation & Analysis)</option>
                  <option value="SOC_L1">SOC_L1 (Triage & Alert Processing)</option>
                  <option value="GRC_ANALYST">GRC_ANALYST (Compliance & Audit)</option>
                </select>
              </div>
            </>
          )}

          <div>
            <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-secondary)", marginBottom: "0.35rem" }}>
              Corporate Email
            </label>
            <div style={{ position: "relative" }}>
              <Mail size={16} style={{ position: "absolute", left: "12px", top: "12px", color: "var(--text-muted)" }} />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@soc.internal"
                style={{
                  width: "100%",
                  padding: "0.65rem 0.75rem 0.65rem 2.25rem",
                  background: "rgba(15, 23, 42, 0.8)",
                  border: "1px solid var(--border-color)",
                  borderRadius: "8px",
                  color: "#f8fafc",
                  fontSize: "0.875rem",
                  outline: "none",
                }}
              />
            </div>
          </div>

          <div>
            <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-secondary)", marginBottom: "0.35rem" }}>
              Password
            </label>
            <div style={{ position: "relative" }}>
              <Lock size={16} style={{ position: "absolute", left: "12px", top: "12px", color: "var(--text-muted)" }} />
              <input
                type="password"
                required
                minLength={8}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                style={{
                  width: "100%",
                  padding: "0.65rem 0.75rem 0.65rem 2.25rem",
                  background: "rgba(15, 23, 42, 0.8)",
                  border: "1px solid var(--border-color)",
                  borderRadius: "8px",
                  color: "#f8fafc",
                  fontSize: "0.875rem",
                  outline: "none",
                }}
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn-primary"
            style={{ width: "100%", justifyContent: "center", marginTop: "0.5rem", padding: "0.75rem" }}
          >
            {loading ? "Authenticating..." : isRegister ? "Create Isolated Tenant" : "Authenticate to SOC"}
          </button>
        </form>

        <div style={{ textAlign: "center", borderTop: "1px solid rgba(255, 255, 255, 0.06)", paddingTop: "1rem" }}>
          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
            Zero-Trust Tenant Isolation • Role-Based Access Control • FIPS Cryptography
          </span>
        </div>
      </div>
    </div>
  );
};
