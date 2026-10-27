import React from "react";
import { Shield, LogOut } from "lucide-react";
import { User } from "../types";
import { StatusBadge } from "./StatusBadge";
import { GlobalThreatSearch } from "./GlobalThreatSearch";

interface NavbarProps {
  user: User | null;
  tenantName: string;
  onLogout: () => void;
  onNavigateTab?: (tab: string, context?: any) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ user, tenantName, onLogout, onNavigateTab }) => {
  return (
    <header
      style={{
        height: "64px",
        backgroundColor: "rgba(10, 15, 29, 0.85)",
        backdropFilter: "blur(12px)",
        borderBottom: "1px solid var(--border-color)",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0 1.5rem",
        position: "sticky",
        top: 0,
        zIndex: 40,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.5rem",
            color: "#06b6d4",
          }}
        >
          <Shield size={26} strokeWidth={2.2} />
          <span style={{ fontSize: "1.15rem", fontWeight: 700, letterSpacing: "-0.02em", color: "#f8fafc" }}>
            AEGIS<span style={{ color: "#06b6d4" }}>SOC</span> <span style={{ fontSize: "0.8rem", color: "#94a3b8", fontWeight: 400 }}>AI</span>
          </span>
        </div>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.4rem",
            padding: "0.25rem 0.65rem",
            background: "rgba(16, 185, 129, 0.1)",
            border: "1px solid rgba(16, 185, 129, 0.25)",
            borderRadius: "9999px",
            fontSize: "0.75rem",
            color: "#34d399",
            fontWeight: 500,
          }}
        >
          <span className="live-indicator" />
          <span>ACTIVE MONITORING</span>
        </div>
      </div>

      {user && (
        <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
          <GlobalThreatSearch onNavigateTab={onNavigateTab || (() => {})} />
        </div>
      )}

      {user && (
        <div style={{ display: "flex", alignItems: "center", gap: "1.25rem" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>Tenant:</span>
            <span style={{ fontSize: "0.85rem", fontWeight: 600, color: "#38bdf8" }}>
              {tenantName || "Loading..."}
            </span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <span style={{ fontSize: "0.85rem", color: "var(--text-secondary)" }}>
              {user.email}
            </span>
            <StatusBadge label={user.role} variant="role" />
          </div>

          <button
            onClick={onLogout}
            className="btn-secondary"
            style={{ padding: "0.4rem 0.75rem", fontSize: "0.8rem" }}
            title="Sign Out"
          >
            <LogOut size={14} />
            <span>Sign Out</span>
          </button>
        </div>
      )}
    </header>
  );
};
