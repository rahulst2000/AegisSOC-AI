import React from "react";
import {
  LayoutDashboard,
  AlertTriangle,
  Server,
  Activity,
  FileText,
  ShieldAlert,
  Sliders,
  Crosshair,
  TrendingUp,
} from "lucide-react";

export type NavTab =
  | "dashboard"
  | "incidents"
  | "rules"
  | "adversary"
  | "improvement"
  | "assets"
  | "events"
  | "docs";

interface SidebarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  openIncidentsCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  openIncidentsCount,
}) => {
  const navItems = [
    { id: "dashboard" as NavTab, label: "Overview", icon: <LayoutDashboard size={18} /> },
    {
      id: "incidents" as NavTab,
      label: "Incidents",
      icon: <AlertTriangle size={18} />,
      badge: openIncidentsCount > 0 ? openIncidentsCount : undefined,
    },
    { id: "rules" as NavTab, label: "Detection Rules", icon: <Sliders size={18} /> },
    { id: "adversary" as NavTab, label: "Adversary Validation", icon: <Crosshair size={18} /> },
    { id: "improvement" as NavTab, label: "Security Improvement", icon: <TrendingUp size={18} /> },
    { id: "assets" as NavTab, label: "Asset Inventory", icon: <Server size={18} /> },
    { id: "events" as NavTab, label: "Security Events", icon: <Activity size={18} /> },
    { id: "docs" as NavTab, label: "Architecture & Docs", icon: <FileText size={18} /> },
  ];

  return (
    <aside
      style={{
        width: "240px",
        backgroundColor: "rgba(10, 15, 29, 0.6)",
        borderRight: "1px solid var(--border-color)",
        padding: "1.25rem 0.75rem",
        display: "flex",
        flexDirection: "column",
        gap: "0.35rem",
      }}
    >
      <div style={{ padding: "0 0.75rem 0.75rem 0.75rem" }}>
        <span style={{ fontSize: "0.7rem", fontWeight: 700, color: "var(--text-muted)", letterSpacing: "0.08em" }}>
          SECURITY OPERATIONS
        </span>
      </div>

      {navItems.map((item) => {
        const isActive = activeTab === item.id;
        return (
          <button
            key={item.id}
            onClick={() => onSelectTab(item.id)}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "0.65rem 0.85rem",
              borderRadius: "8px",
              border: "none",
              background: isActive ? "rgba(6, 182, 212, 0.12)" : "transparent",
              color: isActive ? "#38bdf8" : "var(--text-secondary)",
              fontWeight: isActive ? 600 : 400,
              cursor: "pointer",
              transition: "all 0.15s ease",
              textAlign: "left",
              fontSize: "0.875rem",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
              <div style={{ color: isActive ? "#06b6d4" : "var(--text-muted)" }}>
                {item.icon}
              </div>
              <span>{item.label}</span>
            </div>

            {item.badge !== undefined && (
              <span
                style={{
                  backgroundColor: "rgba(244, 63, 94, 0.2)",
                  color: "#fb7185",
                  fontSize: "0.7rem",
                  fontWeight: 700,
                  padding: "0.15rem 0.45rem",
                  borderRadius: "9999px",
                  border: "1px solid rgba(244, 63, 94, 0.4)",
                }}
              >
                {item.badge}
              </span>
            )}
          </button>
        );
      })}

      <div style={{ marginTop: "auto", padding: "1rem 0.75rem" }}>
        <div
          className="glass-panel"
          style={{
            padding: "0.75rem",
            display: "flex",
            alignItems: "center",
            gap: "0.6rem",
            backgroundColor: "rgba(15, 23, 42, 0.4)",
          }}
        >
          <ShieldAlert size={18} style={{ color: "#10b981" }} />
          <div>
            <div style={{ fontSize: "0.75rem", fontWeight: 600, color: "#f8fafc" }}>
              Tenant Boundary
            </div>
            <div style={{ fontSize: "0.65rem", color: "#10b981" }}>
              Zero Trust Enforced
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
};
