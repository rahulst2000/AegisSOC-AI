import React from "react";

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: React.ReactNode;
  accent?: "cyan" | "emerald" | "rose" | "violet";
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  subtitle,
  icon,
  accent = "cyan",
}) => {
  const accentColors = {
    cyan: { text: "#06b6d4", glow: "glow-cyan" },
    emerald: { text: "#10b981", glow: "glow-emerald" },
    rose: { text: "#f43f5e", glow: "glow-rose" },
    violet: { text: "#8b5cf6", glow: "" },
  };

  const selected = accentColors[accent];

  return (
    <div
      className={`glass-panel ${selected.glow}`}
      style={{
        padding: "1.25rem 1.5rem",
        display: "flex",
        flexDirection: "column",
        gap: "0.5rem",
        position: "relative",
        overflow: "hidden",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontSize: "0.85rem", color: "var(--text-secondary)", fontWeight: 500 }}>
          {title}
        </span>
        <div style={{ color: selected.text, display: "flex", alignItems: "center" }}>
          {icon}
        </div>
      </div>
      <div style={{ fontSize: "1.85rem", fontWeight: 700, color: "var(--text-primary)" }}>
        {value}
      </div>
      {subtitle && (
        <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
          {subtitle}
        </span>
      )}
    </div>
  );
};
