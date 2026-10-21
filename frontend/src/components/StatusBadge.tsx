import React from "react";

interface StatusBadgeProps {
  label: string;
  variant?: "severity" | "status" | "role";
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ label, variant: _variant = "status" }) => {
  const normalized = label.toUpperCase();

  let bg = "rgba(100, 116, 139, 0.2)";
  let text = "#94a3b8";
  let border = "rgba(100, 116, 139, 0.3)";

  if (["CRITICAL", "FAILURE", "DENIED", "DECOMMISSIONED"].includes(normalized)) {
    bg = "rgba(244, 63, 94, 0.15)";
    text = "#fb7185";
    border = "rgba(244, 63, 94, 0.4)";
  } else if (["HIGH", "INVESTIGATING", "OFFLINE"].includes(normalized)) {
    bg = "rgba(245, 158, 11, 0.15)";
    text = "#fbbf24";
    border = "rgba(245, 158, 11, 0.4)";
  } else if (["MEDIUM", "IN_TRIAGE", "STAGING"].includes(normalized)) {
    bg = "rgba(6, 182, 212, 0.15)";
    text = "#38bdf8";
    border = "rgba(6, 182, 212, 0.4)";
  } else if (["LOW", "ACTIVE", "RESOLVED", "SUCCESS", "CLOSED"].includes(normalized)) {
    bg = "rgba(16, 185, 129, 0.15)";
    text = "#34d399";
    border = "rgba(16, 185, 129, 0.4)";
  } else if (["TENANT_ADMIN", "CISO", "SECURITY_MANAGER"].includes(normalized)) {
    bg = "rgba(139, 92, 246, 0.15)";
    text = "#c084fc";
    border = "rgba(139, 92, 246, 0.4)";
  }

  return (
    <span
      style={{
        backgroundColor: bg,
        color: text,
        border: `1px solid ${border}`,
        padding: "0.2rem 0.55rem",
        borderRadius: "9999px",
        fontSize: "0.75rem",
        fontWeight: 600,
        letterSpacing: "0.03em",
        display: "inline-flex",
        alignItems: "center",
        gap: "0.25rem",
        textTransform: "uppercase",
      }}
    >
      {label}
    </span>
  );
};
