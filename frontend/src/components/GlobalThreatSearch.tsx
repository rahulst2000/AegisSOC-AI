import React, { useEffect, useRef, useState } from "react";
import {
  Activity,
  Bell,
  Search,
  Server,
  Shield,
  ShieldAlert,
  X,
} from "lucide-react";
import { api } from "../services/api";
import { StatusBadge } from "./StatusBadge";

interface GlobalThreatSearchProps {
  onNavigateTab: (tab: string, context?: any) => void;
}

export const GlobalThreatSearch: React.FC<GlobalThreatSearchProps> = ({ onNavigateTab }) => {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);
  const [isOpen, setIsOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        setIsOpen(true);
        const input = containerRef.current?.querySelector("input");
        input?.focus();
      } else if (e.key === "Escape") {
        setIsOpen(false);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, []);

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value;
    setQuery(val);

    if (debounceRef.current) clearTimeout(debounceRef.current);

    if (!val.trim()) {
      setResults(null);
      setLoading(false);
      return;
    }

    setLoading(true);
    setIsOpen(true);

    debounceRef.current = setTimeout(async () => {
      try {
        const res = await api.search(val);
        setResults(res);
      } catch {
        setResults(null);
      } finally {
        setLoading(false);
      }
    }, 250);
  };

  const handleSelect = (category: string, item: any) => {
    setIsOpen(false);
    setQuery("");
    if (category === "incidents") {
      onNavigateTab("incidents", { incidentId: item.id });
    } else if (category === "events") {
      onNavigateTab("events", { eventId: item.id });
    } else if (category === "assets") {
      onNavigateTab("assets", { assetId: item.id });
    } else if (category === "threat_intelligence") {
      onNavigateTab("intelligence", { indicator: item.indicator });
    } else if (category === "detections" || category === "alerts") {
      onNavigateTab("incidents", { filter: item.id });
    }
  };

  const total = results?.total_matches || 0;

  return (
    <div ref={containerRef} style={{ position: "relative", width: "360px" }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "0.5rem",
          background: "rgba(15, 23, 42, 0.8)",
          border: "1px solid var(--border-color)",
          borderRadius: "8px",
          padding: "0.4rem 0.75rem",
          transition: "all 0.2s ease",
          boxShadow: isOpen ? "0 0 0 2px rgba(6, 182, 212, 0.3)" : "none",
        }}
      >
        <Search size={15} style={{ color: "var(--text-muted)", flexShrink: 0 }} />
        <input
          type="text"
          value={query}
          onChange={handleSearchChange}
          onFocus={() => {
            if (query.trim()) setIsOpen(true);
          }}
          placeholder="Global threat search (IP, Host, User, IOC...)"
          style={{
            background: "none",
            border: "none",
            outline: "none",
            color: "#f8fafc",
            fontSize: "0.8rem",
            width: "100%",
          }}
        />
        {query ? (
          <button
            onClick={() => {
              setQuery("");
              setResults(null);
              setIsOpen(false);
            }}
            style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer", padding: 0 }}
          >
            <X size={14} />
          </button>
        ) : (
          <span
            style={{
              fontSize: "0.65rem",
              background: "rgba(255, 255, 255, 0.08)",
              border: "1px solid rgba(255, 255, 255, 0.12)",
              borderRadius: "4px",
              padding: "0.1rem 0.35rem",
              color: "var(--text-muted)",
              fontFamily: "monospace",
              flexShrink: 0,
            }}
          >
            Ctrl+K
          </span>
        )}
      </div>

      {/* Categorized Dropdown Results */}
      {isOpen && query.trim() && (
        <div
          className="glass-panel"
          style={{
            position: "absolute",
            top: "calc(100% + 6px)",
            left: 0,
            right: 0,
            width: "480px",
            maxHeight: "440px",
            overflowY: "auto",
            zIndex: 100,
            padding: "0.75rem",
            background: "rgba(10, 15, 29, 0.95)",
            backdropFilter: "blur(16px)",
            border: "1px solid rgba(6, 182, 212, 0.25)",
            borderRadius: "8px",
            boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5)",
            display: "flex",
            flexDirection: "column",
            gap: "0.75rem",
          }}
        >
          {loading ? (
            <div style={{ padding: "1.5rem", textAlign: "center", color: "var(--text-muted)", fontSize: "0.8rem" }}>
              <span>Searching multi-entity security catalog...</span>
            </div>
          ) : total === 0 ? (
            <div style={{ padding: "1.5rem", textAlign: "center", color: "var(--text-muted)", fontSize: "0.8rem" }}>
              <span>No security entities found matching &quot;{query}&quot;</span>
            </div>
          ) : (
            <>
              {/* Incidents Category */}
              {results?.categories?.incidents?.length > 0 && (
                <div>
                  <div
                    style={{
                      fontSize: "0.7rem",
                      fontWeight: 700,
                      color: "#f43f5e",
                      textTransform: "uppercase",
                      letterSpacing: "0.05em",
                      marginBottom: "0.35rem",
                      display: "flex",
                      alignItems: "center",
                      gap: "0.35rem",
                    }}
                  >
                    <ShieldAlert size={12} />
                    <span>Incidents ({results.categories.incidents.length})</span>
                  </div>
                  {results.categories.incidents.map((inc: any) => (
                    <div
                      key={inc.id}
                      onClick={() => handleSelect("incidents", inc)}
                      style={{
                        padding: "0.45rem 0.6rem",
                        borderRadius: "6px",
                        background: "rgba(255, 255, 255, 0.03)",
                        marginBottom: "0.25rem",
                        cursor: "pointer",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.backgroundColor = "rgba(6, 182, 212, 0.08)";
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.backgroundColor = "rgba(255, 255, 255, 0.03)";
                      }}
                    >
                      <div style={{ display: "flex", flexDirection: "column" }}>
                        <span style={{ fontSize: "0.8rem", fontWeight: 600, color: "#f8fafc" }}>
                          {inc.title}
                        </span>
                        <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>
                          Risk: {inc.risk_score} • Status: {inc.status}
                        </span>
                      </div>
                      <StatusBadge label={inc.severity} variant="severity" />
                    </div>
                  ))}
                </div>
              )}

              {/* Security Events Category */}
              {results?.categories?.events?.length > 0 && (
                <div>
                  <div
                    style={{
                      fontSize: "0.7rem",
                      fontWeight: 700,
                      color: "#38bdf8",
                      textTransform: "uppercase",
                      letterSpacing: "0.05em",
                      marginBottom: "0.35rem",
                      display: "flex",
                      alignItems: "center",
                      gap: "0.35rem",
                    }}
                  >
                    <Activity size={12} />
                    <span>Telemetry Events ({results.categories.events.length})</span>
                  </div>
                  {results.categories.events.map((evt: any) => (
                    <div
                      key={evt.id}
                      onClick={() => handleSelect("events", evt)}
                      style={{
                        padding: "0.45rem 0.6rem",
                        borderRadius: "6px",
                        background: "rgba(255, 255, 255, 0.03)",
                        marginBottom: "0.25rem",
                        cursor: "pointer",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.backgroundColor = "rgba(6, 182, 212, 0.08)";
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.backgroundColor = "rgba(255, 255, 255, 0.03)";
                      }}
                    >
                      <div style={{ display: "flex", flexDirection: "column" }}>
                        <span className="mono" style={{ fontSize: "0.78rem", color: "#38bdf8", fontWeight: 500 }}>
                          {evt.event_type}
                        </span>
                        <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>
                          Src: {evt.source} • IP: {evt.source_ip || "—"} • User: {evt.username || "—"}
                        </span>
                      </div>
                      <StatusBadge label={evt.severity} variant="severity" />
                    </div>
                  ))}
                </div>
              )}

              {/* Alerts Category */}
              {results?.categories?.alerts?.length > 0 && (
                <div>
                  <div
                    style={{
                      fontSize: "0.7rem",
                      fontWeight: 700,
                      color: "#10b981",
                      textTransform: "uppercase",
                      letterSpacing: "0.05em",
                      marginBottom: "0.35rem",
                      display: "flex",
                      alignItems: "center",
                      gap: "0.35rem",
                    }}
                  >
                    <Bell size={12} />
                    <span>Detection Alerts ({results.categories.alerts.length})</span>
                  </div>
                  {results.categories.alerts.map((alt: any) => (
                    <div
                      key={alt.id}
                      onClick={() => handleSelect("alerts", alt)}
                      style={{
                        padding: "0.45rem 0.6rem",
                        borderRadius: "6px",
                        background: "rgba(255, 255, 255, 0.03)",
                        marginBottom: "0.25rem",
                        cursor: "pointer",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.backgroundColor = "rgba(6, 182, 212, 0.08)";
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.backgroundColor = "rgba(255, 255, 255, 0.03)";
                      }}
                    >
                      <div style={{ display: "flex", flexDirection: "column" }}>
                        <span className="mono" style={{ fontSize: "0.78rem", color: "#f8fafc" }}>
                          {alt.detection_rule}
                        </span>
                        <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>
                          Status: {alt.status}
                        </span>
                      </div>
                      <StatusBadge label={alt.severity} variant="severity" />
                    </div>
                  ))}
                </div>
              )}

              {/* Assets Category */}
              {results?.categories?.assets?.length > 0 && (
                <div>
                  <div
                    style={{
                      fontSize: "0.7rem",
                      fontWeight: 700,
                      color: "#a855f7",
                      textTransform: "uppercase",
                      letterSpacing: "0.05em",
                      marginBottom: "0.35rem",
                      display: "flex",
                      alignItems: "center",
                      gap: "0.35rem",
                    }}
                  >
                    <Server size={12} />
                    <span>Monitored Assets ({results.categories.assets.length})</span>
                  </div>
                  {results.categories.assets.map((ast: any) => (
                    <div
                      key={ast.id}
                      onClick={() => handleSelect("assets", ast)}
                      style={{
                        padding: "0.45rem 0.6rem",
                        borderRadius: "6px",
                        background: "rgba(255, 255, 255, 0.03)",
                        marginBottom: "0.25rem",
                        cursor: "pointer",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.backgroundColor = "rgba(6, 182, 212, 0.08)";
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.backgroundColor = "rgba(255, 255, 255, 0.03)";
                      }}
                    >
                      <div style={{ display: "flex", flexDirection: "column" }}>
                        <span style={{ fontSize: "0.8rem", fontWeight: 600, color: "#f8fafc" }}>
                          {ast.hostname}
                        </span>
                        <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>
                          IP: {ast.ip_address} • Type: {ast.asset_type}
                        </span>
                      </div>
                      <StatusBadge label={ast.criticality} variant="severity" />
                    </div>
                  ))}
                </div>
              )}

              {/* Threat Intelligence Category */}
              {results?.categories?.threat_intelligence?.length > 0 && (
                <div>
                  <div
                    style={{
                      fontSize: "0.7rem",
                      fontWeight: 700,
                      color: "#f59e0b",
                      textTransform: "uppercase",
                      letterSpacing: "0.05em",
                      marginBottom: "0.35rem",
                      display: "flex",
                      alignItems: "center",
                      gap: "0.35rem",
                    }}
                  >
                    <Shield size={12} />
                    <span>Threat Intelligence ({results.categories.threat_intelligence.length})</span>
                  </div>
                  {results.categories.threat_intelligence.map((ti: any, idx: number) => (
                    <div
                      key={idx}
                      onClick={() => handleSelect("threat_intelligence", ti)}
                      style={{
                        padding: "0.45rem 0.6rem",
                        borderRadius: "6px",
                        background: "rgba(255, 255, 255, 0.03)",
                        marginBottom: "0.25rem",
                        cursor: "pointer",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.backgroundColor = "rgba(6, 182, 212, 0.08)";
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.backgroundColor = "rgba(255, 255, 255, 0.03)";
                      }}
                    >
                      <div style={{ display: "flex", flexDirection: "column" }}>
                        <span className="mono" style={{ fontSize: "0.8rem", color: "#f59e0b", fontWeight: 600 }}>
                          {ti.indicator}
                        </span>
                        <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>
                          {ti.threat_type} • Score: {ti.threat_score}
                        </span>
                      </div>
                      <span
                        style={{
                          fontSize: "0.7rem",
                          color: "#f59e0b",
                          background: "rgba(245, 158, 11, 0.1)",
                          padding: "0.2rem 0.4rem",
                          borderRadius: "4px",
                        }}
                      >
                        IOC MATCH
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
};
