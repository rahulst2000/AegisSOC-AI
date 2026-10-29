import React, { useEffect, useState } from "react";
import { Alert, Asset, AuthResponse, Incident, SecurityEvent, User } from "./types";
import { api } from "./services/api";
import { Navbar } from "./components/Navbar";
import { NavTab, Sidebar } from "./components/Sidebar";
import { LoginPage } from "./pages/LoginPage";
import { DashboardPage } from "./pages/DashboardPage";
import { IncidentsPage } from "./pages/IncidentsPage";
import { AssetsPage } from "./pages/AssetsPage";
import { EventsPage } from "./pages/EventsPage";
import { DocsPage } from "./pages/DocsPage";
import RulesPage from "./pages/RulesPage";
import { AdversaryPage } from "./pages/AdversaryPage";
import { SecurityImprovementPage } from "./pages/SecurityImprovementPage";
import { IntelligencePage } from "./pages/IntelligencePage";

export const App: React.FC = () => {
  const [user, setUser] = useState<User | null>(null);
  const [tenantName, setTenantName] = useState<string>("");
  const [activeTab, setActiveTab] = useState<NavTab>("dashboard");
  const [initializing, setInitializing] = useState(true);
  const [dataError, setDataError] = useState<string | null>(null);

  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);

  // Setup auth expiration handler
  useEffect(() => {
    api.onAuthExpired(() => {
      setUser(null);
      setTenantName("");
      setDataError("Your authentication session has expired. Please sign in again.");
    });
  }, []);

  // Load user session on startup
  useEffect(() => {
    const initAuth = async () => {
      const token = api.getToken();
      if (token) {
        try {
          const me = await api.getMe();
          setUser(me);
          const tenant = await api.getMyTenant();
          setTenantName(tenant.name);
        } catch {
          api.logout();
          setUser(null);
        }
      }
      setInitializing(false);
    };
    initAuth();
  }, []);

  const refreshData = async () => {
    if (!user) return;
    setDataError(null);
    try {
      const [incList, assetList, evtList, alertList, tenantInfo] = await Promise.all([
        api.getIncidents(),
        api.getAssets(),
        api.getEvents(),
        api.getAlerts(),
        api.getMyTenant(),
      ]);
      setIncidents(incList);
      setAssets(assetList);
      setEvents(evtList);
      setAlerts(alertList);
      if (tenantInfo) setTenantName(tenantInfo.name);
    } catch (err: any) {
      if (err?.isAuthError || err?.status === 401) {
        setUser(null);
        setDataError("Authentication expired — please sign in again.");
      } else {
        setDataError(err?.message || "Failed to synchronize operational security telemetry.");
      }
    }
  };

  useEffect(() => {
    if (user) {
      refreshData();
    }
  }, [user]);

  const handleAuthSuccess = (authData: AuthResponse) => {
    setUser(authData.user);
    setDataError(null);
    refreshData();
  };

  const handleLogout = () => {
    api.logout();
    setUser(null);
    setTenantName("");
    setIncidents([]);
    setAssets([]);
    setEvents([]);
    setAlerts([]);
    setDataError(null);
  };


  if (initializing) {
    return (
      <div
        style={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          backgroundColor: "var(--bg-primary)",
        }}
      >
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "1rem" }}>
          <span className="live-indicator" style={{ width: "16px", height: "16px" }} />
          <span style={{ fontSize: "0.85rem", color: "var(--text-secondary)" }}>
            Initializing AegisSOC Security Engine...
          </span>
        </div>
      </div>
    );
  }

  if (!user) {
    return <LoginPage onAuthSuccess={handleAuthSuccess} />;
  }

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      <Navbar
        user={user}
        tenantName={tenantName}
        onLogout={handleLogout}
        onNavigateTab={(tab) => setActiveTab(tab as NavTab)}
      />

      <div style={{ display: "flex", flex: 1 }}>
        <Sidebar
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          openIncidentsCount={incidents.filter((i) => i.status !== "RESOLVED" && i.status !== "CLOSED").length}
        />

        <main style={{ flex: 1, padding: "2rem", overflowY: "auto" }}>
          {dataError && (
            <div
              style={{
                marginBottom: "1.5rem",
                padding: "1rem 1.25rem",
                borderRadius: "0.75rem",
                backgroundColor: "rgba(244, 63, 94, 0.15)",
                border: "1px solid rgba(244, 63, 94, 0.4)",
                color: "#fecdd3",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <span>⚠️ {dataError}</span>
              <button
                onClick={refreshData}
                style={{
                  background: "rgba(244, 63, 94, 0.3)",
                  border: "none",
                  color: "#fff",
                  padding: "0.4rem 0.8rem",
                  borderRadius: "0.5rem",
                  cursor: "pointer",
                  fontSize: "0.8rem",
                }}
              >
                Retry
              </button>
            </div>
          )}
          {activeTab === "dashboard" && (

            <DashboardPage
              user={user}
              incidents={incidents}
              assets={assets}
              events={events}
              alerts={alerts}
              onNavigateTab={setActiveTab}
              onRefresh={refreshData}
            />
          )}

          {activeTab === "incidents" && (
            <IncidentsPage incidents={incidents} onRefresh={refreshData} />
          )}

          {activeTab === "rules" && (
            <RulesPage currentUser={user} />
          )}

          {activeTab === "adversary" && (
            <AdversaryPage />
          )}

          {activeTab === "improvement" && (
            <SecurityImprovementPage />
          )}

          {activeTab === "intelligence" && (
            <IntelligencePage incidents={incidents} />
          )}

          {activeTab === "assets" && (
            <AssetsPage assets={assets} onRefresh={refreshData} />
          )}

          {activeTab === "events" && (
            <EventsPage events={events} onRefresh={refreshData} />
          )}

          {activeTab === "docs" && <DocsPage />}
        </main>
      </div>
    </div>
  );
};

export default App;
