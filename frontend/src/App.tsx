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

export const App: React.FC = () => {
  const [user, setUser] = useState<User | null>(null);
  const [tenantName, setTenantName] = useState<string>("");
  const [activeTab, setActiveTab] = useState<NavTab>("dashboard");
  const [initializing, setInitializing] = useState(true);

  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);

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
    try {
      const [incList, assetList, evtList, alertList, tenantInfo] = await Promise.all([
        api.getIncidents().catch(() => []),
        api.getAssets().catch(() => []),
        api.getEvents().catch(() => []),
        api.getAlerts().catch(() => []),
        api.getMyTenant().catch(() => null),
      ]);
      setIncidents(incList);
      setAssets(assetList);
      setEvents(evtList);
      setAlerts(alertList);
      if (tenantInfo) setTenantName(tenantInfo.name);
    } catch {
      // Handled silently
    }
  };

  useEffect(() => {
    if (user) {
      refreshData();
    }
  }, [user]);

  const handleAuthSuccess = (authData: AuthResponse) => {
    setUser(authData.user);
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
      <Navbar user={user} tenantName={tenantName} onLogout={handleLogout} />

      <div style={{ display: "flex", flex: 1 }}>
        <Sidebar
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          openIncidentsCount={incidents.filter((i) => i.status !== "RESOLVED" && i.status !== "CLOSED").length}
        />

        <main style={{ flex: 1, padding: "2rem", overflowY: "auto" }}>
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
