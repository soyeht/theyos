import type { ReactElement } from "react";
import { useEffect, useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { ProtectedLayout } from "./components/ProtectedLayout";
import { api } from "./lib/api";
import type { User } from "./lib/types";
import { ClawStorePage } from "./pages/ClawStorePage";
import { CreatePage } from "./pages/CreatePage";
import { InstanceDetailPage } from "./pages/InstanceDetailPage";
import { InstancesPage } from "./pages/InstancesPage";
import { LoginPage } from "./pages/LoginPage";
import { LogsPage } from "./pages/LogsPage";
import { ModelsLivePage } from "./pages/ModelsLivePage";
import { ModelsPage } from "./pages/ModelsPage";
import { NetworkPage } from "./pages/NetworkPage";
import { SettingsPage } from "./pages/SettingsPage";
import { TerminalsPage } from "./pages/TerminalsPage";

function RequireAuth({ user, children }: { user: User | null; children: ReactElement }) {
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  return children;
}

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loadingAuth, setLoadingAuth] = useState(true);

  const refreshUser = async () => {
    try {
      const data = await api.me();
      setUser(data);
    } catch {
      setUser(null);
    }
  };

  useEffect(() => {
    void (async () => {
      await refreshUser();
      setLoadingAuth(false);
    })();
  }, []);

  const handleLogout = async () => {
    await api.logout();
    setUser(null);
  };

  if (loadingAuth) {
    return <div className="loading-screen">booting-soyeht...</div>;
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage onLoginSuccess={refreshUser} />} />

        {/* TODO(remove-before-merge): unauthenticated UX preview of /models so
            we can iterate on the design without booting the full server-rs stack. */}
        <Route path="/models-preview" element={<ModelsPage />} />

        <Route
          element={
            <RequireAuth user={user}>
              <ProtectedLayout user={user as User} onLogout={handleLogout} />
            </RequireAuth>
          }
        >
          <Route path="/" element={<Navigate to="/instances" replace />} />
          <Route path="/instances" element={<InstancesPage />} />
          <Route path="/instances/:id" element={<InstanceDetailPage />} />
          <Route path="/claws" element={<ClawStorePage />} />
          <Route path="/models" element={<ModelsLivePage />} />
          <Route path="/create" element={<CreatePage />} />
          <Route path="/logs" element={<LogsPage />} />
          <Route path="/terminals" element={<TerminalsPage />} />
          <Route path="/network" element={<NetworkPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
