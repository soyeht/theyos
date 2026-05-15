import { useState, useEffect } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import type { User } from "../lib/types";
import { MaintenanceBanner } from "./MaintenanceBanner";
import { UpgradeBanner } from "./UpgradeBanner";

type ProtectedLayoutProps = {
  user: User;
  onLogout: () => Promise<void>;
};

export function ProtectedLayout({ user, onLogout }: ProtectedLayoutProps) {
  const navigate = useNavigate();
  const [navOpen, setNavOpen] = useState(false);
  const [theme, setTheme] = useState(
    () => document.documentElement.getAttribute("data-theme") || "light"
  );

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("soyeht-theme", next);
  };

  useEffect(() => {
    if (localStorage.getItem("soyeht-theme")) return;
    const mq = matchMedia("(prefers-color-scheme: dark)");
    const handler = (e: MediaQueryListEvent) => {
      const val = e.matches ? "dark" : "light";
      setTheme(val);
      document.documentElement.setAttribute("data-theme", val);
    };
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);

  const handleLogout = async () => {
    await onLogout();
    navigate("/login", { replace: true });
  };

  const closeNav = () => setNavOpen(false);

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-brand">
          <span className="prompt">&gt;</span>
          <span>soyeht</span>
        </div>

        <button
          type="button"
          className="nav-toggle"
          aria-label="menu"
          onClick={() => setNavOpen((o) => !o)}
        >
          &#9776;
        </button>

        <nav className={`topbar-nav${navOpen ? " nav-open" : ""}`} aria-label="main menu">
          <NavLink to="/instances" className="nav-item" onClick={closeNav}>
            instances
          </NavLink>
          <NavLink to="/claws" className="nav-item" onClick={closeNav}>
            claws
          </NavLink>
          <NavLink to="/create" className="nav-item" onClick={closeNav}>
            create
          </NavLink>
          <NavLink to="/logs" className="nav-item" onClick={closeNav}>
            logs
          </NavLink>
          <NavLink to="/terminals" className="nav-item" onClick={closeNav}>
            terminals
          </NavLink>
          <NavLink to="/network" className="nav-item" onClick={closeNav}>
            network
          </NavLink>
          <NavLink to="/settings" className="nav-item" onClick={closeNav}>
            settings
          </NavLink>
        </nav>

        <button
          type="button"
          className="theme-toggle"
          onClick={toggleTheme}
          aria-label={theme === "dark" ? "switch to light mode" : "switch to dark mode"}
          title={theme === "dark" ? "switch to light mode" : "switch to dark mode"}
        >
          {theme === "dark" ? "light" : "dark"}
        </button>

        <button type="button" className="logout-btn" onClick={handleLogout}>
          sign out ({user.username})
        </button>
      </header>

      <MaintenanceBanner />

      <main className="page-content">
        <Outlet />
        <UpgradeBanner />
      </main>
    </div>
  );
}
