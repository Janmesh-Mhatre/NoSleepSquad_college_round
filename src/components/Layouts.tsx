import { NavLink, Outlet, useLocation } from "react-router-dom";
import { Shield, ShieldAlert, SlidersHorizontal, Lock, CheckCircle, FileText, Activity, Layers, Terminal } from "lucide-react";

const PUBLIC_NAV = [
  { to: "/how-it-works", label: "How it works" },
  { to: "/security", label: "Security" },
  { to: "/report/status", label: "Track report" },
  { to: "/help", label: "Help & FAQ" },
  { to: "/privacy", label: "Privacy" },
];

export function PublicHeader() {
  const loc = useLocation();
  const isDash = loc.pathname.startsWith("/moderator") || loc.pathname.startsWith("/admin");

  return (
    <header className="hdr">
      <div className="wrap">
        <NavLink to="/" className="brand">
          <Shield size={20} style={{ color: "var(--accent)" }} aria-hidden />
          <span>Incognito</span>
          <span className="brand-badge">Institutional</span>
        </NavLink>

        <nav aria-label="Primary navigation">
          {PUBLIC_NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              className={({ isActive }) => (isActive ? "active" : undefined)}
            >
              {n.label}
            </NavLink>
          ))}
        </nav>

        <div className="hdr-actions">
          <NavLink to="/enroll" className="btn sm">
            Verify eligibility
          </NavLink>
          <NavLink to="/report" className="btn sm primary">
            Submit a Report
          </NavLink>
          {!isDash ? (
            <NavLink
              to="/moderator"
              className="btn sm"
              style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}
              title="Switch to Institutional Staff View"
            >
              Console
            </NavLink>
          ) : (
            <NavLink
              to="/"
              className="btn sm"
              style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}
            >
              Public View
            </NavLink>
          )}
        </div>
      </div>
    </header>
  );
}

export function PublicLayout() {
  return (
    <>
      <a href="#main-content" className="skip-link">Skip to main content</a>
      <PublicHeader />
      <main id="main-content" className="wrap" style={{ padding: "36px 16px 64px" }}>
        <Outlet />
      </main>
      <footer style={{ borderTop: "1px solid var(--border)", background: "var(--surface)", padding: "28px 0", marginTop: "auto" }}>
        <div className="wrap" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 16 }}>
          <div className="muted" style={{ fontSize: "0.85rem" }}>
            Designed to separate institutional identity from report submission. See the{" "}
            <NavLink to="/security" style={{ fontWeight: 600 }}>technical limitations and threat model</NavLink>.
          </div>
          <div className="row" style={{ fontSize: "0.82rem" }}>
            <NavLink to="/privacy" className="muted">Privacy Policy</NavLink>
            <span className="muted">·</span>
            <NavLink to="/security" className="muted">Security Posture</NavLink>
            <span className="muted">·</span>
            <NavLink to="/admin" className="muted">Admin Audit Console</NavLink>
          </div>
        </div>
      </footer>
    </>
  );
}

export interface NavItem {
  to: string;
  label: string;
  icon: typeof Shield;
}

export function DashboardLayout({
  title,
  items,
}: {
  title: string;
  items: NavItem[];
}) {
  return (
    <>
      <a href="#dash-content" className="skip-link">Skip to main content</a>
      <PublicHeader />
      <div className="dash">
        <nav className="side" aria-label={`${title} Sidebar Navigation`}>
          <div className="side-header">{title} Console</div>
          {items.map((it) => {
            const Icon = it.icon;
            return (
              <NavLink
                key={it.to}
                to={it.to}
                end={it.to === "/moderator" || it.to === "/admin"}
                className={({ isActive }) => (isActive ? "active" : undefined)}
              >
                <Icon size={16} aria-hidden />
                <span>{it.label}</span>
              </NavLink>
            );
          })}
        </nav>
        <main id="dash-content" className="main">
          <Outlet />
        </main>
      </div>
    </>
  );
}
