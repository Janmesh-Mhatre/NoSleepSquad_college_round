import { Route, Routes } from "react-router-dom";
import { PublicLayout, DashboardLayout, type NavItem } from "./components/Layouts";
import { Landing, HowItWorks, Security, Help, Privacy } from "./pages/Public";
import { Enroll } from "./pages/Enroll";
import { Report, Submitted, Status } from "./pages/Report";
import { ModeratorDashboard } from "./pages/Moderator/ModeratorDashboard";
import { ReportQueue } from "./pages/Moderator/ReportQueue";
import { ReportReview } from "./pages/Moderator/ReportReview";
import { ModerationPolicies } from "./pages/Moderator/ModerationPolicies";
import { AdminDashboard } from "./pages/Admin/AdminDashboard";
import { AuditDashboard } from "./pages/Admin/AuditDashboard";
import { SecurityTests } from "./pages/Admin/SecurityTests";
import { SystemHealth } from "./pages/Admin/SystemHealth";
import { Activity, Inbox, SlidersHorizontal, Layers, ShieldCheck, Terminal } from "lucide-react";

const MODERATOR_NAV: NavItem[] = [
  { to: "/moderator", label: "Overview", icon: Activity },
  { to: "/moderator/reports", label: "Report Queue", icon: Inbox },
  { to: "/moderator/moderation", label: "Safety Policies", icon: SlidersHorizontal },
];

const ADMIN_NAV: NavItem[] = [
  { to: "/admin", label: "Overview", icon: Activity },
  { to: "/admin/audit", label: "Audit Commitments", icon: Layers },
  { to: "/admin/security", label: "Security Tests", icon: ShieldCheck },
  { to: "/admin/system", label: "System Health", icon: Terminal },
];

export default function App() {
  return (
    <Routes>
      {/* Public & Member Routes */}
      <Route element={<PublicLayout />}>
        <Route index element={<Landing />} />
        <Route path="how-it-works" element={<HowItWorks />} />
        <Route path="security" element={<Security />} />
        <Route path="help" element={<Help />} />
        <Route path="privacy" element={<Privacy />} />
        <Route path="enroll" element={<Enroll />} />
        <Route path="report" element={<Report />} />
        <Route path="report/submitted" element={<Submitted />} />
        <Route path="report/status" element={<Status />} />
      </Route>

      {/* Institutional Moderator Console */}
      <Route path="moderator" element={<DashboardLayout title="Moderator" items={MODERATOR_NAV} />}>
        <Route index element={<ModeratorDashboard />} />
        <Route path="reports" element={<ReportQueue />} />
        <Route path="reports/:id" element={<ReportReview />} />
        <Route path="moderation" element={<ModerationPolicies />} />
      </Route>

      {/* Institutional Administrator Console */}
      <Route path="admin" element={<DashboardLayout title="Administrator" items={ADMIN_NAV} />}>
        <Route index element={<AdminDashboard />} />
        <Route path="audit" element={<AuditDashboard />} />
        <Route path="security" element={<SecurityTests />} />
        <Route path="system" element={<SystemHealth />} />
      </Route>
    </Routes>
  );
}
