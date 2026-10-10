# Frontend Implementation Architecture

The Incognito frontend is built with React 18, TypeScript (Strict Mode), and Vite 5, adhering to institutional security aesthetics and strict metadata minimization.

---

## 1. Directory Structure

- **Core Routing & Entry**:
  - [src/main.tsx](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/main.tsx): React root initialization and client bootstrap.
  - [src/App.tsx](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/App.tsx): Declarative route tree mapping Public, Member, Moderator, and Administrator flows.
- **Design System & Styling**:
  - [src/styles/tokens.css](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/styles/tokens.css): Institutional color tokens, typography scales, surface hierarchies, and dark/light mode definitions.
  - [src/styles/global.css](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/styles/global.css): Global layout rules, button variants, accessible focus rings, tables, forms, and responsive breakpoints.
- **Shared Components & Layouts**:
  - [src/components/ui.tsx](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/components/ui.tsx): Reusable UI primitives (`StatusBadge`, `PageHeader`, `EmptyState`, `ErrorState`, `LoadingState`, `StepIndicator`, `PrivacyNotice`, `MetricCard`, `ConfirmationModal`).
  - [src/components/Layouts.tsx](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/components/Layouts.tsx): `PublicLayout` and `DashboardLayout` shells with keyboard skip links and navigation bars.
  - [src/components/TrustBoundaryDiagram.tsx](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/components/TrustBoundaryDiagram.tsx): 5-stage interactive trust boundary visualizer showing data visibility rules.
  - [src/components/AuditPipelineDiagram.tsx](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/components/AuditPipelineDiagram.tsx): 6-stage off-chain to on-chain Merkle audit visualizer.
- **API Client & Services**:
  - [src/api/client.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/api/client.ts): Central fetch client with error normalization and proxy support.
  - [src/api/types.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/api/types.ts): TypeScript interfaces for reports, metrics, audit batches, policies, and health.
  - [src/api/services.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/api/services.ts): Typed service endpoints for reporting, credentials, moderation, audit, and security.

---

## 2. Page Components & Workflows

### Public Pages
- [src/pages/Public.tsx](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/pages/Public.tsx):
  - `Landing`: Concrete product explanation, feature cards, trust boundary diagram, and technical limitation notices.
  - `HowItWorks`: Deep technical walkthrough of identity separation and transport hygiene.
  - `Security`: Detailed threat model (adversaries, defenses, and technical limitations).
  - `Help`: 12 comprehensive FAQs with backend-aligned answers.
  - `Privacy`: Zero-PII storage policy and in-memory drafting commitments.

### Member Pages
- [src/pages/Enroll.tsx](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/pages/Enroll.tsx):
  - 3-step enrollment workflow (Verify Eligibility, Issue Credential, Setup Confirmation).
  - Queries authoritative backend status via `credentialService.getMembershipStatus()`.
  - Executes registration via `credentialService.enroll()` and displays commitment digest.
- [src/pages/Report.tsx](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/pages/Report.tsx):
  - `Report`: 4-step wizard. Fetches live categories from backend, provides character bounds validation (20-5000 chars), mandates privacy review acknowledgment, and generates a client-side UUID idempotency key.
  - `Submitted`: Confirmation receipt displaying public reference (`INC-XXXXXX`) and single-view status secret (`sec_xxxxxxxx`). Includes print styling and warnings that secrets are not stored in browser storage.
  - `Status`: Authenticated status lookup requiring reference and secret. Displays a 6-stage lifecycle progression bar (`received` → `under_review` → `moderation_review` → `assigned` → `action_taken` → `closed`).

### Moderator Pages
- [src/pages/Moderator/ModeratorDashboard.tsx](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/pages/Moderator/ModeratorDashboard.tsx):
  - Real telemetry metrics (Total Reports, Awaiting Review, In Investigation, Resolved, Flagged, Audit Committed).
  - Summary table of recent queue items with direct links to review.
- [src/pages/Moderator/ReportQueue.tsx](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/pages/Moderator/ReportQueue.tsx):
  - Multi-dimensional filtering by status, category, priority, and text search.
  - Displays relative timestamps, safety signal tags, and moderation confidence scores.
- [src/pages/Moderator/ReportReview.tsx](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/pages/Moderator/ReportReview.tsx):
  - Two-panel review layout:
    - *Left Panel*: Decrypted report payload (AES-256-GCM), case timeline, and moderator audit trail.
    - *Right Panel*: AI safety evaluation (urgency score, confidence, policy rules) and action execution controls (`confirm`, `reclassify`, `escalate`, `request_review`, `close`) with mandatory justification.
- [src/pages/Moderator/ModerationPolicies.tsx](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/pages/Moderator/ModerationPolicies.tsx):
  - Active rule engine status, DistilBERT NLP classifier parameters, and LLM privacy fallback policies.

### Administrator Pages
- [src/pages/Admin/AdminDashboard.tsx](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/pages/Admin/AdminDashboard.tsx):
  - Audit queue status, security test pass rates, and system component telemetry.
- [src/pages/Admin/AuditDashboard.tsx](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/pages/Admin/AuditDashboard.tsx):
  - Batch sequence table, SHA-256 Merkle roots, and live `Verify Proof` action calling `auditService.verifyBatch()`.
- [src/pages/Admin/SecurityTests.tsx](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/pages/Admin/SecurityTests.tsx):
  - Live technical test runner asserting zero-PII schema, secret hashing, nullifier privacy, Merkle tree integrity, and header hygiene.
- [src/pages/Admin/SystemHealth.tsx](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/pages/Admin/SystemHealth.tsx):
  - Component readiness probes for API Gateway, SQLite Storage, Membership Registry, Moderation Engine, Audit Batcher, and Blockchain Bridge.

---

## 3. Frontend Security Controls

1. **In-Memory Drafting**: Form state exists strictly in React `useState`. Drafts are not written to `localStorage` or `sessionStorage`.
2. **Navigation Isolation**: Sensitive submission results (reference and secret) pass via React Router location state (`history.replaceState`), never in URL query strings.
3. **No Decorative AI Vibe Coding**: Interface eliminates purple glowing gradients, oversized pill containers, and arbitrary SaaS metrics.
4. **Accessible Semantics**: Focus indicators (`:focus-visible`), WCAG AA contrast, semantic HTML headings, screen-reader ARIA tags, and keyboard skip links.
