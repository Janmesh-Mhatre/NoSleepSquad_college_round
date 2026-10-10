# Incognito — Technical Limitations & Environmental Assumptions

## 1. Scope of Protections

Incognito is engineered to solve the problem of institutional whistleblower intimidation by mathematically decoupling identity from reporting. However, real-world deployments operate within physical, legal, and operational constraints.

---

## 2. Explicit System Limitations

### 2.1 Network Transport Metadata (Traffic Analysis)
- The application layer strips IP addresses, cookies, and session headers.
- However, physical TCP/IP packets transit campus switches and ISPs. If an adversary has wiretap access to the victim's network and correlates the precise millisecond of a student's OIDC login with the arrival of an HTTP POST to `/api/reports`, they can infer the reporting event.
- **Limitation**: Cannot be solved at the web app layer alone. Whistleblowers in high-threat environments must use Tor or an external VPN.

### 2.2 Stylometry
- Cryptography protects the sender's identity, but cannot prevent the whistleblower from voluntarily typing self-revealing circumstantial details (e.g., job titles, dates, idiosyncratic slang).
- **Limitation**: Requires user discipline and UI guidance.

### 2.3 Anonymity Set Dynamics
- Zero-knowledge membership proofs prove membership in an institutional group.
- If an institutional group tree contains only 1 or 2 registered students, the anonymity set is trivially small.
- **Requirement**: Institutional deployments should maintain group sizes of $N \ge 50$ members.

### 2.4 Browser Endpoint Compromise
- If a student's workstation is infected with keyloggers or screen recording malware, or if a physical camera is pointed at the screen, the browser session is compromised.
- **Mitigation**: Users must generate reports from secure, trusted devices.
