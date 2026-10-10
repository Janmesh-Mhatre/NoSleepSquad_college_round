# Incognito — Technical Limitations & Operational Non-Claims
**Document Classification**: Risk Disclosure & Operational Boundaries  
**Version**: 2.2  
**Status**: Active  

---

## 1. Explicit Non-Claims & Real-World Boundaries

> The application separates institutional identity from anonymous reporting through privacy-preserving membership proofs. This protects against direct application-level identity disclosure, but does not eliminate risks from compromised devices, malicious infrastructure operators, traffic analysis, institutional identity-service compromise, or collusion between trusted components.

In accordance with responsible security engineering practices, Incognito explicitly rejects marketing slogans such as "100% anonymous", "completely untraceable", or "mathematically unbreakable anonymity".

---

## 2. Key Limitations & Risk Disclosures

### 2.1 Network-Layer Traffic Analysis
- **Limitation**: Zero-knowledge cryptographic proofs operate at the application layer. They protect identity data inside HTTP payloads, but cannot mask TCP/IP packet metadata.
- **Risk**: An adversary controlling campus Wi-Fi or ISP routers who observes a connection to `POST /api/reports` can infer that the device owner submitted a report at that timestamp.
- **Mitigation**: Users requiring network anonymity must access Incognito through Tor or an external VPN.

### 2.2 Anonymity Set Size ($N$)
- **Limitation**: A zero-knowledge membership proof proves inclusion in a group of size $N$.
- **Risk**: If a group contains only 2 members, the verifier knows the submitter is one of those 2 individuals.
- **Mitigation**: The system requires a minimum group threshold before opening anonymous reporting categories.

### 2.3 Trusted Setup Reliance (Groth16)
- **Limitation**: Groth16 zk-SNARKs rely on a structured reference string (SRS) generated during the Semaphore multi-party trusted setup ceremony.
- **Mitigation**: Semaphore v4 uses the official, publicly verified Ethereum Foundation multi-party computation (MPC) ceremony parameters.

### 2.4 Content-Based Deanonymization (Linguistic Stylometry & Self-Disclosure)
- **Limitation**: Cryptographic ciphers protect data in transit and at rest, but cannot sanitize narrative facts that identify the author.
- **Risk**: If an employee writes, *"I am the sole technician operating the mass spectrometer in building 4,"* administrators can deduce identity through context regardless of cryptographic separation.
- **Mitigation**: Incognito features an automated PII detector that warns reporters before submission. Users are strongly advised to omit unique dates, personal pronouns, and identifiable facts.

### 2.5 Compromised Client Endpoints
- **Limitation**: The security of client-side proof generation depends entirely on the integrity of the user's browser and machine.
- **Risk**: Keyloggers, screen recorders, or institutional spyware installed on university-managed laptops can record keystrokes before browser encryption occurs.
- **Mitigation**: Reporters should use personal, unmanaged devices and private browsing mode.

### 2.6 Blockchain Scope: Integrity vs Real-World Truth
- **Limitation**: Anchoring Merkle roots to the Ethereum blockchain guarantees **historical integrity and non-repudiation**; it does **NOT** certify physical truth.
- **Risk**: A malicious moderator who enters inaccurate case notes can still anchor them. The blockchain proves *what* was recorded and *when*, but cannot independently verify physical truth in the real world.

---

## 3. Implementation Status Matrix

### Implemented
- Semaphore v4 Groth16 zero-knowledge group membership proofs (`@semaphore-protocol/core`).
- Poseidon Merkle tree group maintenance and active root tracking.
- Canonical 248-bit topic-scoped external nullifiers and duplicate rejection.
- Zero identity columns / foreign keys in report storage.
- Authenticated AES-256-GCM cipher and constant-time status secret checking.
- Real `ethers` JsonRpcProvider and Wallet Signer connected to `AuditRegistry.sol`.
- Blockchain deployment automation and receipt metadata recording (`txHash`, `blockNumber`).
- Non-blocking outage handling (`pending_retry`) and contract root reconciliation.

### Partial
- Automated cron worker for background batch commits (currently exposed as callable service methods `publishBatchCommitment`, `retryPendingBatches`, and manual triggers).

### Simulated
- None remaining. All cryptographic and blockchain operations execute against real libraries (`@semaphore-protocol/core`, `ethers`, Hardhat).

### Not Implemented
- Network-layer Tor hidden service / onion routing (network-level anonymity must be provided by user transport).
