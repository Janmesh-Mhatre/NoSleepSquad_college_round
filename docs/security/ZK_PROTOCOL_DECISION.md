# ZK Protocol Decision Document: Semaphore v4 Protocol Selection

## 1. Selected Protocol & Library

- **Protocol**: Semaphore Anonymous Signaling & Group Membership Proof System
- **Library**: `@semaphore-protocol/core`
- **Version**: `^4.14.3` (installed: `4.14.3`)
- **Underlying Zero-Knowledge Engine**: SnarkJS Groth16 zk-SNARK prover and verifier over BN254 / Alt-bn128 curve with Poseidon hash function.

---

## 2. Selection Rationale

The project previously utilized an ad-hoc custom prototype consisting of SHA-256 Merkle siblings, an identity commitment exposed in cleartext to the verifier, and a Fiat-Shamir HMAC challenge/response. This was **not** a zero-knowledge proof because:
1. The leaf commitment was directly submitted to the verifier, instantly breaking anonymity by allowing the verifier to identify which leaf in the tree submitted the report.
2. The verification logic could not guarantee knowledge of the trapdoor/secret without revealing identifying values.

To satisfy the requirements of honest, established zero-knowledge cryptography, `@semaphore-protocol/core` v4 was selected for the following technical and architectural reasons:

1. **Established & Battle-Tested Standard**:
   - Semaphore is an audited, Ethereum Foundation-supported zero-knowledge protocol designed specifically for privacy-preserving group membership and anonymous signaling.
2. **True Zero-Knowledge Guarantee**:
   - In Semaphore Groth16 proofs, the identity commitment is a private witness within the Circom arithmetic circuit. The verifier only learns:
     $$\text{Known}(identitySecret) \land (Commitment \in Tree(Root))$$
     without discovering *which* commitment in the tree belongs to the prover or revealing the prover's secret trapdoor.
3. **Native Support for Scoped Nullifiers (`scope`)**:
   - Semaphore v4 uses a `scope` parameter (external nullifier). Provers generate:
     $$Nullifier = \text{Poseidon}(identityNullifier, scope)$$
     This guarantees:
     - **Cross-topic unlinkability**: The nullifier generated for topic `cat-safety` cannot be correlated or linked with the nullifier generated for topic `cat-academic`.
     - **Same-topic replay / duplicate prevention**: If a prover attempts to submit multiple reports under the same topic scope, the exact same nullifier is produced, enabling deterministic double-submission detection.
4. **Signal / Context Binding (`message`)**:
   - Semaphore binds a `message` scalar into the Groth16 circuit. In Incognito, this binds the canonical digest of the report payload to the proof, preventing proof-stealing or front-running attacks where an adversary attempts to re-attach an intercepted proof to a different report.
5. **Node.js & TypeScript Ecosystem Compatibility**:
   - `@semaphore-protocol/core` supports native Node.js environments and modern browsers using WebAssembly and Web Workers.

---

## 3. Cryptographic Specification & Security Model

### 3.1 Primitives
- **Curve**: BN254 (alt_bn128)
- **Hash Function**: Poseidon sponge hash function, optimized for arithmetic circuit constraints
- **Proof System**: Groth16 zk-SNARK
- **Tree Structure**: Incremental Merkle Tree with Poseidon hash, default depth 20 (supporting up to $2^{20} = 1,048,576$ members)

### 3.2 Proof Inputs & Public Outputs
- **Private Inputs (Witness)**:
  - `identitySecret`: The user's private scalar (never sent across the network or stored in databases).
  - Merkle proof path & index.
- **Public Signals (Verified by Backend)**:
  - `merkleTreeRoot`: The root of the active institutional group at the time of proof generation.
  - `nullifier`: The derived nullifier hash scoped to the topic.
  - `message`: The canonical report signal digest.
  - `scope`: The topic scope identifier.
  - `points`: Groth16 proof points $(\pi_A \in \mathbb{G}_1, \pi_B \in \mathbb{G}_2, \pi_C \in \mathbb{G}_1)$.

---

## 4. Operational Requirements

### 4.1 Client / Browser Environment
- Modern browser supporting WebAssembly (`wasm`) and `BigInt`.
- ZK artifacts (Wasm circuit and zkey) are loaded on-demand via CDN or bundled static assets.
- Proof generation takes approximately 1.5–3.5 seconds on desktop/mobile hardware.

### 4.2 Backend Verification Environment
- Server executes `verifyProof(semaphoreProof)` inside `@semaphore-protocol/core`.
- The verification verifies the Groth16 bilinear pairing equations without executing proof generation circuits, completing in under 10 milliseconds.
- Backend validates:
  1. `verifyProof(proof) === true`
  2. `merkleTreeRoot` is recognized as an active or recently valid institutional group root.
  3. `scope` matches the target submission category.
  4. `message` matches the canonical hash of the report body.
  5. `nullifier` has not been previously recorded in the database under this scope.

---

## 5. Limitations & Threat Boundaries

1. **Trusted Setup**: Groth16 relies on a structured reference string (SRS) generated during the Semaphore trusted setup ceremony.
2. **Group Size Anonymity Set**: Anonymity is bounded by the size of the active membership tree ($N$). For very small groups ($N < 5$), metadata and timing analysis can degrade anonymity.
3. **Endpoint Security**: A compromised client device running spyware or keyloggers can steal the `identitySecret` prior to zero-knowledge proof generation.
4. **Traffic Analysis**: While the payload and cryptographic identity are decoupled, network metadata (IP addresses, timing correlations) must be mitigated via reverse proxies or Tor.
