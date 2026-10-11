# QuantumGuard: Post-Quantum Discovery, CBOM & Migration Platform

> **An enterprise platform to discover where quantum-vulnerable cryptography is in use across an organization, evaluate "Harvest Now, Decrypt Later" (HNDL) exposure using Mosca's Theorem, and generate actionable NIST PQC migration roadmaps.**

---

## 1. Problem Statement: "Harvest Now, Decrypt Later" (HNDL)
Encrypted data intercepted and archived by adversaries today can be decrypted in the future once a **Cryptographically Relevant Quantum Computer (CRQC)** emerges. Current public-key cryptography relies on mathematical problems breakable in polynomial time by **Shor's Algorithm**:
* **RSA**: Integer factorization ($O((\log N)^3)$)
* **ECDSA / ECDH**: Discrete logarithm problem over elliptic curve groups
* **Diffie-Hellman / DSA**: Finite-field discrete logarithm

Furthermore, **Grover's Algorithm** accelerates brute-force search quadratically, halving symmetric cipher effective key lengths (e.g., AES-128 drops to 64-bit security). High-longevity confidential data (health records, financial systems, government communications) deserves early planning because migration can take years. The risk is conditional on attacker capability, data value, system design and the chosen planning horizon.

---

## 2. Core Novelty & Real Algorithms

### A. Mathematical Risk Engine: Mosca's Theorem ($X + Y > Z$)
QuantumGuard evaluates risk using Dr. Michele Mosca's inequality:
$$\Delta = (X + Y) - Z$$
* **$X$ (Confidentiality Shelf-Life)**: Years the data must remain confidential (e.g., 30 yrs for HIPAA/genomics, 15 yrs for banking, 5 yrs for session data).
* **$Y$ (Migration Time)**: Years required to migrate systems to post-quantum cryptography.
* **$Z$ (Quantum Horizon)**: Time until CRQC arrival ($2033 - 2026 = 7.0$ years).

If $\mathbf{X + Y > Z}$ ($\Delta > 0$), the model flags a **planning gap**: migration may take longer than the remaining assumed horizon while the data is still sensitive. This does not predict that a future decryption event will occur.

### B. Explainable Multi-Factor Quantum Risk Score ($Q_{\text{score}} \in [0,100]$)

$$Q_{\text{score}} = 0.35C + 0.20E + 0.20S + 0.10L + 0.15M$$

Each factor is normalized to 0–100: **C** cryptographic weakness (35%), **E** exposure (20%), **S** data sensitivity (20%), **L** confidentiality lifetime (10%), and **M** Mosca planning-gap urgency (15%). Recognized PQC / hybrid primitives receive a zero quantum-vulnerability score; implementation correctness and inventory completeness still need validation.

- Exposure mappings are documented: public internet 100, internal network 65, at-rest storage 55, local development 20.
- Sensitivity is inferred heuristically from asset name, path and purpose; it is labelled as an assumption and must be confirmed by the data owner.
- Confidentiality lifetime uses $X/30$ years capped at 100; Mosca urgency reflects the sign and size of $\Delta = X+Y-Z$.
- The finding inspector shows each factor score, weight, weighted contribution and source. Q-Score is a prioritization index, **not** a probability of attack, breach or quantum-computer arrival.

### C. Tri-Vector Native Discovery Engine (No Mocks)
1. **Live Network / TLS Scanner**: Executes real socket-level handshakes with servers (e.g., `google.com:443`, internal gateways) to extract negotiated cipher suites, curves, and X.509 certificates.
2. **X.509 Certificate & ASN.1 Parser**: Uses Python's native `cryptography` library to parse `.pem`, `.crt`, `.der`, `.key`, and SSH keys.
3. **Multi-Language AST Source Code Scanner**: Scans Python AST trees and regex patterns across JavaScript/TypeScript, Go, Java, and C/C++.
4. **DevOps & Web Server Config Parser**: Scans Nginx, Apache, OpenSSL, and Dockerfile crypto configurations.

### D. NIST FIPS 203/204/205 Alignment & Diff Studio
Maps legacy primitives to finalized NIST post-quantum standards:
* **ML-KEM-768 / ML-KEM-1024** (FIPS 203) for Key Encapsulation (replacing RSA/ECDH)
* **ML-DSA-65 / ML-DSA-87** (FIPS 204) for Digital Signatures (replacing RSA-PSS/ECDSA)
* **SLH-DSA** (FIPS 205) for Stateless Hash-based Signatures
* **Hybrid Key Exchanges**: `X25519 + ML-KEM-768` (draft-ietf-tls-hybrid-design) for backward compatibility

### E. Standard CycloneDX 1.6 CBOM Export
Exports full Cryptographic Bill of Materials in official CycloneDX 1.6 JSON format for enterprise security pipeline integration.

---

## 3. Persistent SQLite Database Architecture
All audits, assets, risk scores, and migration plans are stored locally in `data/quantumguard.db`:
* `scans`: Historical audit sessions and metrics.
* `assets`: Discovered cryptographic assets and metadata.
* `vulnerabilities`: Computed Mosca gaps, Shor/Grover flags, and Q-Scores.
* `migration_recommendations`: Actionable code diffs and configuration recipes.
* `scan_logs`: Timestamped discovery event logs.
* `settings`: Configurable Mosca parameters ($Z, Y, X$).

---

## 4. Quickstart & Running the Application

### 1. Install Dependencies
Use Python 3.10 or newer. On Windows, double-click `RUN_WINDOWS.bat`; it creates a local virtual environment, installs the dependencies and starts the app. The first run needs an internet connection for package installation.

Manual install:
```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

Open your browser at: **`http://127.0.0.1:8000`**. Keep the terminal open while using the app. The SQLite database is created automatically on first start.

### 3. Run Your First Scan
1. Click **"Launch New Scan"**.
2. Click **"Use Sample Targets"** to immediately scan the built-in testbed containing real RSA, ECC, and AES assets.
3. Or enter a live TLS host (e.g. `google.com:443` or `cloudflare.com:443`) to run real network handshakes.
4. Watch the live discovery stream in the terminal.
5. Explore the interactive **Mosca Risk Matrix**, inspect CBOM assets, view side-by-side migration diffs, and download the CycloneDX 1.6 CBOM.

---

## 5. Added Competition Demo Layer (v2.5)

The original scanner, audit history, risk charts, Mosca settings, migration diff studio, findings table, and CycloneDX CBOM export remain available. The following modules are additive:

- **Executive / technical language toggle:** translates scan output into leadership-friendly context without changing the underlying findings.
- **Industry impact profiles:** hospital, bank, college, IoT/industrial, and general enterprise examples. These explain possible business impact; they are not proof of a breach or automatically inferred facts about the scanned target.
- **Drag-and-drop evidence intake:** upload a small set of supported source/config/public-certificate files into the local app, then scan the temporary folder. Maximum 10 files per batch, 2 MB per file, 8 MB aggregate. Unsupported extensions and obvious PEM private-key content are rejected. Never upload production secrets, credentials, or private keys.
- **Authorized TLS quick checks:** the dashboard shortcuts queue a real TLS scan through the existing socket scanner. Only use endpoints you own or have explicit permission to assess.
- **Quantum horizon scenario slider:** varies the assumed horizon and recalculates the Mosca-style planning gap. This is a transparent *what-if scenario*, not a forecast of when a cryptographically relevant quantum computer will arrive. Industry profiles use illustrative confidentiality lifetimes; validate them with data owners and retention policy.
- **Executive briefing print/PDF:** creates a report from the selected scan's current findings and metrics. In the browser print dialog choose **Save as PDF**. The report includes scope, observed findings, business context, scenario assumptions and interpretation limits.

### Recommended live demo (3–5 minutes)

1. Start the app and choose **Use Sample Targets** to show a reproducible local scan.
2. Open a finding and explain the detected algorithm, evidence location, risk tier and suggested migration path.
3. Switch the business profile from Hospital to Bank or IoT; explain that the evidence stays the same while the *example impact lens* changes.
4. Move the horizon slider and show how the conditional X + Y > Z planning result changes. State clearly that the year is an assumption.
5. Export the existing CycloneDX CBOM, then create the executive briefing and save it as PDF.
6. If internet access and permission are available, demonstrate a quick TLS check against an approved endpoint.

### Interpretation and safety notes

QuantumGuard is a discovery and planning aid, not a compliance certification, proof of compromise, or a substitute for expert review. Scanner matches can require manual validation. A risk score is a model output; it is not a probability of attack. The built-in sample targets are test fixtures, not a live enterprise inventory. Local uploads are retained under `data/uploaded_targets/` until you delete them; remove test uploads after the demo. Avoid exposing this development server to a public network.


## 6. Explainable multi-factor prioritization (v2.6 competition upgrade)

Every finding carries a 0–100 Q-Score calculated from five weighted factors: cryptographic weakness (35%), exposure (20%), data sensitivity (20%), confidentiality lifetime (10%), and Mosca planning-gap urgency (15%). The finding inspector shows each factor's score, weight, weighted contribution, and evidence/assumption source, plus a recommended next action. Data sensitivity and confidentiality lifetime are heuristic/configured assumptions until an asset owner validates them. The startup migration backfills existing database findings to the new model without deleting scan history. The score is not a probability of compromise.
