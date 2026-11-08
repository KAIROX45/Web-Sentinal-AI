# WebSentinel AI: Enterprise AI-Powered Web Threat Detection & Cybersecurity Intelligence Platform

> **Tagline:** Detect. Investigate. Understand. Verify.  
> **Classification:** TLP:AMBER Cyber Threat Intelligence  
> **Version:** 1.0.0 Production Architecture

---

## 1. Overview & Core Mission

**WebSentinel AI** is an enterprise-grade cyber threat intelligence and investigation platform engineered for security analysts, incident responders, and end-users. It delivers unified analysis across deceptive website URLs, smishing SMS campaigns, credential harvesting emails, rogue IP addresses, and misconfigured TLS infrastructure.

Every investigation generates a deterministic **canonical SHA-256 fingerprint** anchored to an **EVM-compatible smart contract** on the Ethereum Sepolia testnet (with seamless local cryptographic ledger fallback) for immutable verification and tamper-detection.

---

## 2. Strict Design System & Palette Compliance

WebSentinel AI strictly follows the defined visual design identity across all components, charts, and surfaces:

| Color Token | Hex Code | Visual Application & Purpose |
| :--- | :--- | :--- |
| **EVENING** | `#192034` | **Main Application Background** — deep midnight slate providing optimal contrast and low eye strain for SOC analysts |
| **STORMY** | `#494E6B` | **Sidebar & Secondary Panels** — steel slate used for borders, structural panels, dividers, and unselected states |
| **CLOUD** | `#98878F` | **Muted Text & Secondary UI** — warm cloud grey for metadata, timestamps, helper descriptions, and secondary metrics |
| **SUNSET** | `#985E6D` | **Primary Brand & Action Highlights** — crimson rose mauve for primary buttons, active navigation, critical alerts, and glowing accents |

*Derived lighter and darker shades (`#202740` card surfaces, `#85c9b7` low-risk sage, `#b5834f` suspicious ochre, `#e58a9d` critical threat) harmonize with the palette to ensure WCAG AAA accessibility.*

---

## 3. Platform Modules & Capabilities

### A. Unified Threat Search & Real-Time Input Classifier
- **Multi-Vector Input:** Accepts website URLs, IPv4/IPv6 addresses, raw email headers, SMS messages, and chat snippets in a single bar.
- **Intelligent Classification:** Automatically detects input type with debounced heuristic analysis and routes directly to the designated investigation engine.
- **One-Click Demo Presets:** Pre-loaded with 3 benign and 3 malicious test cases for evaluation.

### B. Security Intelligence Dashboard
- **Telemetry Cards:** Total URLs scanned, Confirmed Malicious count, Suspicious messages detected, Threats blocked, and overall Defense Score (Grade A+).
- **Interactive Visualizations:**
  - Detection trends over time via Recharts Area Chart.
  - Threat Severity Distribution via Recharts Donut Chart.
  - Threat Category Prevalence via Recharts Bar Chart.
  - Real-time audit timeline of recent investigations.

### C. URL Security Investigation Engine
- **Normalization:** Trims schemes, canonicalizes authorities, and strips tracking fragments.
- **Domain Decomposition:** Leverages `tldextract` with built-in Public Suffix List snapshots for sub-millisecond offline extraction.
- **Typosquatting Detection:** Damerau-Levenshtein distance calculation, omission/insertion checks, and visual substitution against protected global brands (Google, PayPal, Apple, Microsoft, Chase, Netflix, etc.).
- **Homograph (IDN) Attack Detection:** Identifies Punycode (`xn--...`) and mixed-script Cyrillic/Greek glyph substitutions masquerading as Latin characters.
- **Pattern Heuristics:** Shannon entropy calculation for DGA identification, direct IP hosts, suspicious TLD risk tiers (`.xyz`, `.top`, `.buzz`, `.icu`, `.tk`), and embedded credential signs (`@`).
- **DNS Telemetry:** Sub-second queries for A, AAAA, MX, NS, and TXT records.
- **Redirect Chain Tracer:** Traces up to 5 hops with strict per-hop SSRF validation.

### D. TLS / SSL Certificate Inspector
- **Direct Handshake:** Direct socket connection to target host and port 443 with binary DER certificate extraction.
- **Trust Hierarchy Tree:** Visualizes Root CA &rarr; Intermediate CA &rarr; Leaf Server Certificate.
- **Cryptographic Audit:** Cipher suite negotiation, TLSv1.3/1.2 validation, public key bit length, and signature hash algorithm.
- **Hostname RFC 6125 Match:** Validates Common Name and Subject Alternative Names (SANs) including wildcards.
- **Expiration Countdown:** Real-time remaining validity calculation and warning flags for expired or expiring certificates.
- **Revocation Transparency:** Accurately reports OCSP AIA extension presence and CRL requirements without unverified claims.

### E. HTTP Security Header Matrix
- **Compliance Evaluator:** Inspects `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- **Structured Assessment:** Matrix with detection status (Optimal, Weak, Missing), actual value, security importance, and recommended configuration.
- **SOC Analyst Integrity Rule:** Explicitly emphasizes that missing headers weaken defense-in-depth but do not alone prove malicious intent.

### F. AI Phishing & Scam Analyzer
- **Dual-Engine Architecture:**
  - **Engine A (Gemini 2.5 AI):** High-level multi-modal behavioral reasoning using Google Gemini API with structured JSON output schema.
  - **Engine B (Cybersecurity Heuristic Core):** Deterministic local engine detecting urgent pressure tactics, alarmist alerts, fake invoice fees, and brand impersonation when Gemini API key is unconfigured.
- **Granular Signals:** Psychological manipulation techniques, extracted deceptive URLs, impersonated entities, technical evidence, and actionable defense steps.
- **Epistemological Integrity:** Distinguishes probabilistic AI predictions from independently verified threat database entries.

### G. IP Address Intelligence & Boundary Guard
- **Strict SSRF Enforcement:** Automatically classifies IP as Public, RFC 1918 Private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), Loopback (`127.0.0.0/8`, `::1`), Link-Local (`169.254.0.0/16`, `fe80::/10`), or Reserved (`240.0.0.0/4`).
- **Privacy Assurance:** Blocks outbound scanning against internal infrastructure, returning educational defense guidance.
- **Public IP Telemetry:** ASN allocation, Autonomous System Organization, reverse DNS PTR lookup, and city/country geolocation mapping.

### H. Central Threat Intelligence Center (IOC Registry)
- **Curated Threats:** Pre-seeded with verified high-confidence indicators of compromise (phishing kits, malware C2 nodes, bulletproof hosting, wallet drainers).
- **Search & Filtering:** Real-time filtering by indicator type (domain, ip, url, hash), severity, and threat category.
- **Analyst Submissions:** In-app modal for security analysts to register new IOCs with persistent database storage.

### I. Blockchain Threat Verification (Solidity + Web3)
- **Smart Contract:** `contracts/ThreatVerification.sol` written in Solidity v0.8.20 for EVM compatibility (Sepolia testnet MVP).
- **Zero-Knowledge Privacy:** Never records raw emails, user content, or personal identifiers on-chain; anchors strictly canonical SHA-256 fingerprints.
- **Tamper Detection:** In-app verification interface re-calculates SHA-256 digests over submitted investigation JSON and flags any payload tampering.

### J. Investigation History & PDF/JSON Export
- **Audit Persistence:** Stores investigation records in persistent SQLite/PostgreSQL storage.
- **Machine-Readable Export:** One-click JSON export containing full evidence matrices.
- **Print-Ready Threat Briefings:** Server-side PDF generation using Python ReportLab with TLP classification headers, threat score badges, and blockchain stamps.

---

## 4. Controlled Demo Test Cases

| Scenario | Target / Input | Category | Expected Platform Result |
| :--- | :--- | :--- | :--- |
| **Benign Test 1** | `https://example.com` | Safe Website | **LOW RISK (Score: 5/100, Grade A+)** — Clean DNS, valid certificate, no typosquatting |
| **Benign Test 2** | `8.8.8.8` | Public DNS IP | **LOW RISK (Score: 5/100)** — AS15169 Google LLC, clean abuse history |
| **Benign Test 3** | `Team, our sprint retro is Friday 14:00 UTC.` | Benign Message | **LOW RISK (Confidence: 88%)** — Benign communication, zero manipulative coercion |
| **Malicious Test 1** | `http://paypa1-security-verification.com/login` | Typosquatting / Phishing | **CONFIRMED MALICIOUS (Score: 98/100)** — Brand imitation of PayPal, verified IOC match |
| **Malicious Test 2** | `45.154.255.89` | Malware C2 IP | **CONFIRMED MALICIOUS (Score: 98/100)** — RedLine Infostealer C2 node, offshore bulletproof host |
| **Malicious Test 3** | `URGENT: Your PayPal account has been suspended within 24 hours. Click here to verify password: http://paypa1-security-login.xyz` | Phishing SMS / Smishing | **HIGH RISK (Confidence: 92%)** — Artificial urgency, credential harvesting lure, disguised link |

---

## 5. Technology Stack

### Backend
- **Language & Framework:** Python 3.10+, FastAPI, Uvicorn
- **Data Validation & ORM:** Pydantic v2, SQLAlchemy, SQLite / PostgreSQL
- **Security & Inspection:** Cryptography, Python SSL, dnspython, tldextract, httpx
- **PDF Generation:** ReportLab 5.0
- **Blockchain Integration:** Web3.py, Solidity v0.8.20

### Frontend
- **Framework & Tooling:** React 19, TypeScript, Vite, Tailwind CSS v4 (`@tailwindcss/vite`)
- **Icons & Visuals:** Lucide React
- **Data Visualization:** Recharts
- **Routing & Networking:** React Router v7, Axios

---

## 6. Quick Start & Execution Guide

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### One-Click Launch (Both Backend and Frontend)
From the project root on Windows:
```bash
start_websentinel.bat
```
Or using the Python orchestrator:
```bash
python start_sentinelx.py
```

### Manual Individual Startup

#### 1. Backend (FastAPI on Port 8000)
```bash
cd backend
python run_backend.py
```
*API will be available at `http://127.0.0.1:8000` with interactive Swagger docs at `http://127.0.0.1:8000/docs`.*

#### 2. Frontend (Vite on Port 5173)
```bash
cd frontend
npm run dev
```
*Web application will be available at `http://localhost:5173`.*

---

## 7. Environment Variables & API Keys (Optional)

Create a `.env` file in `backend/` or configure directly in the UI under **Platform Settings**:
```env
# Optional: Deep LLM Reasoning (Heuristic fallback active if omitted)
GEMINI_API_KEY=your_gemini_api_key

# Optional: Threat Feeds
GOOGLE_SAFE_BROWSING_API_KEY=your_safe_browsing_key
VIRUSTOTAL_API_KEY=your_virustotal_key

# Optional: Ethereum Sepolia Blockchain
ETHEREUM_RPC_URL=https://sepolia.infura.io/v3/YOUR_KEY
CONTRACT_ADDRESS=0x5e4b9F91e2b6D8C2B30f81d113f8295b774E9419
```

---

## 8. Anti-SSRF Defense Specification

All outbound network probes strictly enforce the following security boundaries:
1. **Scheme Whitelist:** Only `http` and `https` allowed; `file://`, `gopher://`, `ftp://` rejected.
2. **DNS Pre-Validation:** Hostnames resolve to IP addresses before any socket connection is initiated.
3. **Blacklisted CIDR Ranges:**
   - Loopback: `127.0.0.0/8`, `::1`
   - Private: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`
   - Link-Local: `169.254.0.0/16`, `fe80::/10` (Cloud instance metadata endpoints)
   - Reserved & Multicast: `0.0.0.0/8`, `224.0.0.0/4`, `240.0.0.0/4`
4. **Per-Hop Re-Validation:** Every redirect step in the chain re-resolves and validates the destination IP before following.
5. **Memory DOS Protection:** HTTP response streaming capped at 1,048,576 bytes (1 MB) with 6.0s timeout.

