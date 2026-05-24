# Cloud-Phish Guard

Adaptive AI-driven authentication middleware that detects and neutralises phishing attacks before any cloud data is exposed. Built for the SA Cybersecurity Hackathon.

---

## Overview

Cloud-Phish Guard is a security architecture demo that demonstrates a five-layer phishing defence system. It accepts a URL, classifies it across multiple threat vectors in real time, and renders the threat assessment through a minimal Apple-inspired liquid interface.

---

## Architecture

Five independent protection layers form the defence pipeline:

| Layer | Function |
|---|---|
| **Path Analysis** | MITM / traffic inspection — detects proxy, transparent proxy, direct IP access, unencrypted HTTP |
| **Lure Detection** | AI NLP signal classification — urgency manipulation, typosquat domains, fake security prompts |
| **Adaptive Gate** | Risk-based enforcement engine — session manipulation, redirect injection detection |
| **Authenticator** | Step-up MFA on medium-risk; blocks high-risk outright |
| **Neutralisation** | Auto-freeze and isolate on high-confidence threat detection |

---

## Threat Scoring

```
Score = 30 (baseline)
  + Per signal weight (PATH/LURE/GATE)
  − 25 if domain is in trusted list

Low    ≤ 39  → ACCESS GRANTED
Medium 40–69 → STEP-UP MFA
High   ≥ 70  → BLOCKED & FROZEN
```

---

## Interface Design

The interface follows a minimal Apple-inspired aesthetic:
- Dark gradient background (`#0a0a0f → #111118`)
- Liquid threat meter with animated wave surface
- Glassmorphism cards with `backdrop-filter: blur`
- Animated floating indicator dots
- Fade-up entrance animations
- SF Pro Display / system font stack

---

## Running Locally

```bash
bun install
bun run dev
```

Open `http://localhost:5173` in your browser.

---

## Tech Stack

| Component | Technology |
|---|---|
| Framework | React 18 + TypeScript |
| Bundler | Vite |
| Styling | Tailwind-free (inline CSS + system fonts) |
| Language | TypeScript (strict) |
| Package Manager | Bun |

---

## Contributing

All contributions must be submitted as pull requests. The base branch is `master`. Please ensure your PR includes a description of what you changed and why.

---

## Security Note

This is a demonstration project for a hackathon. The threat classification logic is rule-based and intended for illustrative purposes only — it does not constitute a production security product.

---

## License

Private — Cloud-Phish Guard © 2025. All rights reserved.