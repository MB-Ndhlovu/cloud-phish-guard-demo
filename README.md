# Cloud-Phish Guard — Security Architecture Demo

Adaptive AI-driven authentication middleware that detects and neutralises phishing attacks before any cloud data is exposed.

## Architecture (from [Cloud-Phish Guard Data Protection Architecture](./docs/Cloud-Phish_Guard_DataProtection_Architecture.pdf))

1. **Path Analysis** — MITM / eavesdropping detection
2. **Lure Detection** — AI-driven NLP phishing signal identification
3. **Adaptive Gate** — Risk-based enforcement engine
4. **Authenticator** — Custom MFA / step-up verification
5. **Neutralisation** — Auto-freeze & isolate on high risk

## Run Locally

```bash
bun install
bun run dev
```

## License

Private demo project.
