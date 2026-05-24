import { useState, useEffect, useRef } from "react";

type RiskLevel = "low" | "medium" | "high";

interface ThreatSignal {
  label: string;
  category: "PATH" | "LURE" | "GATE" | "AUTH" | "NEUTRAL";
}

interface RequestLog {
  id: number;
  timestamp: string;
  url: string;
  risk: RiskLevel;
  score: number;
}

const PATH_SIGNALS = [
  { pattern: /mitm|man.?in.?the.?middle/i, label: "MITM Intercept", weight: 30 },
  { pattern: /proxy|transparent|i[sp]\.[0-9]+\.[0-9]+\.[0-9]/i, label: "Proxy Traffic", weight: 20 },
  { pattern: /http:\/\//i, label: "Unencrypted", weight: 25 },
  { pattern: /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/i, label: "Direct IP", weight: 15 },
];

const LURE_SIGNALS = [
  { pattern: /urgent|asap|immediately|now/i, label: "Urgency Manipulation", weight: 20 },
  { pattern: /verify|confirm|update.*account/i, label: "Auth Impersonation", weight: 25 },
  { pattern: /suspended|locked|compromised/i, label: "Fear Tactic", weight: 20 },
  { pattern: /login.*urgent|security.*alert/i, label: "Fake Security Prompt", weight: 30 },
  { pattern: /click.*here.*now|act.*now/i, label: "Directive Deception", weight: 25 },
  { pattern: /paypa1\.|bank-of-|amazon-verify\./i, label: "Typosquat Domain", weight: 35 },
  { pattern: /free.*gift|winner|congratulations/i, label: "Social Engineering", weight: 20 },
];

const GATE_SIGNALS = [
  { pattern: /token=|session=|auth=/i, label: "Session Manipulation", weight: 15 },
  { pattern: /redirect=|return=|callback=/i, label: "Redirect Injection", weight: 20 },
];

const TRUSTED_DOMAINS = ["github.com", "google.com", "microsoft.com", "dropbox.com", "linkedin.com", "apple.com", "amazon.com", "cloudflare.com"];

function classifyUrl(raw: string): { risk: RiskLevel; score: number; signals: ThreatSignal[] } {
  let score = 30;
  const signals: ThreatSignal[] = [];
  const url = raw.toLowerCase();
  if (TRUSTED_DOMAINS.some(d => url.includes(d))) {
    score = Math.max(0, score - 25);
    signals.push({ label: "Trusted Domain", category: "PATH" });
  }
  for (const s of PATH_SIGNALS) { if (s.pattern.test(url)) { score += s.weight; signals.push({ label: s.label, category: "PATH" }); } }
  for (const s of LURE_SIGNALS) { if (s.pattern.test(url)) { score += s.weight; signals.push({ label: s.label, category: "LURE" }); } }
  for (const s of GATE_SIGNALS) { if (s.pattern.test(url)) { score += s.weight; signals.push({ label: s.label, category: "GATE" }); } }
  score = Math.max(0, Math.min(100, score));
  const risk: RiskLevel = score >= 70 ? "high" : score >= 40 ? "medium" : "low";
  return { risk, score, signals };
}

const DEMO_URLS = [
  "https://secure-paypal.com/urgent-verify-account",
  "https://github.com/user/settings",
  "https://amazon.com/update-payment-urgent",
  "https://google.com/authcallback",
  "https://bank-of-america.com/verify-identity-now",
  "https://dropbox.com/login",
  "https://urgent-facebook.com/security-alert-click",
  "https://microsoft.com/account-recovery",
  "https://paypa1.com/secure-confirm",
  "https://linkedin.com/auth",
];

function LiquidMeter({ score, risk, phase }: { score: number; risk: RiskLevel; phase: number }) {
  const colors: Record<RiskLevel, string> = {
    low: "#22c55e",
    medium: "#f59e0b",
    high: "#ef4444",
  };

  return (
    <div className="relative w-full" style={{ height: "180px" }}>
      <div
        className="absolute inset-0 rounded-[28px] overflow-hidden backdrop-blur-xl border"
        style={{
          background: "rgba(255,255,255,0.08)",
          borderColor: "rgba(255,255,255,0.15)",
        }}
      >
        {/* Liquid fill */}
        <div
          className="absolute bottom-0 left-0 right-0 transition-all duration-1000 ease-out"
          style={{
            height: phase === 0 ? "0%" : `${score}%`,
            background: `linear-gradient(to top, ${colors[risk]}40, ${colors[risk]}15)`,
          }}
        >
          {/* Liquid surface wave */}
          <div
            className="absolute -top-3 left-0 right-0 h-6 opacity-60"
            style={{
              background: `radial-gradient(ellipse at center, ${colors[risk]}60 0%, transparent 70%)`,
              animation: phase > 0 ? "wave 2s ease-in-out infinite" : "none",
            }}
          />
        </div>

        {/* Score */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className="text-6xl font-semibold tracking-tight transition-all duration-700"
            style={{ color: colors[risk], fontFamily: "'SF Pro Display', -apple-system, sans-serif" }}
          >
            {phase === 0 ? "—" : score}
          </span>
          <span className="text-xs font-medium mt-2 tracking-widest uppercase" style={{ color: colors[risk], opacity: 0.7 }}>
            {phase === 0 ? "Ready" : phase < 6 ? "Scanning" : risk === "high" ? "Threat" : risk === "medium" ? "Caution" : "Safe"}
          </span>
        </div>
      </div>

      {/* Floating dots */}
      {[...Array(3)].map((_, i) => (
        <div
          key={i}
          className="absolute w-1.5 h-1.5 rounded-full"
          style={{
            background: colors[risk],
            opacity: 0.3,
            left: `${30 + i * 20}%`,
            bottom: phase > 0 ? `${Math.min(score - 10 + i * 5, 90)}%` : "5%",
            transition: `bottom 1.2s ${0.3 + i * 0.2}s cubic-bezier(0.34, 1.56, 0.64, 1)`,
            filter: `blur(1px)`,
          }}
        />
      ))}
    </div>
  );
}

function SignalPill({ label, color }: { label: string; color: string }) {
  return (
    <div
      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium"
      style={{
        background: `${color}18`,
        color: color,
        border: `1px solid ${color}30`,
        backdropFilter: "blur(8px)",
      }}
    >
      <div className="w-1.5 h-1.5 rounded-full" style={{ background: color }} />
      {label}
    </div>
  );
}

function RequestCard({ log, active }: { log: RequestLog; active: boolean }) {
  const colors: Record<RiskLevel, string> = { low: "#22c55e", medium: "#f59e0b", high: "#ef4444" };
  return (
    <div
      className="px-4 py-3 rounded-2xl border transition-all duration-500"
      style={{
        background: active ? `${colors[log.risk]}12` : "rgba(255,255,255,0.04)",
        borderColor: active ? `${colors[log.risk]}40` : "rgba(255,255,255,0.06)",
        transform: active ? "scale(1.02)" : "scale(1)",
      }}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full" style={{ background: colors[log.risk], boxShadow: `0 0 6px ${colors[log.risk]}80` }} />
          <span className="text-xs font-medium text-white/80">{log.timestamp}</span>
        </div>
        <span className="text-xs font-semibold" style={{ color: colors[log.risk] }}>{log.score}</span>
      </div>
      <div className="mt-2 text-xs text-white/40 font-mono truncate">{log.url}</div>
    </div>
  );
}

function StatBlock({ value, label, delay }: { value: string; label: string; delay: number }) {
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setVisible(true), delay);
    return () => clearTimeout(t);
  }, [delay]);
  return (
    <div className="text-center">
      <div
        className="text-3xl font-semibold tracking-tight transition-all duration-700"
        style={{
          color: "white",
          opacity: visible ? 1 : 0,
          transform: visible ? "translateY(0)" : "translateY(8px)",
        }}
      >
        {value}
      </div>
      <div className="text-[10px] tracking-widest uppercase mt-1" style={{ color: "rgba(255,255,255,0.35)" }}>{label}</div>
    </div>
  );
}

export default function CloudPhishGuardDemo() {
  const [inputUrl, setInputUrl] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [phase, setPhase] = useState(0);
  const [currentResult, setCurrentResult] = useState<{ risk: RiskLevel; score: number; signals: ThreatSignal[] } | null>(null);
  const [logs, setLogs] = useState<RequestLog[]>([]);
  const [isDemoRunning, setIsDemoRunning] = useState(false);
  const [activeLogId, setActiveLogId] = useState<number | null>(null);
  const demoRef = useRef(0);

  const runAnalysis = (url: string) => {
    setIsAnalyzing(true);
    setCurrentResult(null);
    setPhase(0);
    let p = 0;
    const interval = setInterval(() => {
      p++;
      setPhase(p);
      if (p >= 5) {
        clearInterval(interval);
        const result = classifyUrl(url);
        setCurrentResult(result);
        setIsAnalyzing(false);
        const entry: RequestLog = { id: Date.now(), timestamp: new Date().toLocaleTimeString("en-US", { hour12: false }), url, risk: result.risk, score: result.score };
        setLogs(prev => [entry, ...prev].slice(0, 8));
        setActiveLogId(entry.id);
        setTimeout(() => setActiveLogId(null), 3000);
        setPhase(6);
      }
    }, 350);
  };

  const runDemo = () => {
    if (isDemoRunning) return;
    setIsDemoRunning(true);
    let idx = 0;
    const next = () => {
      if (idx >= DEMO_URLS.length) { setIsDemoRunning(false); return; }
      runAnalysis(DEMO_URLS[idx++]);
      setTimeout(next, 2200);
    };
    next();
  };

  const riskColors: Record<RiskLevel, string> = { low: "#22c55e", medium: "#f59e0b", high: "#ef4444" };

  return (
    <div className="min-h-screen" style={{ background: "linear-gradient(160deg, #0a0a0f 0%, #111118 50%, #0d0d14 100%)", fontFamily: "'SF Pro Display', -apple-system, BlinkMacSystemFont, sans-serif" }}>
      <style>{`
        @keyframes wave {
          0%, 100% { transform: scaleX(1) translateY(0); }
          50% { transform: scaleX(1.05) translateY(-2px); }
        }
        @keyframes fadeUp {
          from { opacity: 0; transform: translateY(16px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes pulse {
          0%, 100% { opacity: 0.4; }
          50% { opacity: 1; }
        }
        .fade-up { animation: fadeUp 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards; }
      `}</style>

      {/* Header */}
      <header className="px-8 pt-10 pb-6">
        <div className="max-w-5xl mx-auto flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight text-white">Cloud-Phish Guard</h1>
            <p className="text-xs mt-1 tracking-widest uppercase" style={{ color: "rgba(255,255,255,0.35)" }}>Adaptive Threat Neutralisation</p>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full" style={{ background: "#22c55e", boxShadow: "0 0 8px #22c55e80", animation: "pulse 2s infinite" }} />
            <span className="text-xs" style={{ color: "rgba(255,255,255,0.4)" }}>System Active</span>
          </div>
        </div>
      </header>

      {/* Main Grid */}
      <main className="px-8 pb-10">
        <div className="max-w-5xl mx-auto" style={{ display: "grid", gridTemplateColumns: "1fr 340px", gap: "20px" }}>

          {/* Left Column */}
          <div className="space-y-5">
            {/* Liquid Meter */}
            <div className="fade-up" style={{ animationDelay: "0ms" }}>
              <LiquidMeter score={currentResult?.score ?? 0} risk={currentResult?.risk ?? "low"} phase={phase} />
            </div>

            {/* Input */}
            <div className="fade-up" style={{ animationDelay: "80ms" }}>
              <div
                className="flex items-center rounded-2xl overflow-hidden"
                style={{
                  background: "rgba(255,255,255,0.05)",
                  border: "1px solid rgba(255,255,255,0.08)",
                  backdropFilter: "blur(20px)",
                }}
              >
                <div className="px-4 text-white/30 text-sm font-mono">&gt;</div>
                <input
                  type="text"
                  value={inputUrl}
                  onChange={e => setInputUrl(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && !isAnalyzing && runAnalysis(inputUrl.trim())}
                  placeholder="Enter URL to analyse"
                  className="flex-1 bg-transparent px-2 py-4 text-sm text-white placeholder-white/20 focus:outline-none"
                />
                <button
                  onClick={() => !isAnalyzing && inputUrl.trim() && runAnalysis(inputUrl.trim())}
                  disabled={isAnalyzing || !inputUrl.trim()}
                  className="m-1.5 px-5 py-2.5 rounded-xl text-xs font-semibold transition-all duration-300 disabled:opacity-30"
                  style={{
                    background: isAnalyzing ? "rgba(255,255,255,0.08)" : "white",
                    color: isAnalyzing ? "rgba(255,255,255,0.5)" : "#0a0a0f",
                  }}
                >
                  {isAnalyzing ? "Scanning..." : "Analyse"}
                </button>
              </div>
            </div>

            {/* Signals */}
            {currentResult && phase > 5 && (
              <div className="fade-up">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs tracking-widest uppercase" style={{ color: "rgba(255,255,255,0.3)" }}>Threat Signals</span>
                  <span className="text-xs font-semibold" style={{ color: riskColors[currentResult.risk] }}>
                    {currentResult.signals.length > 0 ? `${currentResult.signals.length} detected` : "No signals"}
                  </span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {currentResult.signals.length === 0
                    ? <SignalPill label="Domain Trusted" color="#22c55e" />
                    : currentResult.signals.map(s => <SignalPill key={s.label} label={s.label} color={riskColors[currentResult.risk]} />)
                  }
                </div>
              </div>
            )}

            {/* Demo button */}
            <div className="fade-up" style={{ animationDelay: "160ms" }}>
              <button
                onClick={runDemo}
                disabled={isDemoRunning}
                className="text-xs px-4 py-2 rounded-xl transition-all duration-300 disabled:opacity-40"
                style={{ background: "rgba(255,255,255,0.06)", color: "rgba(255,255,255,0.5)", border: "1px solid rgba(255,255,255,0.08)" }}
              >
                {isDemoRunning ? "Demo Running..." : "Run Live Demo"}
              </button>
            </div>
          </div>

          {/* Right Column */}
          <div className="space-y-4">
            {/* Status Card */}
            <div
              className="rounded-2xl p-5 border fade-up"
              style={{
                background: "rgba(255,255,255,0.04)",
                borderColor: "rgba(255,255,255,0.07)",
                backdropFilter: "blur(20px)",
              }}
            >
              <div className="text-xs tracking-widest uppercase mb-4" style={{ color: "rgba(255,255,255,0.3)" }}>Protection Layers</div>
              {[
                { name: "Path Analysis", desc: "MITM / traffic inspection", state: phase === 0 ? "idle" : currentResult?.risk === "high" ? "blocked" : "active" },
                { name: "Lure Detection", desc: "AI NLP classification", state: phase === 0 ? "idle" : currentResult?.signals.some(s => s.category === "LURE") ? "blocked" : "active" },
                { name: "Adaptive Gate", desc: "Risk-based enforcement", state: phase === 0 ? "idle" : currentResult?.risk === "medium" || currentResult?.risk === "high" ? "blocked" : "active" },
                { name: "Authenticator", desc: "Step-up MFA", state: phase === 0 ? "idle" : currentResult?.risk === "medium" ? "blocked" : "active" },
                { name: "Neutralisation", desc: "Auto-freeze on high risk", state: phase === 0 ? "idle" : currentResult?.risk === "high" ? "neutralised" : "active" },
              ].map((layer, i) => {
                const stateColors: Record<string, string> = { idle: "rgba(255,255,255,0.15)", active: "#22c55e", blocked: "#ef4444", neutralised: "#ef4444" };
                return (
                  <div key={layer.name} className="flex items-center justify-between py-2.5 border-b last:border-0" style={{ borderColor: "rgba(255,255,255,0.04)" }}>
                    <div>
                      <div className="text-sm font-medium text-white/80">{layer.name}</div>
                      <div className="text-[10px] mt-0.5" style={{ color: "rgba(255,255,255,0.25)" }}>{layer.desc}</div>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <div className="w-1.5 h-1.5 rounded-full" style={{ background: stateColors[layer.state], boxShadow: layer.state !== "idle" ? `0 0 6px ${stateColors[layer.state]}60` : "none" }} />
                      <span className="text-[10px] uppercase tracking-widest" style={{ color: stateColors[layer.state] }}>{layer.state}</span>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Recent */}
            <div
              className="rounded-2xl p-5 border fade-up"
              style={{
                background: "rgba(255,255,255,0.03)",
                borderColor: "rgba(255,255,255,0.06)",
                backdropFilter: "blur(20px)",
              }}
            >
              <div className="text-xs tracking-widest uppercase mb-3" style={{ color: "rgba(255,255,255,0.3)" }}>Recent</div>
              <div className="space-y-2">
                {logs.length === 0
                  ? <p className="text-xs text-white/15 text-center py-4">No requests yet</p>
                  : logs.map(log => <RequestCard key={log.id} log={log} active={activeLogId === log.id} />)
                }
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Stats Footer */}
      <div className="border-t" style={{ borderColor: "rgba(255,255,255,0.05)" }}>
        <div className="max-w-5xl mx-auto px-8 py-8">
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "32px" }}>
            <StatBlock value="14,302" label="Path Analysis" delay={0} />
            <StatBlock value="9,107" label="Lure Detection" delay={100} />
            <StatBlock value="8,264" label="Adaptive Gate" delay={200} />
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="px-8 pb-8">
        <div className="max-w-5xl mx-auto flex items-center justify-between">
          <span className="text-xs" style={{ color: "rgba(255,255,255,0.2)" }}>© 2025 Cloud-Phish Guard</span>
          <div className="flex items-center gap-6">
            {["Privacy", "Terms", "Security"].map(l => (
              <span key={l} className="text-xs cursor-pointer transition-opacity hover:opacity-60" style={{ color: "rgba(255,255,255,0.2)" }}>{l}</span>
            ))}
          </div>
        </div>
      </footer>
    </div>
  );
}