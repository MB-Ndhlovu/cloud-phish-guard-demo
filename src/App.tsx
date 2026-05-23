import { useState, useEffect, useRef } from "react";

type LayerState = "idle" | "checking" | "pass" | "block" | "neutralize";
type RiskLevel = "low" | "medium" | "high";

interface RequestLog {
  id: number;
  timestamp: string;
  url: string;
  risk: RiskLevel;
  verdict: string;
  score: number;
  layers: {
    pathAnalysis: LayerState;
    lureDetection: LayerState;
    adaptiveGate: LayerState;
    authenticator: LayerState;
    neutralisation: LayerState;
  };
}

interface ThreatSignal {
  label: string;
  category: "PATH" | "LURE" | "GATE" | "AUTH" | "NEUTRAL";
}

// --- Threat Intelligence ---
const PATH_SIGNALS = [
  { pattern: /mitm|man.?in.?the.?middle/i, label: "MITM INTERCEPT RISK", weight: 30 },
  { pattern: /proxy|transparent|i[sp]\.[0-9]+\.[0-9]+\.[0-9]/i, label: "PROXY TRAFFIC DETECTED", weight: 20 },
  { pattern: /http:\/\//i, label: "UNENCRYPTED CHANNEL", weight: 25 },
  { pattern: /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/i, label: "DIRECT IP ACCESS", weight: 15 },
];

const LURE_SIGNALS = [
  { pattern: /urgent|asap|immediately|now/i, label: "URGENCY MANIPULATION", weight: 20 },
  { pattern: /verify|confirm|update.*account/i, label: "AUTH IMPERSONATION", weight: 25 },
  { pattern: /suspended|locked|compromised/i, label: "FEAR TACTIC", weight: 20 },
  { pattern: /login.*urgent|security.*alert/i, label: "FAKE SECURITY PROMPT", weight: 30 },
  { pattern: /click.*here.*now|act.*now/i, label: "DIRECTIVE DECEPTION", weight: 25 },
  { pattern: /paypa1\.|bank-of-|amazon-verify\./i, label: "TYPOSQUAT DOMAIN", weight: 35 },
  { pattern: /secure-login|secure-verify|account-update/i, label: "SUSPICIOUS PATH", weight: 15 },
  { pattern: /free.*gift|winner|congratulations/i, label: "SOCIAL ENGINEERING LURE", weight: 20 },
];

const GATE_SIGNALS = [
  { pattern: /token=|session=|auth=/i, label: "SESSION MANIPULATION", weight: 15 },
  { pattern: /redirect=|return=|callback=/i, label: "REDIRECT INJECTION", weight: 20 },
];

const TRUSTED_DOMAINS = ["github.com", "google.com", "microsoft.com", "dropbox.com", "linkedin.com", "apple.com", "amazon.com", "cloudflare.com"];

function classifyUrl(raw: string): { risk: RiskLevel; score: number; signals: ThreatSignal[] } {
  let score = 30;
  const signals: ThreatSignal[] = [];
  const url = raw.toLowerCase();

  const isTrusted = TRUSTED_DOMAINS.some(d => url.includes(d));
  if (isTrusted) { score -= 25; signals.push({ label: "TRUSTED DOMAIN", category: "PATH" }); }

  for (const s of PATH_SIGNALS) { if (s.pattern.test(url)) { score += s.weight; signals.push({ label: s.label, category: "PATH" }); } }
  for (const s of LURE_SIGNALS) { if (s.pattern.test(url)) { score += s.weight; signals.push({ label: s.label, category: "LURE" }); } }
  for (const s of GATE_SIGNALS) { if (s.pattern.test(url)) { score += s.weight; signals.push({ label: s.label, category: "GATE" }); } }

  score = Math.max(0, Math.min(100, score));
  const risk: RiskLevel = score >= 70 ? "high" : score >= 40 ? "medium" : "low";
  return { risk, score, signals };
}

function getVerdict(risk: RiskLevel, score: number): string {
  if (risk === "high") return "BLOCKED & FROZEN";
  if (risk === "medium") return "STEP-UP MFA";
  return "ACCESS GRANTED";
}

function getVerdictColor(risk: RiskLevel): string {
  if (risk === "high") return "text-red-600";
  if (risk === "medium") return "text-amber-600";
  return "text-emerald-600";
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

function ThreatBar({ score, risk, phase }: { score: number; risk: RiskLevel; phase: number }) {
  const zones = ["SAFE", "LOW", "MED", "HIGH", "CRIT"];
  const zoneColors = ["#16a34a", "#22c55e", "#d97706", "#dc2626", "#991b1b"];

  return (
    <div className="mb-5">
      <div className="flex items-center justify-between mb-2">
        <span className="text-zinc-500 text-xs font-medium">THREAT LEVEL</span>
        <span className={`text-xs font-semibold px-2 py-0.5 border ${risk === "high" ? "border-red-300 text-red-600 bg-red-50" : risk === "medium" ? "border-amber-300 text-amber-600 bg-amber-50" : "border-emerald-300 text-emerald-600 bg-emerald-50"}`} style={{ borderRadius: 4 }}>
          {phase > 0 ? "SCANNING..." : risk === "high" ? "HIGH RISK" : risk === "medium" ? "MEDIUM RISK" : "LOW RISK"}
        </span>
      </div>
      <div className="relative h-10 border border-zinc-300 bg-white rounded overflow-hidden">
        <div className="absolute inset-x-0 top-0 flex h-full">
          {zones.map((zone, i) => (
            <div key={zone} className="flex items-center justify-center text-[9px] font-bold tracking-widest text-white border-r border-white/40 last:border-r-0" style={{ width: "20%", backgroundColor: zoneColors[i] }}>
              {zone}
            </div>
          ))}
        </div>
        <div className="absolute top-0 bottom-0 w-0.5 bg-zinc-900 z-10" style={{ left: `${score}%`, transform: "translateX(-50%)", transition: "left 0.8s cubic-bezier(0.16, 1, 0.3, 1)" }}>
          <div className="absolute -top-1 left-1/2 -translate-x-1/2 w-0 h-0" style={{ borderLeft: "4px solid transparent", borderRight: "4px solid transparent", borderTop: "6px solid #18181b" }} />
        </div>
      </div>
      <div className="flex items-center justify-between mt-1.5">
        <span className="text-zinc-400 text-xs">{score}/100</span>
        <span className={`text-xs font-semibold ${getVerdictColor(risk)}`}>{getVerdict(risk, score)}</span>
      </div>
    </div>
  );
}

function SecurityLayers({ phase, layers }: { phase: number; layers: RequestLog["layers"] }) {
  const layerConfig = [
    { key: "pathAnalysis" as const, label: "PATH ANALYSIS", desc: "MITM / Eavesdropping detection", delay: 0 },
    { key: "lureDetection" as const, label: "LURE DETECTION", desc: "AI-driven NLP phishing signal ID", delay: 1 },
    { key: "adaptiveGate" as const, label: "ADAPTIVE GATE", desc: "Risk-based enforcement engine", delay: 2 },
    { key: "authenticator" as const, label: "AUTHENTICATOR", desc: "Custom MFA / step-up verification", delay: 3 },
    { key: "neutralisation" as const, label: "NEUTRALISATION", desc: "Auto-freeze & isolate on high risk", delay: 4 },
  ];

  return (
    <div className="border border-zinc-300 rounded-lg bg-zinc-100 overflow-hidden">
      <div className="bg-zinc-200 px-4 py-2 border-b border-zinc-300">
        <span className="text-zinc-700 text-xs font-semibold tracking-widest">SECURITY LAYERS</span>
      </div>
      <div className="divide-y divide-zinc-300/60">
        {layerConfig.map(({ key, label, desc, delay }) => {
          const state = layers[key];
          const isActive = phase > delay;
          const isProcessing = phase === delay + 1;

          return (
            <div key={key} className="flex items-center gap-3 px-4 py-3" style={{ opacity: isActive ? 1 : 0.4, transition: "opacity 0.3s" }}>
              <div className={`w-2 h-2 rounded-full flex-shrink-0 ${isActive ? (state === "block" || state === "neutralize" ? "bg-red-500" : state === "pass" ? "bg-emerald-500" : "bg-zinc-400") : "bg-zinc-300"}`}
                style={isActive && isProcessing ? { boxShadow: "0 0 0 3px rgba(185,28,28,0.15)", animation: "pulse 1s infinite" } : {}} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-zinc-700 text-xs font-semibold tracking-wider">{label}</span>
                  {isActive && <span className="text-[9px] font-medium px-1.5 py-0.5 rounded" style={{ backgroundColor: state === "pass" ? "#dcfce7" : state === "block" || state === "neutralize" ? "#fee2e2" : "#f3f4f6", color: state === "pass" ? "#166534" : state === "block" || state === "neutralize" ? "#991b1b" : "#374151" }}>{state.toUpperCase()}</span>}
                </div>
                <div className="text-zinc-400 text-[10px] mt-0.5">{desc}</div>
              </div>
              {isProcessing && <div className="w-16 h-1 bg-zinc-200 rounded overflow-hidden"><div className="h-full bg-red-600 rounded animate-pulse" style={{ animation: "loading 0.6s ease-in-out infinite", width: "70%" }} /></div>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function RequestLog({ logs }: { logs: RequestLog[] }) {
  const recent = [...logs].reverse().slice(0, 5);
  return (
    <div className="border border-zinc-300 rounded-lg bg-zinc-100 overflow-hidden">
      <div className="bg-zinc-200 px-4 py-2 border-b border-zinc-300 flex items-center justify-between">
        <span className="text-zinc-700 text-xs font-semibold tracking-widest">REQUEST LOG</span>
        <span className="text-zinc-400 text-[10px]">{recent.length} entries</span>
      </div>
      <div className="divide-y divide-zinc-300/60">
        {recent.length === 0 && <div className="px-4 py-6 text-center text-zinc-400 text-xs">No requests processed yet</div>}
        {recent.map((log, i) => (
          <div key={log.id} className="px-4 py-3" style={{ borderLeft: `3px solid ${log.risk === "high" ? "#dc2626" : log.risk === "medium" ? "#d97706" : "#16a34a"}`, animation: `fadeInUp 0.3s ease ${i * 0.05}s both` }}>
            <div className="flex items-center justify-between mb-1">
              <span className="text-zinc-500 text-[10px] font-mono">{log.timestamp}</span>
              <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded ${log.risk === "high" ? "bg-red-100 text-red-700" : log.risk === "medium" ? "bg-amber-100 text-amber-700" : "bg-emerald-100 text-emerald-700"}`}>{log.risk.toUpperCase()}</span>
            </div>
            <div className="text-zinc-700 text-xs font-mono truncate">{log.url}</div>
            <div className="text-zinc-400 text-[10px] mt-1">{getVerdict(log.risk, log.score)}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function StatCounter({ label, value, desc }: { label: string; value: number; desc: string }) {
  const [display, setDisplay] = useState(0);

  useEffect(() => {
    const steps = 40;
    const increment = value / steps;
    let current = 0;
    const interval = setInterval(() => {
      current += increment;
      if (current >= value) { setDisplay(value); clearInterval(interval); }
      else setDisplay(Math.floor(current));
    }, 30);
    return () => clearInterval(interval);
  }, [value]);

  return (
    <div className="text-center px-4">
      <div className="text-3xl font-bold text-zinc-800">{display.toLocaleString()}</div>
      <div className="text-xs font-semibold tracking-widest text-zinc-500 mt-1">{label}</div>
      <div className="text-xs text-zinc-400 mt-1">{desc}</div>
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
  const demoRef = useRef(0);

  const handleAnalyze = () => {
    if (!inputUrl.trim()) return;
    runAnalysis(inputUrl.trim());
  };

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
        setLogs(prev => [...prev, {
          id: Date.now(),
          timestamp: new Date().toLocaleTimeString("en-US", { hour12: false }),
          url,
          risk: result.risk,
          verdict: getVerdict(result.risk, result.score),
          score: result.score,
          layers: {
            pathAnalysis: result.risk === "high" ? "block" : "pass",
            lureDetection: result.risk === "high" ? "block" : result.signals.some(s => s.category === "LURE") ? "block" : "pass",
            adaptiveGate: result.risk === "high" ? "block" : result.risk === "medium" ? "block" : "pass",
            authenticator: result.risk === "medium" ? "block" : "pass",
            neutralisation: result.risk === "high" ? "neutralize" : "pass",
          },
        }]);
        setPhase(6);
      }
    }, 400);
  };

  const runDemo = () => {
    if (isDemoRunning) return;
    setIsDemoRunning(true);
    let idx = 0;
    const next = () => {
      if (idx >= DEMO_URLS.length) { setIsDemoRunning(false); return; }
      runAnalysis(DEMO_URLS[idx]);
      idx++;
      demoRef.current = setTimeout(next, 3200);
    };
    next();
  };

  useEffect(() => {
    return () => { clearTimeout(demoRef.current); };
  }, []);

  return (
    <div className="min-h-screen bg-zinc-200">
      <style>{`
        @keyframes fadeInUp { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes loading { 0% { width: 0%; } 50% { width: 70%; } 100% { width: 100%; } }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
      `}</style>

      <nav className="bg-zinc-800 border-b border-zinc-700 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 bg-red-600 rounded flex items-center justify-center">
              <span className="text-white text-xs font-bold">CP</span>
            </div>
            <span className="text-zinc-100 font-bold text-sm tracking-wide">CLOUD-PHISH GUARD</span>
          </div>
          <div className="hidden md:flex items-center gap-1 text-zinc-400 text-xs">
            <span>PRODUCT</span>
            <span className="mx-2 text-zinc-600">/</span>
            <span className="text-zinc-300">SECURITY ARCHITECTURE</span>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <div className="w-1.5 h-1.5 rounded-full bg-emerald-400" style={{ animation: "pulse 2s infinite" }} />
            <span className="text-emerald-400 text-xs font-medium">SYSTEM ONLINE</span>
          </div>
          <span className="text-zinc-500 text-[10px] font-mono">v2.4.1</span>
        </div>
      </nav>

      <section className="bg-zinc-800 pb-10">
        <div className="max-w-5xl mx-auto px-6 pt-12 pb-8">
          <div className="max-w-2xl">
            <p className="text-red-400 text-xs font-semibold tracking-widest mb-3">ADAPTIVE IDENTITY INTELLIGENCE</p>
            <h1 className="text-zinc-100 text-4xl md:text-5xl font-bold leading-tight mb-4">
              Cloud Breach Prevention<br />Starts Here
            </h1>
            <p className="text-zinc-400 text-base leading-relaxed mb-6">
              An AI-driven authentication middleware that detects and neutralises phishing attacks before any cloud data is exposed. Five-layer protection, zero compromise.
            </p>
            <div className="flex items-center gap-3">
              <button onClick={runDemo} disabled={isDemoRunning} className="bg-red-600 hover:bg-red-700 text-white text-xs font-semibold px-4 py-2 rounded transition-colors disabled:opacity-50">
                {isDemoRunning ? "RUNNING DEMO..." : "RUN DEMO"}
              </button>
              <span className="text-zinc-500 text-xs">10 sample requests</span>
            </div>
          </div>
        </div>
        <div className="max-w-5xl mx-auto px-6">
          <div className="grid grid-cols-3 gap-0 border-t border-zinc-700">
            {[
              { label: "PATH ANALYSIS", value: 14302, desc: "MITM / Traffic inspection" },
              { label: "LURE DETECTION", value: 9107, desc: "AI NLP phishing signals" },
              { label: "ADAPTIVE GATE", value: 8264, desc: "Risk-based enforcement" },
            ].map((s, i) => (
              <div key={s.label} className={`px-6 py-5 ${i < 2 ? "border-r border-zinc-700" : ""}`}>
                <div className="text-2xl font-bold text-zinc-200">{s.value.toLocaleString()}</div>
                <div className="text-xs font-semibold tracking-widest text-zinc-500 mt-1">{s.label}</div>
                <div className="text-xs text-zinc-600 mt-1">{s.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <div className="max-w-5xl mx-auto px-6 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-5">
            <div className="border border-zinc-300 rounded-lg bg-zinc-100 p-4">
              <ThreatBar score={currentResult?.score ?? 30} risk={currentResult?.risk ?? "low"} phase={phase} />
            </div>

            <div className="border border-zinc-300 rounded-lg bg-zinc-100 p-5">
              <div className="flex items-center gap-0">
                <div className="bg-zinc-300 border border-l border-y border-zinc-300 rounded-l px-3 py-2.5 text-zinc-600 text-sm font-mono">&gt;_</div>
                <input
                  type="text"
                  value={inputUrl}
                  onChange={e => setInputUrl(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && handleAnalyze()}
                  placeholder="Enter URL to analyse..."
                  className="flex-1 border border-zinc-300 rounded-none px-3 py-2.5 text-sm text-zinc-800 placeholder-zinc-400 focus:outline-none focus:border-red-400 bg-white"
                />
                <button onClick={handleAnalyze} disabled={isAnalyzing || !inputUrl.trim()} className="bg-zinc-800 hover:bg-zinc-900 disabled:bg-zinc-400 text-white text-xs font-semibold px-4 py-2.5 rounded-r transition-colors border border-l-0 border-zinc-300 disabled:cursor-not-allowed" style={{ borderRadius: "0 4px 4px 0" }}>
                  [ANALYSE]
                </button>
              </div>

              {currentResult && phase > 5 && (
                <div className="mt-4">
                  <div className="text-xs font-semibold text-zinc-500 tracking-wider mb-2">THREAT SIGNALS DETECTED</div>
                  <div className="flex flex-wrap gap-1.5">
                    {currentResult.signals.length === 0
                      ? <span className="text-xs text-emerald-600 font-medium">No suspicious signals — domain is trusted</span>
                      : currentResult.signals.map(s => (
                        <span key={s.label} className="text-[10px] font-semibold px-2 py-1 rounded" style={{ backgroundColor: "#fee2e2", color: "#991b1b" }}>[{s.label}]</span>
                      ))}
                  </div>
                </div>
              )}
            </div>

            <SecurityLayers phase={phase} layers={currentResult ? {
              pathAnalysis: currentResult.risk === "high" ? "block" : "pass",
              lureDetection: currentResult.risk === "high" ? "block" : currentResult.signals.some(s => s.category === "LURE") ? "block" : "pass",
              adaptiveGate: currentResult.risk === "high" ? "block" : currentResult.risk === "medium" ? "block" : "pass",
              authenticator: currentResult.risk === "medium" ? "block" : "pass",
              neutralisation: currentResult.risk === "high" ? "neutralize" : "pass",
            } : { pathAnalysis: "idle", lureDetection: "idle", adaptiveGate: "idle", authenticator: "idle", neutralisation: "idle" }} />
          </div>

          <div className="space-y-5">
            <RequestLog logs={logs} />

            <div className="border border-zinc-300 rounded-lg bg-zinc-100 overflow-hidden">
              <div className="bg-zinc-300 px-4 py-2 border-b border-zinc-300">
                <span className="text-zinc-700 text-xs font-semibold tracking-widest">DATA CLASSIFICATION</span>
              </div>
              <div className="divide-y divide-zinc-300/60">
                {[
                  { cat: "IDENTITY & CREDENTIALS", level: "HIGH", retention: "Session only", color: "text-red-600" },
                  { cat: "BEHAVIOURAL METADATA", level: "MED", retention: "30 days", color: "text-amber-600" },
                  { cat: "INCIDENT / AUDIT LOGS", level: "MED", retention: "90 days encrypted", color: "text-amber-600" },
                ].map(row => (
                  <div key={row.cat} className="px-4 py-3">
                    <div className="text-xs font-semibold text-zinc-700">{row.cat}</div>
                    <div className="flex items-center justify-between mt-1">
                      <span className={`text-[10px] font-bold ${row.color}`}>{row.level}</span>
                      <span className="text-[10px] text-zinc-400">{row.retention}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="mt-8 border-t border-zinc-300 pt-6 pb-4">
          <div className="grid grid-cols-3 divide-x divide-zinc-300">
            {[
              { label: "PATH ANALYSIS", count: 14302, desc: "Man-in-the-middle / traffic inspection" },
              { label: "LURE DETECTION", count: 9107, desc: "AI NLP phishing signal classification" },
              { label: "ADAPTIVE GATE", count: 8264, desc: "Risk-based enforcement engine" },
            ].map(s => (
              <div key={s.label} className="text-center px-6">
                <StatCounter label={s.label} value={s.count} desc={s.desc} />
              </div>
            ))}
          </div>
          <p className="text-center text-zinc-400 text-xs mt-5 tracking-wide">
            "Every security control exists to protect one thing: the user's data."
          </p>
        </div>
      </div>

      <footer className="bg-zinc-800 border-t border-zinc-700 px-6 py-4 mt-6">
        <div className="max-w-5xl mx-auto flex items-center justify-between">
          <span className="text-zinc-500 text-xs">© 2025 Cloud-Phish Guard. All rights reserved.</span>
          <div className="flex items-center gap-4">
            <span className="text-zinc-500 text-xs">Privacy</span>
            <span className="text-zinc-500 text-xs">Terms</span>
            <span className="text-zinc-500 text-xs">Security</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
