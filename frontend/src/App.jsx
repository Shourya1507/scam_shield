import { useState, useEffect } from 'react';
import { 
  Shield, Phone, Mail, DollarSign, Database, FileText, Play, 
  CheckCircle, AlertTriangle, XCircle, RefreshCw, Layers, Award, 
  Image as ImageIcon, HelpCircle, Activity, ArrowRight, User, Eye
} from 'lucide-react';

// --- Scam Patterns Library (Matches scam_patterns.json) ---
const SCAM_PATTERNS = {
  urgency_phrases: [
    "act now", "immediate action required", "your account will be suspended",
    "verify your identity within 24 hours", "final notice", "last warning",
    "you have won", "claim your prize", "limited time offer",
    "respond immediately", "expires today", "deadline passed"
  ],
  financial_red_flags: [
    "wire transfer", "gift card", "bitcoin", "crypto wallet", "western union",
    "send money to", "processing fee", "unlock your funds", "advance fee",
    "guaranteed returns", "risk-free investment", "double your money",
    "money gram", "zelle payment", "venmo payment", "cash app", "prepaid debit"
  ],
  impersonation_terms: [
    "irs", "social security administration", "amazon support", "microsoft support",
    "bank security team", "tech support", "government grant", "law enforcement",
    "fbi", "federal reserve", "drug enforcement", "customs and border protection",
    "apple support", "google support", "paypal security"
  ],
  credential_harvest_terms: [
    "confirm your password", "update your billing information", "click here to verify",
    "enter your ssn", "enter your pin", "your card has been locked",
    "verify your account", "confirm your social security", "provide your date of birth",
    "enter your mother's maiden name", "reset your password now"
  ],
  emotional_manipulation: [
    "grandchild in trouble", "arrested", "hospital emergency", "kidnapped",
    "do not tell anyone", "keep this confidential", "this is urgent and secret",
    "loved one in danger", "bail money", "emergency situation",
    "do not hang up", "stay on the line"
  ]
};

const CATEGORY_WEIGHTS = {
  urgency_phrases: 12,
  financial_red_flags: 20,
  impersonation_terms: 15,
  credential_harvest_terms: 22,
  emotional_manipulation: 18
};

// --- Legitimate Domain Library (Matches legitimate_domains.json) ---
const DOMAIN_DATA = {
  trusted_domains: [
    "irs.gov", "ssa.gov", "usa.gov", "amazon.com", "paypal.com",
    "microsoft.com", "apple.com", "bankofamerica.com", "chase.com",
    "wellsfargo.com", "google.com", "fdic.gov", "consumerfinance.gov",
    "citibank.com", "usbank.com", "td.com", "capitalone.com",
    "discover.com", "americanexpress.com", "ebay.com", "walmart.com",
    "target.com", "bestbuy.com", "netflix.com", "spotify.com",
    "facebook.com", "instagram.com", "twitter.com", "linkedin.com"
  ],
  common_lookalike_tlds: [".xyz", ".top", ".club", ".support", ".live", ".click", ".info", ".online", ".site", ".tech"]
};

// --- Presets / Sample Inputs ---
const PRESETS = {
  call: {
    text: "Hello, this is Officer Daniels calling from the Social Security Administration.\nYour social security number has been suspended due to suspicious activity.\nThis is urgent. You must act now or you will be arrested within 24 hours.\nTo avoid legal action, please confirm your social security number and date of birth,\nthen purchase gift cards and read me the codes to verify your identity.\nDo not tell anyone about this call, it is confidential.",
    sender: "+1-800-772-1213"
  },
  email: {
    text: "Subject: Final Notice - Your Amazon Account Will Be Suspended\n\nDear Customer,\n\nWe detected unusual sign-in activity on your account. Your account will be suspended within 24 hours unless you verify your identity immediately.\n\nClick here to verify: http://amaz0n-secure-login.xyz/verify\n\nPlease confirm your password and update your billing information to avoid permanent suspension. This is your final notice.\n\nAmazon Support Team",
    sender: "support@amaz0n-secure-login.xyz"
  },
  financial: {
    text: "Exclusive opportunity! Our AI trading bot guarantees 20% monthly returns with zero risk.\nLimited spots available, act now before this offer closes. Just send a small processing fee in Bitcoin to unlock your account and start earning guaranteed returns immediately.\nThis is a once in a lifetime, risk-free investment opportunity.",
    sender: "AI_Crypto_Bot"
  }
};

// --- Helper Functions ---
function levenshtein(a, b) {
  if (a === b) return 0;
  const dp = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = dp[0];
    dp[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cur = dp[j];
      dp[j] = Math.min(dp[j] + 1, dp[j - 1] + 1, prev + (a[i - 1] !== b[j - 1] ? 1 : 0));
      prev = cur;
    }
  }
  return dp[b.length];
}

function extractUrls(text) {
  const urlRegex = /https?:\/\/[^\s\])>\'\"]+/g;
  return text.match(urlRegex) || [];
}

function redactPii(text) {
  let redacted = text;
  const flags = [];
  
  // US SSN
  const ssnRegex = /\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b/g;
  const ssnMatches = text.match(ssnRegex);
  if (ssnMatches) {
    flags.push(`pii_redacted:ssn:count=${ssnMatches.length}`);
    redacted = redacted.replace(ssnRegex, "[SSN_REDACTED]");
  }
  
  // Credit Card
  const cardRegex = /\b(?:\d[ -]?){13,16}\b/g;
  const cardMatches = text.match(cardRegex);
  if (cardMatches) {
    flags.push(`pii_redacted:card:count=${cardMatches.length}`);
    redacted = redacted.replace(cardRegex, "[CARD_REDACTED]");
  }
  
  // US Phone
  const phoneRegex = /\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
  const phoneMatches = text.match(phoneRegex);
  if (phoneMatches) {
    flags.push(`pii_redacted:phone:count=${phoneMatches.length}`);
    redacted = redacted.replace(phoneRegex, "[PHONE_REDACTED]");
  }
  
  // Email
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const emailMatches = text.match(emailRegex);
  if (emailMatches) {
    flags.push(`pii_redacted:email:count=${emailMatches.length}`);
    redacted = redacted.replace(emailRegex, "[EMAIL_REDACTED]");
  }

  return { redacted, flags };
}

async function computeSHA256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function VideoPlayer({ src }) {
  const [hasError, setHasError] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  if (hasError || !src) {
    return (
      <div style={{
        width: '100%', height: '100%',
        display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
        background: 'linear-gradient(135deg, rgba(15,23,42,0.9), rgba(30,27,75,0.8))',
        color: 'var(--text-muted)', gap: '12px', padding: '24px', textAlign: 'center'
      }}>
        <Play size={40} style={{ opacity: 0.25 }} />
        <p style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: 'var(--text-secondary)' }}>Video Placeholder</p>
        <p style={{ margin: 0, fontSize: '12px', maxWidth: '280px', lineHeight: 1.4 }}>
          Place your walkthrough recording as <code style={{ background: 'rgba(255,255,255,0.06)', padding: '2px 6px', borderRadius: '4px', fontSize: '11px' }}>walkthrough.webp</code> in the <code style={{ background: 'rgba(255,255,255,0.06)', padding: '2px 6px', borderRadius: '4px', fontSize: '11px' }}>public/</code> directory, then reload.
        </p>
      </div>
    );
  }

  return (
    <video
      className="media-video"
      src={src}
      controls
      loop
      muted
      playsInline
      onError={() => setHasError(true)}
      onLoadedData={() => setIsLoading(false)}
      style={{ display: isLoading ? 'none' : 'block' }}
    />
  );
}

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [channel, setChannel] = useState('call');
  const [inputText, setInputText] = useState(PRESETS.call.text);
  const [sender, setSender] = useState(PRESETS.call.sender);
  const [userId, setUserId] = useState('elderly_user_1');
  const [guardianContact, setGuardianContact] = useState('+1-555-0100');
  
  // Analysis Pipeline States
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [pipelineStep, setPipelineStep] = useState(0); // 0: idle, 1: sanitizer, 2: routing, 3: analysis, 4: memory, 5: final, 6: audit
  const [pipelineLog, setPipelineLog] = useState([]);
  
  // Results
  const [analysisResult, setAnalysisResult] = useState(null);
  
  // Simulator Memory and Notifications State
  const [userHistory, setUserHistory] = useState({
    'elderly_user_1': [
      { id: 1, ts: Date.now() - 3600000 * 4, type: 'call', verdict: 'HIGH_RISK_SCAM', score: 85 },
      { id: 2, ts: Date.now() - 3600000 * 2, type: 'email', verdict: 'HIGH_RISK_SCAM', score: 91 }
    ]
  });
  const [notifications, setNotifications] = useState([
    {
      id: 1,
      ts: new Date(Date.now() - 3600000 * 2).toLocaleTimeString(),
      user_id: 'elderly_user_1',
      recipient: '+1-555-0100',
      message: 'ScamShield Alert: PhishingEmailAgent flagged a HIGH_RISK_SCAM targeting elderly_user_1. Threat Score: 91. Urgent Action required!',
      severity: 'high',
      status: 'Delivered ✓'
    }
  ]);
  
  // Tamper-Evident Ledger State
  const [ledger, setLedger] = useState([]);
  const [isLedgerVerified, setIsLedgerVerified] = useState(null);
  const [isVerifyingLedger, setIsVerifyingLedger] = useState(false);
  const [zoomImage, setZoomImage] = useState(false);

  // Initialize Ledger with pre-existing block hash chain
  useEffect(() => {
    const initializeLedger = async () => {
      let entries = [];
      let prevHash = "0".repeat(64);
      
      const seedEvents = [
        { event_type: "system_initialized", detail: { version: "1.0.0", status: "ready" }, user_id: "system" },
        { event_type: "scan_completed", detail: { input_type: "call", risk: { final_score: 85, verdict: "HIGH_RISK_SCAM", components: { text_score: 80, url_score: 0, channel_weight: 5 } } }, user_id: "elderly_user_1" },
        { event_type: "scan_completed", detail: { input_type: "email", risk: { final_score: 91, verdict: "HIGH_RISK_SCAM", components: { text_score: 66, url_score: 80, channel_weight: 0 } } }, user_id: "elderly_user_1" }
      ];

      for (let i = 0; i < seedEvents.length; i++) {
        const ev = seedEvents[i];
        const entry = {
          ts: Date.now() - 3600000 * (seedEvents.length - i),
          event_type: ev.event_type,
          user_id: ev.user_id,
          detail: ev.detail,
          prev_hash: prevHash
        };
        const payload = JSON.stringify(entry, Object.keys(entry).sort());
        const hash = await computeSHA256(prevHash + payload);
        entry.hash = hash;
        entries.push(entry);
        prevHash = hash;
      }
      setLedger(entries);
    };
    initializeLedger();
  }, []);

  // Update preset inputs when channel changes
  const handleChannelChange = (c) => {
    setChannel(c);
    setInputText(PRESETS[c].text);
    setSender(PRESETS[c].sender);
  };

  // Perform client-side multi-agent threat scan
  const handleAnalyze = async () => {
    setIsAnalyzing(true);
    setPipelineLog([]);
    setAnalysisResult(null);
    
    // Step 1: Security Gateway (Sanitization)
    setPipelineStep(1);
    await new Promise(r => setTimeout(r, 600));
    
    const cleanResult = redactPii(inputText);
    // Check for injection
    const injectionFlags = [];
    const injectionPatterns = [
      /ignore previous instructions/i,
      /ignore all instructions/i,
      /system prompt/i,
      /you are now/i,
      /disregard/i
    ];
    injectionPatterns.forEach(pat => {
      if (pat.test(inputText)) {
        injectionFlags.push(`possible_prompt_injection:${pat.source}`);
      }
    });

    const sanitizerFlags = [...cleanResult.flags, ...injectionFlags];
    
    setPipelineLog(prev => [...prev, {
      step: "Security Gateway (InputSanitizer)",
      desc: `Cleaned characters, Cap size, Redacted PII, Screened Injection. Found ${sanitizerFlags.length} anomalies.`,
      data: JSON.stringify({ redacted_text: cleanResult.redacted, flags: sanitizerFlags }, null, 2)
    }]);

    // Step 2: Orchestration (Routing)
    setPipelineStep(2);
    await new Promise(r => setTimeout(r, 700));
    
    const targetAgent = channel === 'call' ? 'CallProtectionAgent' : channel === 'email' ? 'PhishingEmailAgent' : 'FinancialScamAgent';
    setPipelineLog(prev => [...prev, {
      step: "GuardianAgent (Orchestration)",
      desc: `Inbound type: '${channel.toUpperCase()}'. Dispatched to specialist agent: '${targetAgent}'.`,
      data: `Routing completed. Initializing memory checks for target user_id: '${userId}'.`
    }]);

    // Step 3: Analysis (Rules execution)
    setPipelineStep(3);
    await new Promise(r => setTimeout(r, 900));

    // 1. Text Score
    const lowered = cleanResult.redacted.toLowerCase();
    const findings = {};
    let textScore = 0;
    
    for (const [cat, phrases] of Object.entries(SCAM_PATTERNS)) {
      const hits = phrases.filter(p => lowered.includes(p));
      if (hits.length > 0) {
        findings[cat] = hits;
        textScore += CATEGORY_WEIGHTS[cat] * Math.min(hits.length, 3);
      }
    }
    textScore = Math.min(100, textScore);

    // 2. URL Score
    const urls = extractUrls(inputText);
    const urlResults = urls.map(url => {
      let host = "";
      try { host = new URL(url.includes("://") ? url : "http://" + url).hostname.toLowerCase(); } catch { host = url; }
      const flags = [];
      
      // Suspicious TLD check
      if (DOMAIN_DATA.common_lookalike_tlds.some(tld => host.endsWith(tld))) {
        flags.push("suspicious_tld");
      }
      
      // HTTPS check
      if (!url.startsWith("https://")) {
        flags.push("no_https");
      }
      
      // Typosquat check
      const normalizedHost = host.replace(/[013]/g, c => ({ '0': 'o', '1': 'l', '3': 'e' }[c] || c));
      const hostBrand = normalizedHost.split('.')[0].split('-')[0];
      
      let closest = null;
      let minDist = 99;
      
      DOMAIN_DATA.trusted_domains.forEach(trusted => {
        const trustedBrand = trusted.split('.')[0];
        const d = Math.min(levenshtein(host, trusted), levenshtein(hostBrand, trustedBrand));
        if (d < minDist) {
          closest = trusted;
          minDist = d;
        }
      });
      
      const isTyposquat = closest && minDist <= 2 && host !== closest;
      if (isTyposquat) {
        flags.push(`typosquat_of:${closest}`);
      }
      
      const isTrusted = DOMAIN_DATA.trusted_domains.includes(host);
      
      let risk = 0;
      if (isTyposquat) risk += 60;
      if (flags.includes("suspicious_tld")) risk += 20;
      if (flags.includes("no_https")) risk += 10;
      if (isTrusted) risk = 0;
      
      return {
        url,
        host,
        is_trusted: isTrusted,
        is_typosquat_suspect: isTyposquat,
        closest_known_domain: closest,
        edit_distance: minDist,
        flags,
        url_risk_score: Math.min(100, risk)
      };
    });

    const maxUrlScore = urlResults.reduce((max, r) => Math.max(max, r.url_risk_score), 0);
    const channelWeight = { call: 5, sms: 8, email: 0, financial: 6 }[channel] || 0;
    
    // Combined core score
    let finalScore = Math.round(0.55 * textScore + 0.35 * maxUrlScore + channelWeight);
    finalScore = Math.min(100, finalScore);
    
    setPipelineLog(prev => [...prev, {
      step: `${targetAgent} (Signal Extraction)`,
      desc: `Scanned content. Text Score: ${textScore}, Max URL Score: ${maxUrlScore}, Channel Weight: +${channelWeight}.`,
      data: JSON.stringify({ 
        matched_categories: findings, 
        urls_scanned: urlResults 
      }, null, 2)
    }]);

    // Step 4: Memory Check (Repeat Offender Boost)
    setPipelineStep(4);
    await new Promise(r => setTimeout(r, 600));

    const history = userHistory[userId] || [];
    const highRiskHits = history.filter(h => h.verdict === 'HIGH_RISK_SCAM').length;
    let boost = 0;
    if (highRiskHits >= 3) {
      boost = 15;
    } else if (highRiskHits > 0) {
      boost = 5;
    }

    let preBoostScore = finalScore;
    finalScore = Math.min(100, finalScore + boost);

    let verdict = "LIKELY_SAFE";
    if (finalScore >= 80) verdict = "HIGH_RISK_SCAM";
    else if (finalScore >= 60) verdict = "LIKELY_SCAM";
    else if (finalScore >= 30) verdict = "SUSPICIOUS";

    setPipelineLog(prev => [...prev, {
      step: "RiskMemoryAgent (Memory Check)",
      desc: `History lookup for '${userId}' found ${history.length} events (${highRiskHits} high risk). Memory Boost: +${boost} pts.`,
      data: `Pre-boost Score: ${preBoostScore} -> Boosted Score: ${finalScore} -> Verdict: ${verdict}`
    }]);

    // Step 5: Decision & Actions (Notifications)
    setPipelineStep(5);
    await new Promise(r => setTimeout(r, 600));

    let notifyResult = { sent: false, recipient: null };
    if (finalScore >= 60) {
      const msg = `ScamShield Alert: ${targetAgent} flagged a ${verdict} targeting ${userId}. Threat Score: ${finalScore}. Contact: ${guardianContact}.`;
      notifyResult = {
        sent: true,
        recipient: guardianContact,
        message: msg,
        severity: finalScore >= 80 ? 'high' : 'medium'
      };
      
      // Add notification to state logs
      const newNotif = {
        id: Date.now(),
        ts: new Date().toLocaleTimeString(),
        user_id: userId,
        recipient: guardianContact,
        message: msg,
        severity: finalScore >= 80 ? 'high' : 'medium',
        status: 'Delivered ✓'
      };
      setNotifications(prev => [newNotif, ...prev]);
    }

    setPipelineLog(prev => [...prev, {
      step: "FamilyNotificationAgent (Action Gate)",
      desc: notifyResult.sent 
        ? `High severity trigger met. Dispatched urgent SMS alert to guardian contact: ${guardianContact}.`
        : "Alert threshold not met. Monitoring active.",
      data: JSON.stringify(notifyResult, null, 2)
    }]);

    // Step 6: Ledger Writing (Audit Log)
    setPipelineStep(6);
    await new Promise(r => setTimeout(r, 500));

    // Append to ledger
    const lastBlock = ledger[ledger.length - 1];
    const prevHash = lastBlock ? lastBlock.hash : "0".repeat(64);
    
    const newEntry = {
      ts: Date.now(),
      event_type: "scan_completed",
      user_id: userId,
      detail: {
        input_type: channel,
        risk: {
          final_score: finalScore,
          verdict,
          components: {
            text_score: textScore,
            url_score: maxUrlScore,
            channel_weight: channelWeight
          }
        },
        notify: notifyResult
      },
      prev_hash: prevHash
    };

    const payload = JSON.stringify(newEntry, Object.keys(newEntry).sort());
    const newHash = await computeSHA256(prevHash + payload);
    newEntry.hash = newHash;

    setLedger(prev => [...prev, newEntry]);
    
    // Add current run to user's history
    const updatedHistoryItem = {
      id: Date.now(),
      ts: Date.now(),
      type: channel,
      verdict,
      score: finalScore
    };
    setUserHistory(prev => ({
      ...prev,
      [userId]: [...(prev[userId] || []), updatedHistoryItem]
    }));

    setPipelineLog(prev => [...prev, {
      step: "AuditLogger (Ledger Entry Created)",
      desc: "Hash-chained block appended successfully. SHA-256 seal computed.",
      data: `Block Hash: ${newHash}\nPrev Hash: ${prevHash}`
    }]);

    setAnalysisResult({
      score: finalScore,
      verdict,
      textScore,
      urlScore: maxUrlScore,
      redactedText: cleanResult.redacted,
      flags: sanitizerFlags,
      findings,
      urlResults,
      boost,
      notified: notifyResult.sent
    });

    setIsAnalyzing(false);
    setPipelineStep(0);
  };

  // Perform full ledger chain verification
  const handleVerifyLedger = async () => {
    setIsVerifyingLedger(true);
    setIsLedgerVerified(null);
    await new Promise(r => setTimeout(r, 1200));

    let prev = "0".repeat(64);
    let valid = true;

    for (let i = 0; i < ledger.length; i++) {
      const block = { ...ledger[i] };
      const claimedHash = block.hash;
      delete block.hash;
      
      const payload = JSON.stringify(block, Object.keys(block).sort());
      const expectedHash = await computeSHA256(prev + payload);
      
      if (expectedHash !== claimedHash || block.prev_hash !== prev) {
        valid = false;
        break;
      }
      prev = claimedHash;
    }

    setIsLedgerVerified(valid);
    setIsVerifyingLedger(false);
  };

  // Tamper ledger to test verification failure
  const handleTamperLedger = () => {
    if (ledger.length === 0) return;
    const modifiedLedger = [...ledger];
    // Tamper with the details in the second block
    if (modifiedLedger[1]) {
      modifiedLedger[1] = {
        ...modifiedLedger[1],
        detail: {
          ...modifiedLedger[1].detail,
          risk: {
            ...modifiedLedger[1].detail.risk,
            final_score: 10 // Tampered! Changed score from 85 to 10
          }
        }
      };
      setLedger(modifiedLedger);
      setIsLedgerVerified(null);
      alert("⚠️ SYSTEM TAMPERED: Score in Block #2 modified from 85 to 10. Run 'Verify Chain Integrity' to test detectors.");
    }
  };

  // Reset/restore Ledger
  const handleResetLedger = async () => {
    let entries = [];
    let prevHash = "0".repeat(64);
    
    const seedEvents = [
      { event_type: "system_initialized", detail: { version: "1.0.0", status: "ready" }, user_id: "system" },
      { event_type: "scan_completed", detail: { input_type: "call", risk: { final_score: 85, verdict: "HIGH_RISK_SCAM", components: { text_score: 80, url_score: 0, channel_weight: 5 } } }, user_id: "elderly_user_1" },
      { event_type: "scan_completed", detail: { input_type: "email", risk: { final_score: 91, verdict: "HIGH_RISK_SCAM", components: { text_score: 66, url_score: 80, channel_weight: 0 } } }, user_id: "elderly_user_1" }
    ];

    for (let i = 0; i < seedEvents.length; i++) {
      const ev = seedEvents[i];
      const entry = {
        ts: Date.now() - 3600000 * (seedEvents.length - i),
        event_type: ev.event_type,
        user_id: ev.user_id,
        detail: ev.detail,
        prev_hash: prevHash
      };
      const payload = JSON.stringify(entry, Object.keys(entry).sort());
      const hash = await computeSHA256(prevHash + payload);
      entry.hash = hash;
      entries.push(entry);
      prevHash = hash;
    }
    setLedger(entries);
    setIsLedgerVerified(null);
  };

  // Add simulated historical incident
  const handleAddIncident = (verdictType) => {
    const score = verdictType === 'HIGH_RISK_SCAM' ? 88 : verdictType === 'SUSPICIOUS' ? 45 : 15;
    const item = {
      id: Date.now(),
      ts: Date.now(),
      type: ['call', 'email', 'financial'][Math.floor(Math.random() * 3)],
      verdict: verdictType,
      score
    };
    setUserHistory(prev => ({
      ...prev,
      [userId]: [item, ...(prev[userId] || [])]
    }));
  };

  const clearIncidentHistory = () => {
    setUserHistory(prev => ({
      ...prev,
      [userId]: []
    }));
  };

  // Radial Dial calculations
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const currentScore = analysisResult ? analysisResult.score : 0;
  const strokeDashoffset = circumference - (currentScore / 100) * circumference;

  const getVerdictStyle = (v) => {
    if (v === 'HIGH_RISK_SCAM' || v === 'LIKELY_SCAM') return 'verdict-SCAM';
    if (v === 'SUSPICIOUS') return 'verdict-SUSPICIOUS';
    return 'verdict-SAFE';
  };

  const getDialColor = (score) => {
    if (score >= 80) return 'var(--accent-rose)';
    if (score >= 60) return 'var(--accent-amber)';
    if (score >= 30) return '#fbbf24';
    return 'var(--accent-emerald)';
  };

  return (
    <div className="app-container">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div>
          <div className="brand-section">
            <div className="brand-icon-wrapper">
              <Shield size={24} color="#ffffff" />
            </div>
            <span className="brand-name">ScamShield AI</span>
          </div>

          <nav className="nav-links">
            <button 
              id="nav-dashboard"
              className={`nav-btn ${activeTab === 'dashboard' ? 'active' : ''}`}
              onClick={() => setActiveTab('dashboard')}
            >
              <Activity size={18} />
              <span>Inbound Analyzer</span>
            </button>
            <button 
              id="nav-simulator"
              className={`nav-btn ${activeTab === 'simulator' ? 'active' : ''}`}
              onClick={() => setActiveTab('simulator')}
            >
              <Award size={18} />
              <span>Memory Simulator</span>
            </button>
            <button 
              id="nav-ledger"
              className={`nav-btn ${activeTab === 'ledger' ? 'active' : ''}`}
              onClick={() => setActiveTab('ledger')}
            >
              <Database size={18} />
              <span>Audit Ledger</span>
              <span className="pill-count">{ledger.length}</span>
            </button>
            <button 
              id="nav-gallery"
              className={`nav-btn ${activeTab === 'gallery' ? 'active' : ''}`}
              onClick={() => setActiveTab('gallery')}
            >
              <ImageIcon size={18} />
              <span>Media Gallery</span>
            </button>
          </nav>
        </div>

        <div className="sidebar-footer">
          <p>Protected User: <strong>{userId}</strong></p>
          <p style={{ marginTop: '4px', fontSize: '11px' }}>Vercel Edge Gateway • v1.0</p>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main-content">
        
        {activeTab === 'dashboard' && (
          <div>
            <div className="page-header">
              <h1 className="page-title">ScamShield AI Gateway</h1>
              <p className="page-subtitle">Real-time threat detection and multi-agent analysis for elderly protection</p>
            </div>

            <div className="dashboard-grid">
              
              {/* Scan Control Input panel */}
              <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div className="form-group">
                  <label className="form-label">Inbound Channel</label>
                  <div className="channel-selector">
                    <button 
                      id="chan-call"
                      className={`channel-btn ${channel === 'call' ? 'active' : ''}`}
                      onClick={() => handleChannelChange('call')}
                    >
                      <Phone size={20} />
                      <span>Phone Call</span>
                    </button>
                    <button 
                      id="chan-email"
                      className={`channel-btn ${channel === 'email' ? 'active' : ''}`}
                      onClick={() => handleChannelChange('email')}
                    >
                      <Mail size={20} />
                      <span>Phishing Email</span>
                    </button>
                    <button 
                      id="chan-financial"
                      className={`channel-btn ${channel === 'financial' ? 'active' : ''}`}
                      onClick={() => handleChannelChange('financial')}
                    >
                      <DollarSign size={20} />
                      <span>Financial Msg</span>
                    </button>
                  </div>
                </div>

                <div className="form-group">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <label className="form-label">Sample Presets</label>
                    <span className="preset-badge" style={{ fontSize: '11px' }} onClick={() => handleChannelChange(channel)}>Reload Template</span>
                  </div>
                  <div className="preset-container">
                    <button 
                      id="preset-load"
                      className="preset-badge" 
                      onClick={() => {
                        setInputText(PRESETS[channel].text);
                        setSender(PRESETS[channel].sender);
                      }}
                    >
                      Load Standard {channel.charAt(0).toUpperCase() + channel.slice(1)} Scam Pattern
                    </button>
                  </div>
                </div>

                <div className="form-row">
                  <div className="form-group">
                    <label className="form-label">Protected User ID</label>
                    <input 
                      id="input-user-id"
                      type="text" 
                      className="input-field" 
                      value={userId} 
                      onChange={(e) => setUserId(e.target.value)} 
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Sender Address / Contact</label>
                    <input 
                      id="input-sender"
                      type="text" 
                      className="input-field" 
                      value={sender} 
                      onChange={(e) => setSender(e.target.value)} 
                    />
                  </div>
                </div>

                <div className="form-group">
                  <label className="form-label">Content Body</label>
                  <textarea 
                    id="input-text-body"
                    className="text-input"
                    value={inputText}
                    onChange={(e) => setInputText(e.target.value)}
                    placeholder="Enter transcript, email body, or transaction memo to scan..."
                  />
                </div>

                <button 
                  id="btn-scan"
                  className="btn-primary" 
                  onClick={handleAnalyze} 
                  disabled={isAnalyzing || !inputText.trim()}
                >
                  {isAnalyzing ? (
                    <>
                      <RefreshCw className="loading-dots" style={{ animation: 'spin 2s linear infinite' }} size={18} />
                      <span>Agents Analysing</span>
                    </>
                  ) : (
                    <>
                      <Shield size={18} />
                      <span>Analyze Inbound Transmission</span>
                    </>
                  )}
                </button>
              </div>

              {/* Threat Result Panel */}
              <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '20px', justifyContent: 'center', minHeight: '450px' }}>
                {!analysisResult && !isAnalyzing && (
                  <div style={{ color: 'var(--text-muted)', textAlign: 'center' }}>
                    <Shield size={48} style={{ opacity: 0.15, marginBottom: '16px' }} />
                    <h3 style={{ margin: 0, fontFamily: 'var(--heading)' }}>Awaiting Scan Content</h3>
                    <p style={{ fontSize: '13px', marginTop: '6px' }}>Provide raw text inputs on the left side and trigger the scan to run the multi-agent detection pipeline.</p>
                  </div>
                )}

                {isAnalyzing && (
                  <div className="pipeline-status">
                    <div className="status-step active">
                      <div className={`step-icon-wrapper ${pipelineStep >= 1 ? 'completed' : 'active'}`}>
                        {pipelineStep > 1 ? <CheckCircle size={16} /> : <Layers size={16} />}
                      </div>
                      <div className="step-info">
                        <p className="step-name">Security Gateway</p>
                        <p className="step-desc">PII scrubbing, control char check, injection screening...</p>
                      </div>
                    </div>

                    <div className={`status-step ${pipelineStep >= 2 ? 'active' : ''}`}>
                      <div className={`step-icon-wrapper ${pipelineStep >= 2 ? (pipelineStep > 2 ? 'completed' : 'active') : ''}`}>
                        {pipelineStep > 2 ? <CheckCircle size={16} /> : <Activity size={16} />}
                      </div>
                      <div className="step-info">
                        <p className="step-name">GuardianAgent Routing</p>
                        <p className="step-desc">Loading weights, matching channel, starting agent thread...</p>
                      </div>
                    </div>

                    <div className={`status-step ${pipelineStep >= 3 ? 'active' : ''}`}>
                      <div className={`step-icon-wrapper ${pipelineStep >= 3 ? (pipelineStep > 3 ? 'completed' : 'active') : ''}`}>
                        {pipelineStep > 3 ? <CheckCircle size={16} /> : <RefreshCw style={{ animation: 'spin 2s linear infinite' }} size={16} />}
                      </div>
                      <div className="step-info">
                        <p className="step-name">Threat Signal Extraction</p>
                        <p className="step-desc">Keyword parsing, typosquat search, TLD check...</p>
                      </div>
                    </div>

                    <div className={`status-step ${pipelineStep >= 4 ? 'active' : ''}`}>
                      <div className={`step-icon-wrapper ${pipelineStep >= 4 ? (pipelineStep > 4 ? 'completed' : 'active') : ''}`}>
                        {pipelineStep > 4 ? <CheckCircle size={16} /> : <Award size={16} />}
                      </div>
                      <div className="step-info">
                        <p className="step-name">RiskMemoryAgent Query</p>
                        <p className="step-desc">Retrieving rolling threat indices, applying recidivism boost...</p>
                      </div>
                    </div>
                  </div>
                )}

                {analysisResult && !isAnalyzing && (
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                    <div className="score-card">
                      <div className="dial-outer">
                        <svg width="160" height="160" className="svg-dial">
                          <circle cx="80" cy="80" r={radius} className="dial-circle-bg" />
                          <circle 
                            cx="80" 
                            cy="80" 
                            r={radius} 
                            className="dial-circle-fill" 
                            stroke={getDialColor(analysisResult.score)}
                            strokeDasharray={circumference}
                            strokeDashoffset={strokeDashoffset}
                          />
                        </svg>
                        <div className="dial-content">
                          <span className="dial-number">{analysisResult.score}</span>
                          <span className="dial-max">/ 100</span>
                        </div>
                      </div>
                      
                      <div className={`verdict-badge ${getVerdictStyle(analysisResult.verdict)}`}>
                        {analysisResult.score >= 60 ? <AlertTriangle size={16} /> : <CheckCircle size={16} />}
                        <span>{analysisResult.verdict.replace(/_/g, ' ')}</span>
                      </div>
                    </div>

                    <div style={{ width: '100%', borderTop: '1px solid var(--border-color)', paddingTop: '20px', textAlign: 'left' }}>
                      <h4 className="form-label" style={{ marginBottom: '10px' }}>Sanitized Output (PII Redacted)</h4>
                      <p className="step-data" style={{ margin: 0, fontFamily: 'var(--sans)', fontSize: '13px' }}>
                        {analysisResult.redactedText}
                      </p>
                      {analysisResult.flags.length > 0 && (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '12px' }}>
                          {analysisResult.flags.map((flg, idx) => (
                            <span key={idx} style={{ background: 'rgba(245, 158, 11, 0.1)', color: '#fbbf24', border: '1px solid rgba(245, 158, 11, 0.2)', fontSize: '11px', padding: '2px 8px', borderRadius: '4px' }}>
                              ⚠️ {flg}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>

                    {Object.keys(analysisResult.findings).length > 0 && (
                      <div style={{ width: '100%', marginTop: '20px', textAlign: 'left' }}>
                        <h4 className="form-label" style={{ marginBottom: '8px' }}>Matched Threat Categories</h4>
                        <div className="categories-container" style={{ justifyContent: 'flex-start' }}>
                          {Object.keys(analysisResult.findings).map((cat, idx) => (
                            <div key={idx} className="category-tag">
                              <strong>{cat.replace(/_/g, ' ')}</strong>: "{analysisResult.findings[cat].slice(0,2).join(', ')}"
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {analysisResult.urlResults.length > 0 && (
                      <div style={{ width: '100%', marginTop: '20px', textAlign: 'left' }}>
                        <h4 className="form-label" style={{ marginBottom: '8px' }}>URL Analysis Detail</h4>
                        {analysisResult.urlResults.map((ur, idx) => (
                          <div key={idx} className="step-data" style={{ fontSize: '12px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                            <p style={{ margin: 0, color: '#818cf8', fontWeight: 600 }}>{ur.url}</p>
                            <p style={{ margin: 0 }}>Host: <strong>{ur.host}</strong></p>
                            <p style={{ margin: 0 }}>Typosquat Suspect: <span style={{ color: ur.is_typosquat_suspect ? 'var(--accent-rose)' : 'var(--accent-emerald)' }}>{ur.is_typosquat_suspect ? `Yes (Lookalike of ${ur.closest_known_domain})` : 'No'}</span></p>
                            <p style={{ margin: 0 }}>Trusted Domain: <span style={{ color: ur.is_trusted ? 'var(--accent-emerald)' : 'var(--text-secondary)' }}>{ur.is_trusted ? 'Yes ✓' : 'No'}</span></p>
                            {ur.flags.length > 0 && <p style={{ margin: 0, color: '#fbbf24' }}>Flags: [{ur.flags.join(', ')}]</p>}
                          </div>
                        ))}
                      </div>
                    )}

                    {analysisResult.boost > 0 && (
                      <div className="step-data" style={{ width: '100%', marginTop: '16px', background: 'rgba(79, 70, 229, 0.1)', border: '1px solid rgba(79, 70, 229, 0.25)', color: '#c7d2fe', display: 'flex', gap: '8px', alignItems: 'center' }}>
                        <Award size={16} />
                        <span><strong>Repeat Offender Memory Boost</strong>: +{analysisResult.boost} points applied for previous threat incidents.</span>
                      </div>
                    )}

                    {analysisResult.notified && (
                      <div className="step-data" style={{ width: '100%', marginTop: '8px', background: 'rgba(244, 63, 94, 0.1)', border: '1px solid rgba(244, 63, 94, 0.25)', color: '#fecdd3', display: 'flex', gap: '8px', alignItems: 'center' }}>
                        <AlertTriangle size={16} style={{ animation: 'pulse-glow-red 2s infinite' }} />
                        <span><strong>Family Alert Dispatched</strong>: SMS emergency warning successfully transmitted to Guardian.</span>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Live Activity logs at the bottom */}
              <div className="glass-card full-width">
                <h3 className="form-label" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Database size={16} />
                  <span>Pipeline Analysis Steps Log</span>
                </h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
                  {pipelineLog.length === 0 ? (
                    <div style={{ color: 'var(--text-muted)', fontSize: '13px', gridColumn: '1/-1', textAlign: 'center', padding: '20px 0' }}>
                      Logs will populate during the next scan.
                    </div>
                  ) : (
                    pipelineLog.map((log, idx) => (
                      <div key={idx} className="step-data" style={{ fontSize: '11px', display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '180px' }}>
                        <span style={{ fontWeight: 600, color: 'var(--accent-blue)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <ArrowRight size={10} />
                          {log.step}
                        </span>
                        <p style={{ margin: 0, color: 'var(--text-secondary)' }}>{log.desc}</p>
                        <pre style={{ margin: 0, overflowX: 'auto', background: 'rgba(0,0,0,0.3)', padding: '6px', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.02)' }}>{log.data}</pre>
                      </div>
                    ))
                  )}
                </div>
              </div>

            </div>
          </div>
        )}

        {activeTab === 'simulator' && (
          <div>
            <div className="page-header">
              <h1 className="page-title">RiskMemory & Notification Simulator</h1>
              <p className="page-subtitle">Test how repeated threat events trigger risk score boosts and deliver alerts</p>
            </div>

            <div className="memory-grid">
              {/* Controls */}
              <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                <div>
                  <h3 className="form-label" style={{ marginBottom: '12px' }}>Simulate Historical Events</h3>
                  <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px', lineHeight: 1.4 }}>
                    Add threats to user's history database. High risk events trigger memory boosts during live scans.
                  </p>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    <button 
                      id="sim-high-risk"
                      className="channel-btn" 
                      style={{ flexDirection: 'row', justifyContent: 'space-between', padding: '12px' }}
                      onClick={() => handleAddIncident('HIGH_RISK_SCAM')}
                    >
                      <span style={{ color: 'var(--accent-rose)' }}>Add High Risk Incident</span>
                      <span className="verdict-badge verdict-SCAM" style={{ fontSize: '10px', padding: '2px 6px' }}>HIGH RISK</span>
                    </button>
                    <button 
                      id="sim-suspicious"
                      className="channel-btn" 
                      style={{ flexDirection: 'row', justifyContent: 'space-between', padding: '12px' }}
                      onClick={() => handleAddIncident('SUSPICIOUS')}
                    >
                      <span style={{ color: 'var(--accent-amber)' }}>Add Suspicious Incident</span>
                      <span className="verdict-badge verdict-SUSPICIOUS" style={{ fontSize: '10px', padding: '2px 6px' }}>SUSPICIOUS</span>
                    </button>
                    <button 
                      id="sim-clear"
                      className="preset-badge" 
                      style={{ padding: '10px', width: '100%', background: 'rgba(244, 63, 94, 0.05)', borderColor: 'rgba(244, 63, 94, 0.2)', color: '#fecdd3' }}
                      onClick={clearIncidentHistory}
                    >
                      Reset / Clear Incident History
                    </button>
                  </div>
                </div>

                <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '20px' }}>
                  <h3 className="form-label" style={{ marginBottom: '12px' }}>Guardian Contact Details</h3>
                  <div className="form-group">
                    <label className="form-label">Twilio SMS Contact</label>
                    <input 
                      id="sim-sms-contact"
                      type="text" 
                      className="input-field" 
                      value={guardianContact} 
                      onChange={(e) => setGuardianContact(e.target.value)} 
                    />
                  </div>
                </div>
              </div>

              {/* Memory Display */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                <div className="glass-card">
                  <h3 className="form-label" style={{ marginBottom: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span>Incident History Ledger ({userId})</span>
                    <span style={{ fontSize: '11px', textTransform: 'none', color: 'var(--accent-blue)' }}>Used by RiskMemoryAgent</span>
                  </h3>
                  
                  <div className="memory-list">
                    {(userHistory[userId] || []).length === 0 ? (
                      <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '40px 0' }}>
                        No history entries found. Add simulated incidents on the left to test memory boost logic.
                      </div>
                    ) : (
                      (userHistory[userId] || []).map((inc) => (
                        <div key={inc.id} className="memory-item">
                          <div className="memory-header">
                            <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                              {inc.type.toUpperCase()} Scam Scan
                            </span>
                            <span className={`verdict-badge ${getVerdictStyle(inc.verdict)}`} style={{ fontSize: '10px', padding: '2px 8px' }}>
                              Score: {inc.score}
                            </span>
                          </div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px', color: 'var(--text-muted)' }}>
                            <span>Incident recorded: {new Date(inc.ts).toLocaleString()}</span>
                            <span>ID: #{inc.id.toString().slice(-6)}</span>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                <div className="glass-card">
                  <h3 className="form-label" style={{ marginBottom: '16px' }}>Twilio / SendGrid Outbound Logs</h3>
                  <div className="notification-delivery-log">
                    {notifications.map((notif) => (
                      <div key={notif.id} className={`log-entry ${notif.severity === 'high' ? 'high-risk' : ''}`}>
                        <div className="log-time">{notif.ts} — Outbound SMS Gateway</div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px' }}>
                          <p style={{ margin: 0, color: 'var(--text-primary)' }}>{notif.message}</p>
                          <span style={{ color: 'var(--accent-emerald)', fontWeight: 600, fontSize: '11px', whiteSpace: 'nowrap' }}>{notif.status}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

            </div>
          </div>
        )}

        {activeTab === 'ledger' && (
          <div>
            <div className="page-header">
              <h1 className="page-title">Tamper-Evident Audit Ledger</h1>
              <p className="page-subtitle">Inspect the hash-chained blocks generated by our security logging layer</p>
            </div>

            <div className="glass-card">
              <div className="ledger-header-row">
                <div>
                  <h3 className="form-label" style={{ marginBottom: '4px' }}>SHA-256 Block Ledger</h3>
                  <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: 0 }}>Every scan writes a cryptographically sealed block to the logs.</p>
                </div>
                
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button 
                    id="btn-tamper-ledger"
                    className="preset-badge"
                    style={{ background: 'rgba(244, 63, 94, 0.08)', borderColor: 'rgba(244, 63, 94, 0.2)', color: '#fecdd3' }}
                    onClick={handleTamperLedger}
                  >
                    Tamper with Data (Demo Failure)
                  </button>
                  <button 
                    id="btn-verify-ledger"
                    className="btn-primary" 
                    style={{ padding: '8px 16px', fontSize: '13px', width: 'auto', display: 'flex', alignItems: 'center', gap: '6px' }}
                    onClick={handleVerifyLedger}
                    disabled={isVerifyingLedger}
                  >
                    {isVerifyingLedger ? (
                      <>
                        <RefreshCw style={{ animation: 'spin 2s linear infinite' }} size={14} />
                        <span>Verifying Seals...</span>
                      </>
                    ) : (
                      <>
                        <Database size={14} />
                        <span>Verify Chain Integrity</span>
                      </>
                    )}
                  </button>
                  <button className="preset-badge" style={{ padding: '8px 16px' }} onClick={handleResetLedger}>
                    Reset Ledger
                  </button>
                </div>
              </div>

              {isLedgerVerified !== null && (
                <div style={{ 
                  marginBottom: '20px', 
                  padding: '12px 16px', 
                  borderRadius: '8px', 
                  background: isLedgerVerified ? 'rgba(16, 185, 129, 0.1)' : 'rgba(244, 63, 94, 0.1)', 
                  border: isLedgerVerified ? '1px solid rgba(16, 185, 129, 0.2)' : '1px solid rgba(244, 63, 94, 0.2)',
                  color: isLedgerVerified ? '#a7f3d0' : '#fecdd3',
                  textAlign: 'left',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px'
                }}>
                  {isLedgerVerified ? <CheckCircle size={20} /> : <XCircle size={20} />}
                  <div>
                    <strong>Ledger Integrity Check: {isLedgerVerified ? 'PASSED' : 'FAILED'}</strong>
                    <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: isLedgerVerified ? '#cbd5e1' : '#fecdd3' }}>
                      {isLedgerVerified 
                        ? 'All block seals are valid. Chain linkage verifies that no history blocks have been edited or deleted.'
                        : 'Tampering detected! Recomputed block hashes do not match the ledger chain records. Data is untrusted.'}
                    </p>
                  </div>
                </div>
              )}

              <div className="ledger-table-container">
                <table className="ledger-table">
                  <thead>
                    <tr>
                      <th>Block #</th>
                      <th>Timestamp</th>
                      <th>Event Type</th>
                      <th>User ID</th>
                      <th>Detail Summary</th>
                      <th>Previous Block Hash</th>
                      <th>Block Seal Hash</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ledger.map((block, idx) => (
                      <tr key={idx} style={{ background: idx % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)' }}>
                        <td style={{ fontWeight: 600 }}>#{idx + 1}</td>
                        <td style={{ color: 'var(--text-muted)', fontSize: '11px', whiteSpace: 'nowrap' }}>
                          {new Date(block.ts).toLocaleString()}
                        </td>
                        <td>
                          <span className="preset-badge" style={{ textTransform: 'uppercase', fontSize: '10px' }}>
                            {block.event_type}
                          </span>
                        </td>
                        <td><strong>{block.user_id}</strong></td>
                        <td style={{ maxWidth: '280px' }}>
                          <span style={{ fontSize: '11px', color: 'var(--text-secondary)', display: 'block', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                            {JSON.stringify(block.detail)}
                          </span>
                        </td>
                        <td>
                          <span className="ledger-hash">{block.prev_hash}</span>
                        </td>
                        <td>
                          <span className="ledger-hash" style={{ color: 'var(--accent-blue)', fontWeight: 600 }}>{block.hash}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'gallery' && (
          <div>
            <div className="page-header">
              <h1 className="page-title">Project Media Gallery</h1>
              <p className="page-subtitle">Submission assets: cover image and recorded system walkthrough video</p>
            </div>

            <div className="gallery-layout">
              {/* Alert note about Vercel submission requirements */}
              <div className="step-data" style={{ background: 'rgba(79, 70, 229, 0.08)', borderColor: 'rgba(79, 70, 229, 0.25)', color: '#cbd5e1', textAlign: 'left', display: 'flex', gap: '12px', alignItems: 'center', padding: '16px' }}>
                <Shield size={24} style={{ color: '#a5b4fc' }} />
                <div>
                  <strong>Submission Guidelines Compliance</strong>
                  <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>
                    As required, a project cover image is hosted for the writeup submission, and a product walkthrough video (under 5 minutes) is attached below to demonstrate live operation.
                  </p>
                </div>
              </div>

              <div className="media-main-section">
                {/* Cover Image Block */}
                <div className="media-item-box">
                  <div className="media-display-container" style={{ cursor: 'zoom-in' }} onClick={() => setZoomImage(true)}>
                    <img 
                      src="/cover_image.png" 
                      alt="ScamShield AI Cover" 
                      className="media-image" 
                    />
                  </div>
                  <div className="media-info-text">
                    <h3 className="media-title">Project Cover Image</h3>
                    <p className="media-desc">
                      Futuristic cybersecurity dashboard cover asset for ScamShield AI. Exposes the core orchestrator connecting Phishing Email, Scam Call, and Financial Fraud detection engines with our threat indicator library.
                    </p>
                    <div style={{ marginTop: '12px', display: 'flex', gap: '8px' }}>
                      <span className="preset-badge" style={{ fontSize: '10px' }}>1024 × 1024 PX</span>
                      <span className="preset-badge" style={{ fontSize: '10px' }}>PNG format</span>
                    </div>
                  </div>
                </div>


                {/* Walkthrough Video Block */}
                <div className="media-item-box">
                  <div className="media-display-container" style={{ flexDirection: 'column', gap: '12px' }}>
                    <VideoPlayer src="/walkthrough.webp" />
                  </div>
                  <div className="media-info-text">
                    <h3 className="media-title">Product Walkthrough Demonstration</h3>
                    <p className="media-desc">
                      This screen recording showcases the web application in action: executing an email typosquat scanning check, analyzing a voice call transcript, triggering memory boosts via the Risk Memory simulator, and conducting cryptographic block integrity validation.
                    </p>
                    <div style={{ marginTop: '12px', display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                      <span className="preset-badge" style={{ fontSize: '10px' }}>Walkthrough Video</span>
                      <span className="preset-badge" style={{ fontSize: '10px' }}>Duration: &lt;5 min</span>
                      <span className="preset-badge" style={{ fontSize: '10px', color: '#fbbf24', borderColor: 'rgba(245,158,11,0.3)' }}>Drop walkthrough.webp in /public to activate</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Cover Image Zoom Modal */}
            {zoomImage && (
              <div style={{
                position: 'fixed',
                top: 0,
                left: 0,
                width: '100vw',
                height: '100vh',
                background: 'rgba(0,0,0,0.85)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                zIndex: 9999,
                cursor: 'zoom-out'
              }} onClick={() => setZoomImage(false)}>
                <img 
                  src="/cover_image.png" 
                  alt="ScamShield AI Cover Zoom" 
                  style={{ maxHeight: '90vh', maxWidth: '90vw', borderRadius: '8px', boxShadow: '0 8px 32px rgba(0,0,0,0.6)' }} 
                />
              </div>
            )}
          </div>
        )}

      </main>
    </div>
  );
}

export default App;
