// =====================================================================
// PHISHGUARD // OMNITRIX EDITION — Live URL Inspector Controller
// Multi-Model Consensus, Typosquatting Analysis & Telemetry Visualizer
// =====================================================================

const HOMOGLYPH_MAP = {
  'а': 'a', // Cyrillic
  'е': 'e',
  'о': 'o',
  'р': 'p',
  'с': 'c',
  'і': 'i',
  'ν': 'v', // Greek
  'τ': 't',
  '0': 'o', // Digit to letter
  '1': 'l',
  'ı': 'i',
  'ɡ': 'g',
  'ß': 'b',
  'ʀ': 'r'
};

document.addEventListener("DOMContentLoaded", () => {
  initEngineStatus();
  initFormAndPresets();
  initUrlHistory();

  // Handle URL hash anchor if navigated directly to #url-history-section
  if (window.location.hash === "#url-history-section") {
    setTimeout(() => {
      const el = document.getElementById("url-history-section");
      if (el) el.scrollIntoView({ behavior: "smooth" });
    }, 300);
  }
});

// =====================================================================
// 1. ENGINE STATUS TELEMETRY
// =====================================================================
async function initEngineStatus() {
  const pill = document.getElementById("phish-engine-status");
  const text = document.getElementById("phish-engine-text");
  if (!pill || !text) return;

  try {
    const res = await fetch("/api/models-info");
    if (res.ok) {
      const data = await res.json();
      const loadedCount = Object.values(data.models_loaded || {}).filter(Boolean).length;
      pill.classList.remove("status-error");
      pill.classList.add("status-active");
      text.textContent = `Omnitrix ML Neural Core: Online (${loadedCount} URL Models + Live DNS/SSL)`;
      return;
    }
  } catch (err) {
    console.warn("[PhishGuard] Models info endpoint error:", err);
  }

  pill.classList.add("status-error");
  text.textContent = "Omnitrix ML Core: Initialized (Fallback Mode)";
}

// =====================================================================
// 2. FORM INTERACTIONS & PRESETS
// =====================================================================
function initFormAndPresets() {
  const form = document.getElementById("url-scan-form");
  const input = document.getElementById("url-input");
  const clearBtn = document.getElementById("btn-clear-url");
  const sampleBtn = document.getElementById("btn-sample-url");

  if (input && clearBtn) {
    input.addEventListener("input", () => {
      clearBtn.style.display = input.value.trim() ? "block" : "none";
    });
    clearBtn.addEventListener("click", () => {
      input.value = "";
      clearBtn.style.display = "none";
      input.focus();
    });
  }

  if (sampleBtn && input) {
    sampleBtn.addEventListener("click", () => {
      input.value = "http://paypa1-secure.login.verify.xyz/account?ref=session_8f3a";
      if (clearBtn) clearBtn.style.display = "block";
      runUrlScan(input.value.trim());
    });
  }

  // Preset chips
  document.querySelectorAll(".preset-chip[data-url]").forEach((chip) => {
    chip.addEventListener("click", () => {
      const url = chip.getAttribute("data-url");
      if (input && url) {
        input.value = url;
        if (clearBtn) clearBtn.style.display = "block";
        runUrlScan(url);
      }
    });
  });

  if (form) {
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const url = input.value.trim();
      if (url) {
        runUrlScan(url);
      }
    });
  }
}

// =====================================================================
// 3. RUN URL SCAN & SCANNING ANIMATION
// =====================================================================
async function runUrlScan(targetUrl) {
  const scanningBox = document.getElementById("phish-scanning-box");
  const emptyState = document.getElementById("phish-empty-state");
  const outputContainer = document.getElementById("url-output");
  const errorEl = document.getElementById("url-scan-error");

  if (errorEl) {
    errorEl.hidden = true;
    errorEl.textContent = "";
  }

  // Show scanning state
  if (emptyState) emptyState.style.display = "none";
  if (outputContainer) outputContainer.style.display = "none";
  if (scanningBox) {
    scanningBox.style.display = "flex";
    scanningBox.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  // Progressive telemetry step simulation for high-tech feeling
  const steps = ["step-lexical", "step-typo", "step-ml", "step-net", "step-ai"];
  steps.forEach((s) => {
    const el = document.getElementById(s);
    if (el) el.classList.remove("step-active", "step-done");
  });

  let stepIdx = 0;
  const stepInterval = setInterval(() => {
    if (stepIdx < steps.length) {
      const current = document.getElementById(steps[stepIdx]);
      if (current) current.classList.add("step-active");
      if (stepIdx > 0) {
        const prev = document.getElementById(steps[stepIdx - 1]);
        if (prev) {
          prev.classList.remove("step-active");
          prev.classList.add("step-done");
        }
      }
      stepIdx++;
    }
  }, 220);

  try {
    const response = await fetch("/api/analyze-url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: targetUrl }),
    });

    clearInterval(stepInterval);
    steps.forEach((s) => {
      const el = document.getElementById(s);
      if (el) {
        el.classList.remove("step-active");
        el.classList.add("step-done");
      }
    });

    if (!response.ok) {
      throw new Error(`Server returned HTTP ${response.status}`);
    }

    const data = await response.json();

    // Render results
    setTimeout(() => {
      if (scanningBox) scanningBox.style.display = "none";
      renderUrlAnalysis(targetUrl, data);
      initUrlHistory(); // Refresh history log table
    }, 400);

  } catch (err) {
    clearInterval(stepInterval);
    if (scanningBox) scanningBox.style.display = "none";
    if (emptyState) emptyState.style.display = "block";
    if (errorEl) {
      errorEl.hidden = false;
      errorEl.textContent = `Omnitrix Scanner Error: ${err.message}. Please check connection or target URL syntax.`;
    }
  }
}

// =====================================================================
// 4. RENDER ANALYSIS RESULTS IN OMNITRIX THEME
// =====================================================================
function renderUrlAnalysis(inputUrl, data) {
  const container = document.getElementById("url-output");
  if (!container) return;

  const {
    url,
    normalized_url,
    hostname,
    overall_threat_level: level,
    threat_score: score,
    consensus,
    models,
    typosquatting,
    dns_check,
    ssl_check,
    flags,
    features,
    ai_intelligence
  } = data;

  // Level configuration
  const levelLabels = {
    safe: "CLEAN &amp; VERIFIED",
    suspicious: "SUSPICIOUS THREAT",
    dangerous: "HIGH DANGER",
    critical: "CRITICAL THREAT"
  };

  const levelBadges = {
    safe: "badge-low",
    suspicious: "badge-medium",
    dangerous: "badge-high",
    critical: "badge-critical"
  };

  const badgeClass = levelBadges[level] || "badge-low";
  const labelText = levelLabels[level] || "UNKNOWN";
  const displayUrl = normalized_url || url || inputUrl;

  let parsed;
  try {
    parsed = new URL(displayUrl);
  } catch {
    parsed = null;
  }

  let html = "";

  // 1. HERO VERDICT BANNER
  html += `
  <div class="verdict-hero-card verdict-${level}">
    <div class="verdict-hero-left">
      <div class="verdict-omnitrix-dial">
        <div class="verdict-dial-bezel"></div>
        <div class="verdict-dial-core">
          <svg viewBox="0 0 100 100">
            <polygon points="15,15 85,15 50,47" />
            <polygon points="15,85 85,85 50,53" />
          </svg>
        </div>
      </div>
      <div class="verdict-hero-info">
        <div class="verdict-hero-tagline">
          <span class="badge ${badgeClass}">${labelText}</span>
          <span class="consensus-pill-tag">
            ${consensus?.flagged_by_any ? `Flagged by ${consensus.flagged_count} of ${consensus.total_models} ML Models` : `Consensus: Clean by All ${consensus?.total_models || 3} ML Models`}
          </span>
        </div>
        <h2 class="verdict-hostname">${escapeHtml(hostname || url)}</h2>
        <div class="verdict-url-row">
          <code class="verdict-code">${escapeHtml(displayUrl)}</code>
          <button type="button" class="btn-copy-tag" onclick="window.CAEMP_COPY('${escapeAttr(displayUrl)}', 'Target URL copied')">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none"><rect x="9" y="9" width="13" height="13" rx="2" stroke="currentColor" stroke-width="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" stroke="currentColor" stroke-width="2"/></svg>
            Copy
          </button>
        </div>
      </div>
    </div>

    <div class="verdict-hero-score">
      <div class="score-number-display">${score}</div>
      <div class="score-max-sub">/ 100 THREAT SCORE</div>
      <div class="score-progress-bar">
        <div class="score-progress-fill" style="width: ${score}%;"></div>
      </div>
    </div>
  </div>`;

  // 2. DECEPTIVE BRAND LOOKALIKE / TYPOSQUATTING ALERT
  if (typosquatting && typosquatting.is_typosquat) {
    html += `
    <div class="typosquat-omnitrix-card">
      <div class="typosquat-header">
        <div class="typosquat-title">
          <span class="alert-pulse-icon">&#9888;&#65039;</span>
          <span>Deceptive Brand Impersonation &middot; Typosquatting Attack Detected</span>
        </div>
        <span class="badge badge-critical">BRAND CLONE SPOOF</span>
      </div>
      <div class="typosquat-body">
        <p class="typosquat-desc">
          This domain (<strong class="target-highlight">${escapeHtml(hostname || url)}</strong>) uses character spoofing to mimic the authoritative brand <strong class="brand-highlight">${escapeHtml(typosquatting.brand)}</strong>.
        </p>
        <div class="typosquat-comparison-strip">
          <div class="typo-box suspicious-box">
            <span class="typo-box-label">SUSPICIOUS INPUT HOSTNAME</span>
            <code>${escapeHtml(hostname || url)}</code>
          </div>
          <div class="typo-arrow">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
          </div>
          <div class="typo-box legitimate-box">
            <span class="typo-box-label">AUTHENTIC BRAND DOMAIN</span>
            <a href="https://${escapeHtml(typosquatting.legitimate_domain)}" target="_blank" rel="noopener noreferrer">
              <strong>https://${escapeHtml(typosquatting.legitimate_domain)}</strong> &#8599;
            </a>
          </div>
        </div>
        <div class="typosquat-meta-strip">
          <div class="meta-item"><strong>Attack Method:</strong> ${escapeHtml(typosquatting.technique || "Character Substitution")}</div>
          <div class="meta-item"><strong>Impersonation Confidence:</strong> ${typosquatting.confidence || 98}%</div>
        </div>
      </div>
    </div>`;
  }

  // 3. MULTI-MODEL ML CONSENSUS BREAKDOWN (TRIO)
  if (models && Object.keys(models).length > 0) {
    html += `
    <div class="section-title-strip" style="margin-top:28px;">
      <span class="omnitrix-glyph">&#9670;</span>
      <h3>Multi-Model Neural Consensus Engine Breakdown</h3>
    </div>
    <div class="models-trio-grid">`;

    for (const [key, m] of Object.entries(models)) {
      const isSus = m.is_suspicious;
      const mBadge = isSus ? "badge-critical" : "badge-low";
      const mText = isSus ? "THREAT DETECTED" : "VERIFIED CLEAN";

      html += `
      <div class="model-omni-card ${isSus ? 'model-flagged' : 'model-clean'}">
        <div class="model-card-top">
          <div>
            <h4 class="model-name">${escapeHtml(m.name)}</h4>
            <span class="model-type-sub">${escapeHtml(m.type)}</span>
          </div>
          <span class="badge ${mBadge}">${mText}</span>
        </div>

        <div class="model-meter-wrap">
          <div class="meter-labels">
            <span>Threat Probability</span>
            <strong class="meter-val">${m.threat_score}%</strong>
          </div>
          <div class="meter-track">
            <div class="meter-fill ${isSus ? 'meter-high' : 'meter-low'}" style="width: ${m.threat_score}%;"></div>
          </div>
        </div>

        ${m.key_signals && m.key_signals.length > 0 ? `
        <div class="model-signals-list">
          <span class="signals-label">Detected Model Signals:</span>
          <ul>
            ${m.key_signals.map(s => `<li>${escapeHtml(s)}</li>`).join("")}
          </ul>
        </div>` : ""}
      </div>`;
    }
    html += `</div>`;
  }

  // 4. LIVE TELEMETRY: DNS & SSL VERIFICATIONS
  html += `
  <div class="section-title-strip" style="margin-top:28px;">
    <span class="omnitrix-glyph">&#9670;</span>
    <h3>Live Host &amp; Cryptographic Telemetry</h3>
  </div>
  <div class="telemetry-twin-grid">`;

  // DNS Card
  const dnsOk = dns_check?.resolved;
  html += `
    <div class="telemetry-omni-card ${dnsOk ? 'tele-pass' : 'tele-fail'}">
      <div class="telemetry-icon-box">
        ${dnsOk ? `
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--omnitrix-green)" stroke-width="2.2"><path d="M20 6 9 17l-5-5"/></svg>
        ` : `
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--omnitrix-red)" stroke-width="2.2"><path d="M18 6 6 18M6 6l12 12"/></svg>
        `}
      </div>
      <div class="telemetry-details">
        <div class="telemetry-header-row">
          <h4 class="telemetry-title">Live DNS Resolution &amp; Host Reachability</h4>
          <span class="badge ${dnsOk ? 'badge-low' : 'badge-critical'}">${dnsOk ? 'REACHABLE' : 'UNRESOLVED'}</span>
        </div>
        <p class="telemetry-sub">${escapeHtml(dns_check?.message || "DNS verification executed")}</p>
        <div class="telemetry-prop">
          <span>Resolved IP:</span>
          <code>${escapeHtml(dns_check?.ip || "NXDOMAIN / Host Offline")}</code>
        </div>
      </div>
    </div>`;

  // SSL Card
  const sslOk = ssl_check?.has_ssl && ssl_check?.valid;
  html += `
    <div class="telemetry-omni-card ${sslOk ? 'tele-pass' : 'tele-fail'}">
      <div class="telemetry-icon-box">
        ${sslOk ? `
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--omnitrix-green)" stroke-width="2.2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        ` : `
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--omnitrix-amber)" stroke-width="2.2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>
        `}
      </div>
      <div class="telemetry-details">
        <div class="telemetry-header-row">
          <h4 class="telemetry-title">Live Port 443 SSL / TLS Cryptography</h4>
          <span class="badge ${sslOk ? 'badge-low' : 'badge-medium'}">${sslOk ? 'ACTIVE &amp; VALID' : (ssl_check?.has_ssl ? 'CERT ISSUE' : 'NO SSL')}</span>
        </div>
        <p class="telemetry-sub">${escapeHtml(ssl_check?.message || (sslOk ? 'Active HTTPS Encryption' : 'No Valid SSL Certificate'))}</p>
        <div class="telemetry-prop">
          <span>Cipher / Issuer:</span>
          <code>${ssl_check?.protocol ? `${ssl_check.protocol} &bull; ${escapeHtml(ssl_check.issuer || 'Secure')}` : (ssl_check?.has_ssl ? 'SSL Present' : 'Port 443 Closed')}</code>
        </div>
      </div>
    </div>
  </div>`;

  // 5. HEURISTICS & STRUCTURAL INSPECTION GRID (6 ITEMS)
  const hasHttps = (ssl_check && ssl_check.has_ssl) || (features && features.has_https === 1) || parsed?.protocol === "https:";
  let sslDetail = "Unencrypted — plain HTTP";
  if (ssl_check && ssl_check.has_ssl) {
    sslDetail = `Secure (${ssl_check.protocol || "TLS"} &bull; ${ssl_check.issuer || "Valid SSL"})`;
  } else if (hasHttps) {
    sslDetail = "Secure connection (HTTPS)";
  }

  const checks = [
    { label: "HTTPS Encryption", pass: hasHttps, detail: sslDetail },
    { label: "Domain TLD Risk", pass: features ? features.is_suspicious_tld === 0 : true, detail: parsed ? `TLD: .${parsed.hostname.split(".").pop()}` : "Normal TLD" },
    { label: "IP Address Check", pass: features ? features.is_ip === 0 : true, detail: features?.is_ip ? "Uses numeric IP" : "Uses registered FQDN" },
    { label: "URL Shortener Mask", pass: features ? features.is_shortener === 0 : true, detail: features?.is_shortener ? "Known cloaking shortener" : "Direct domain" },
    { label: "Subdomain Nesting", pass: features ? features.subdomain_count < 3 : true, detail: features ? `${features.subdomain_count} level(s)` : "Standard" },
    { label: "Phishing Keywords", pass: features ? features.phishing_keyword_count === 0 : true, detail: features ? `${features.phishing_keyword_count} sensitive token(s)` : "None found" },
  ];

  html += `
  <div class="section-title-strip" style="margin-top:28px;">
    <span class="omnitrix-glyph">&#9670;</span>
    <h3>Structural &amp; Lexical Inspection Checklist</h3>
  </div>
  <div class="heuristics-omni-grid">
    ${checks.map(c => `
      <div class="heuristic-omni-item ${c.pass ? 'pass' : 'flagged'}">
        <div class="item-icon-indicator">${c.pass ? '&#10003;' : '!'}</div>
        <div class="item-text">
          <div class="item-label">${c.label}</div>
          <div class="item-detail">${c.detail}</div>
        </div>
      </div>
    `).join("")}
  </div>`;

  // 6. CHARACTER & HOMOGLYPH MATRIX
  if (parsed && parsed.hostname) {
    html += `
    <div class="card" style="margin-top:28px;">
      <div class="card-header" style="border-bottom:1px solid var(--border-subtle); padding-bottom:12px; margin-bottom:16px;">
        <span class="card-title" style="font-family:var(--font-display); font-size:13px; color:var(--text-main);">
          Character Unicode &amp; Homoglyph Spoof Matrix &middot; ${escapeHtml(parsed.hostname)}
        </span>
      </div>
      <div class="table-container" style="max-height:260px; overflow-y:auto;">
        <table class="data-table" style="font-size:12.5px;">
          <thead>
            <tr>
              <th style="width:100px;">Char</th>
              <th style="width:150px;">Unicode Hex</th>
              <th>Heuristic Analysis</th>
            </tr>
          </thead>
          <tbody>`;

    for (const char of parsed.hostname) {
      const spoof = HOMOGLYPH_MAP[char];
      html += `
        <tr>
          <td style="font-size:15px; font-weight:700; ${spoof ? 'color:var(--omnitrix-red); text-shadow:0 0 8px rgba(255,23,68,0.6);' : 'color:var(--omnitrix-green);'}">${escapeHtml(char)}</td>
          <td class="mono">U+${char.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}</td>
          <td>${spoof ? `<span class="badge badge-critical">SPOOFED</span> Visual duplicate for Latin letter "<strong>${spoof}</strong>"` : '<span class="dim">&#10003; Standard alphanumeric glyph</span>'}</td>
        </tr>`;
    }

    html += `
          </tbody>
        </table>
      </div>
    </div>`;
  }

  // 7. SECURITY RED FLAG FINDINGS
  if (flags && flags.length > 0) {
    html += `
    <div class="section-title-strip" style="margin-top:28px;">
      <span class="omnitrix-glyph">&#9670;</span>
      <h3>Security Threat Findings (${flags.length})</h3>
    </div>
    <div class="findings-stack">`;

    flags.forEach((f) => {
      const sevBadge = levelBadges[f.severity] || "badge-medium";
      html += `
      <div class="finding-omni-card finding-${f.severity}">
        <div class="finding-icon-wrap">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        </div>
        <div class="finding-content">
          <div class="finding-top-row">
            <h4 class="finding-title">${escapeHtml(f.title)}</h4>
            <span class="badge ${sevBadge}">${(f.severity || "MEDIUM").toUpperCase()}</span>
          </div>
          <p class="finding-desc">${escapeHtml(f.description)}</p>
        </div>
      </div>`;
    });

    html += `</div>`;
  }

  // 8. OMNITRIX AI THREAT INTELLIGENCE TERMINAL
  if (ai_intelligence) {
    html += `
    <div class="ai-intel-omni-card" style="margin-top:28px;">
      <div class="ai-intel-header">
        <div class="ai-intel-title">
          <span class="status-dot pulse" style="background:var(--omnitrix-green);"></span>
          Omnitrix AI Defensive Threat Advisory
        </div>
        <span class="ai-engine-tag">${escapeHtml(ai_intelligence.engine || "Level-20 Neural Agent")}</span>
      </div>
      <div class="ai-intel-body" id="ai-intel-text-container">
        <p class="ai-intel-paragraph">${escapeHtml(ai_intelligence.explanation || "")}</p>
        ${ai_intelligence.recommendations && ai_intelligence.recommendations.length > 0 ? `
        <div class="ai-recommendations-list">
          <div class="rec-headline">// RECOMMENDED DEFENSIVE COUNTERMEASURES:</div>
          ${ai_intelligence.recommendations.map(r => `
            <div class="rec-item">
              <span class="rec-bullet">&#9670;</span>
              <span>${escapeHtml(r)}</span>
            </div>
          `).join("")}
        </div>` : ""}
      </div>
    </div>`;
  }

  container.innerHTML = html;
  container.style.display = "block";
  container.scrollIntoView({ behavior: "smooth", block: "start" });
}

// =====================================================================
// 5. URL SCAN HISTORY LOG (PERSISTENT SQLITE)
// =====================================================================
async function initUrlHistory() {
  const tbody = document.getElementById("url-history-body");
  const refreshBtn = document.getElementById("btn-refresh-history");
  const clearBtn = document.getElementById("btn-clear-history");

  if (refreshBtn) {
    refreshBtn.onclick = () => initUrlHistory();
  }

  if (clearBtn) {
    clearBtn.onclick = async () => {
      if (confirm("Are you sure you want to clear all URL scan history from the database?")) {
        try {
          await fetch("/api/clear-url-history", { method: "POST" });
          initUrlHistory();
          if (window.CAEMP_TOAST) window.CAEMP_TOAST("URL threat history cleared");
        } catch (e) {
          console.error(e);
        }
      }
    };
  }

  if (!tbody) return;

  try {
    const res = await fetch("/api/url-history");
    if (!res.ok) throw new Error("Failed to fetch history");
    const rows = await res.json();

    if (!rows || rows.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align:center; padding:28px; color:var(--text-dim);">
            No recorded URL scans found. Inspect a target URL above to populate telemetry.
          </td>
        </tr>`;
      return;
    }

    const levelBadges = {
      safe: "badge-low",
      suspicious: "badge-medium",
      dangerous: "badge-high",
      critical: "badge-critical"
    };

    tbody.innerHTML = rows.map((r) => {
      const badge = levelBadges[r.threat_level] || "badge-low";
      return `
        <tr>
          <td class="mono" style="font-size:12px; color:var(--text-muted);">${escapeHtml(r.scan_date || "")}</td>
          <td>
            <div style="max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeAttr(r.url || "")}">
              <code class="mono" style="color:var(--text-main); font-size:12px;">${escapeHtml(r.url || "")}</code>
            </div>
          </td>
          <td class="mono" style="font-size:12px; color:var(--text-muted);">${escapeHtml(r.hostname || "")}</td>
          <td>
            <span class="mono" style="font-weight:700; color:${r.threat_score >= 70 ? 'var(--omnitrix-red)' : (r.threat_score >= 45 ? 'var(--omnitrix-amber)' : 'var(--omnitrix-green)')};">
              ${r.threat_score}/100
            </span>
          </td>
          <td>
            <span class="badge ${badge}">${(r.threat_level || "SAFE").toUpperCase()}</span>
            ${r.is_typosquat ? '<span class="badge badge-critical" style="margin-left:4px;">SPOOF</span>' : ''}
          </td>
          <td class="mono" style="font-size:12px; color:var(--text-muted);">${r.flagged_count || 0} / ${r.total_models || 3}</td>
          <td>
            <button type="button" class="btn-table-action" onclick="reInspectUrl('${escapeAttr(r.url)}')">
              Re-Scan
            </button>
          </td>
        </tr>`;
    }).join("");

  } catch (err) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align:center; padding:24px; color:var(--omnitrix-red);">
          Error loading history: ${err.message}
        </td>
      </tr>`;
  }
}

window.reInspectUrl = function(targetUrl) {
  const input = document.getElementById("url-input");
  const clearBtn = document.getElementById("btn-clear-url");
  if (input && targetUrl) {
    input.value = targetUrl;
    if (clearBtn) clearBtn.style.display = "block";
    runUrlScan(targetUrl);
  }
};

// Utilities
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function escapeAttr(str) {
  if (!str) return "";
  return String(str).replace(/"/g, "&quot;").replace(/'/g, "\\'");
}
