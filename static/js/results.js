(function () {
  const COLORS = window.CAEMP_SEVERITY_COLORS || {
    Critical: "#FF1744", High: "#FFAB00", Medium: "#FFD600", Low: "#00FF41", Info: "#00E5FF",
  };

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str == null ? "" : str;
    return div.innerHTML;
  }

  // --- Omnitrix Threat Dial Animation ---
  const gaugeFill = document.getElementById("gauge-fill");
  if (gaugeFill) {
    const score = parseFloat(gaugeFill.dataset.score || "0");
    const pct = Math.max(0, Math.min(100, score));
    const circumference = 314; // 2 * PI * 50
    const offset = circumference - (pct / 100) * circumference;

    let color = "#00FF41";
    if (score >= 70) color = "#FF1744";
    else if (score >= 30) color = "#FFD600";

    requestAnimationFrame(() => {
      gaugeFill.style.stroke = color;
      gaugeFill.style.strokeDashoffset = offset;
    });
  }

  const scanUid = window.SCAN_UID;
  const exposureGrid = document.getElementById("exposure-grid");

  // --- Galvan Baseline Drift Panel ---
  function renderExposure(data) {
    const { new_ports, removed_ports, changed_services } = data;
    const hasChanges = (new_ports && new_ports.length) ||
                       (removed_ports && removed_ports.length) ||
                       (changed_services && changed_services.length);

    const driftEl = document.getElementById("exec-drift-value");
    if (driftEl) {
      driftEl.textContent = hasChanges ? "DRIFT MUTATION DETECTED" : "BASELINE STABILIZED";
      driftEl.style.color = hasChanges ? "var(--omnitrix-amber)" : "var(--omnitrix-green)";
    }

    if (!hasChanges) {
      exposureGrid.innerHTML = `<div class="exposure-empty">✓ No baseline attack surface divergence registered since preceding scan</div>`;
      return;
    }

    let html = "";

    if (new_ports && new_ports.length) {
      html += `
        <div class="exposure-card new">
          <h4>● NEWLY EXPOSED DAEMONS</h4>
          <ul>${new_ports.map(p => `<li>Port ${p.port} &mdash; ${escapeHtml(p.service)}</li>`).join("")}</ul>
        </div>`;
    }

    if (removed_ports && removed_ports.length) {
      html += `
        <div class="exposure-card removed">
          <h4>● TERMINATED / CLOSED PORTS</h4>
          <ul>${removed_ports.map(p => `<li>Port ${p.port} &mdash; ${escapeHtml(p.service)}</li>`).join("")}</ul>
        </div>`;
    }

    if (changed_services && changed_services.length) {
      html += `
        <div class="exposure-card changed">
          <h4>● SERVICE / VERSION MUTATIONS</h4>
          <ul>${changed_services.map(c => `<li>Port ${c.port}: ${escapeHtml(c.old)} &rarr; ${escapeHtml(c.new)}</li>`).join("")}</ul>
        </div>`;
    }

    exposureGrid.innerHTML = html;
  }

  let findingsData = [];

  if (scanUid && exposureGrid) {
    fetch(`/api/scan/${scanUid}`)
      .then((r) => r.json())
      .then((data) => {
        renderExposure(data);
        findingsData = data.findings || [];
        renderSeverityChart(findingsData);
        renderServicesChart(findingsData);
        renderRecommendations(findingsData);
      })
      .catch(() => {
        exposureGrid.innerHTML = `<div class="exposure-empty">Unable to query exposure baseline data.</div>`;
      });
  }

  // --- CVE Table Loading ---
  const cveBody = document.getElementById("cve-table-body");
  if (scanUid && cveBody) {
    fetch(`/api/cves/${scanUid}`)
      .then((r) => r.json())
      .then((cves) => {
        if (!cves.length) {
          cveBody.innerHTML = `<tr><td colspan="6" class="empty-row">No active CVE vulnerability signatures matched for detected service daemons.</td></tr>`;
          return;
        }
        cveBody.innerHTML = cves.map((c) => {
          const score = c.cvss_score || 0;
          let sevLabel = "Low", sevClass = "badge-low";
          if (score >= 9) { sevLabel = "Critical"; sevClass = "badge-critical"; }
          else if (score >= 7) { sevLabel = "High"; sevClass = "badge-high"; }
          else if (score >= 4) { sevLabel = "Medium"; sevClass = "badge-medium"; }

          return `
            <tr>
              <td data-label="CVE ID" class="mono">
                <span style="color:var(--omnitrix-green); font-weight:700;">${escapeHtml(c.cve_id)}</span>
                <button type="button" class="copy-btn" onclick="window.CAEMP_COPY('${escapeHtml(c.cve_id)}', 'CVE ID copied')" title="Copy CVE ID">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none"><rect x="9" y="9" width="13" height="13" rx="2" stroke="currentColor" stroke-width="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" stroke="currentColor" stroke-width="2"/></svg>
                </button>
              </td>
              <td data-label="CVSS"><span class="mono" style="font-weight:800;">${score.toFixed(1)}</span></td>
              <td data-label="Severity"><span class="badge ${sevClass}">${sevLabel}</span></td>
              <td data-label="Service" class="mono">${escapeHtml(c.service)}:${c.port}</td>
              <td data-label="Description" style="font-size:12.5px; line-height:1.45; color:var(--text-muted);">${escapeHtml(c.description || "No CVE description cataloged.")}</td>
              <td data-label="NVD">
                <a class="row-link" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.cve_id)}" target="_blank" rel="noopener">
                  NVD Ref &rarr;
                </a>
              </td>
            </tr>`;
        }).join("");
      })
      .catch(() => {
        cveBody.innerHTML = `<tr><td colspan="6" class="empty-row">Error querying NIST NVD correlation engine.</td></tr>`;
      });
  }

  // --- Severity Distribution Chart ---
  function renderSeverityChart(findings) {
    const counts = {};
    findings.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
    const order = ["Critical", "High", "Medium", "Low", "Info"];
    const labels = order.filter((k) => counts[k]);
    const values = labels.map((k) => counts[k]);
    const colors = labels.map((k) => COLORS[k] || "#00FF41");

    const legendEl = document.getElementById("severity-legend");
    const canvas = document.getElementById("chart-severity");
    if (!labels.length || !canvas) {
      if (legendEl) legendEl.innerHTML = "";
      if (canvas) canvas.parentElement.innerHTML = `<div class="empty-state">No exposure findings recorded.</div>`;
      return;
    }
    if (legendEl) {
      legendEl.innerHTML = labels.map((l, i) => `
        <span class="chart-legend-item">
          <span class="chart-legend-dot" style="background:${colors[i]}; box-shadow:0 0 8px ${colors[i]};"></span>
          ${l}: <strong style="color:#fff;">${values[i]}</strong>
        </span>
      `).join("");
    }

    new Chart(canvas.getContext("2d"), {
      type: "doughnut",
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: colors,
          borderColor: "#080D14",
          borderWidth: 3,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "70%",
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "rgba(8, 13, 20, 0.95)",
            titleFont: { family: "'Orbitron', sans-serif", size: 12 },
            bodyFont: { family: "'JetBrains Mono', monospace", size: 12 },
            borderColor: "rgba(0, 255, 65, 0.4)",
            borderWidth: 1,
            padding: 10,
          },
        },
      },
    });
  }

  // --- Open Port Distribution Chart ---
  function renderServicesChart(findings) {
    const counts = {};
    findings.forEach((f) => { counts[f.service] = (counts[f.service] || 0) + 1; });
    const labels = Object.keys(counts);
    const values = Object.values(counts);
    const canvas = document.getElementById("chart-services");
    if (!labels.length || !canvas) {
      if (canvas) canvas.parentElement.innerHTML = `<div class="empty-state">No active daemons cataloged.</div>`;
      return;
    }
    new Chart(canvas.getContext("2d"), {
      type: "bar",
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: "rgba(0, 255, 65, 0.75)",
          borderColor: "#00FF41",
          borderWidth: 1,
          borderRadius: 4,
          maxBarThickness: 28,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "rgba(8, 13, 20, 0.95)",
            titleFont: { family: "'Orbitron', sans-serif", size: 12 },
            bodyFont: { family: "'JetBrains Mono', monospace", size: 12 },
            borderColor: "rgba(0, 255, 65, 0.4)",
            borderWidth: 1,
            padding: 10,
          },
        },
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              precision: 0,
              color: "#546578",
              font: { family: "'JetBrains Mono', monospace", size: 11 },
            },
            grid: { color: "rgba(255, 255, 255, 0.06)" },
          },
          x: {
            grid: { display: false },
            ticks: {
              color: "#546578",
              font: { family: "'JetBrains Mono', monospace", size: 11 },
            },
          },
        },
      },
    });
  }

  // --- Galvanic Security Directives ---
  function renderRecommendations(findings) {
    const list = document.getElementById("recommendation-list");
    if (!list) return;

    const bySeverity = { Critical: [], High: [], Medium: [] };
    findings.forEach((f) => { if (bySeverity[f.severity]) bySeverity[f.severity].push(f); });

    const recs = [];

    if (bySeverity.Critical.length) {
      recs.push({
        icon: "!", color: "var(--omnitrix-red)", bg: "var(--omnitrix-red-soft)",
        title: "Initiate Immediate Galvanic Lockdown on Critical Exposures",
        text: `${bySeverity.Critical.length} critical service exposure(s) detected (${bySeverity.Critical.map(f => f.service).join(", ")}). Place behind strict firewall rules, isolate network segment, or patch daemon versions within 24 hours.`,
      });
    }
    if (bySeverity.High.length) {
      recs.push({
        icon: "▲", color: "var(--omnitrix-amber)", bg: "var(--omnitrix-amber-soft)",
        title: "Harden Exposed Daemons and Enforce Cryptographic Authentication",
        text: `${bySeverity.High.length} high-severity daemon(s) are reachable across perimeter. Restrict listening interfaces, enable TLS encryption, and disable default service credentials.`,
      });
    }
    if (bySeverity.Medium.length) {
      recs.push({
        icon: "i", color: "var(--omnitrix-amber)", bg: "rgba(255, 214, 0, 0.08)",
        title: "Review Medium-Risk Configuration Banners",
        text: `${bySeverity.Medium.length} medium-risk exposed daemon(s) detected. Conceal detailed software version headers and evaluate whether public port exposure is operationally justified.`,
      });
    }
    recs.push({
      icon: "✓", color: "var(--omnitrix-green)", bg: "var(--omnitrix-green-soft)",
      title: "Execute Differential Verification Calibration",
      text: "After implementing remediation and firewall adjustments, re-run reconnaissance against this host to verify that port closures register in the Omnitrix baseline.",
    });

    list.innerHTML = recs.map((r) => `
      <div class="recommendation">
        <div class="recommendation-icon" style="color:${r.color}; background:${r.bg}; border:1px solid ${r.color};">${r.icon}</div>
        <div class="recommendation-body">
          <div class="recommendation-title">${escapeHtml(r.title)}</div>
          <div class="recommendation-text">${escapeHtml(r.text)}</div>
        </div>
      </div>
    `).join("");
  }

  // --- Findings Table Search & Sorting ---
  const searchInput = document.getElementById("findings-search");
  const table = document.getElementById("findings-table");

  if (searchInput && table) {
    const tbody = table.querySelector("tbody");
    const allRows = Array.from(tbody.querySelectorAll("tr"));

    searchInput.addEventListener("input", () => {
      const q = searchInput.value.toLowerCase();
      allRows.forEach((row) => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(q) ? "" : "none";
      });
    });

    // Column sorting
    const headers = table.querySelectorAll("th[data-key]");
    let sortState = { key: null, dir: 1 };

    headers.forEach((th) => {
      th.addEventListener("click", () => {
        const key = th.dataset.key;
        sortState.dir = sortState.key === key ? sortState.dir * -1 : 1;
        sortState.key = key;

        headers.forEach((h) => (h.querySelector(".sort-arrow").textContent = ""));
        th.querySelector(".sort-arrow").textContent = sortState.dir === 1 ? "▲" : "▼";

        const colIndex = Array.from(th.parentElement.children).indexOf(th);
        const rows = Array.from(tbody.querySelectorAll("tr"));

        rows.sort((a, b) => {
          const aText = a.children[colIndex]?.textContent.trim() || "";
          const bText = b.children[colIndex]?.textContent.trim() || "";
          const aNum = parseFloat(aText);
          const bNum = parseFloat(bText);
          if (!isNaN(aNum) && !isNaN(bNum)) {
            return (aNum - bNum) * sortState.dir;
          }
          return aText.localeCompare(bText) * sortState.dir;
        });

        rows.forEach((row) => tbody.appendChild(row));
      });
    });
  }
})();
