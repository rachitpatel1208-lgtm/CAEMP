(function () {
  const COLORS = window.CAEMP_SEVERITY_COLORS || {
    Critical: "#DC2626", High: "#EA580C", Medium: "#D97706", Low: "#16A34A", Info: "#0284C7",
  };

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str == null ? "" : str;
    return div.innerHTML;
  }

  // --- Risk gauge animation ---
  const gaugeFill = document.getElementById("gauge-fill");
  if (gaugeFill) {
    const score = parseFloat(gaugeFill.dataset.score || "0");
    const pct = Math.max(0, Math.min(100, score));
    const circumference = 314; // 2 * PI * 50
    const offset = circumference - (pct / 100) * circumference;

    let color = "#16A34A";
    if (score >= 70) color = "#DC2626";
    else if (score >= 30) color = "#D97706";

    requestAnimationFrame(() => {
      gaugeFill.style.stroke = color;
      gaugeFill.style.strokeDashoffset = offset;
    });
  }

  const scanUid = window.SCAN_UID;
  const exposureGrid = document.getElementById("exposure-grid");

  // --- Exposure changes panel (existing functionality, preserved) ---
  function renderExposure(data) {
    const { new_ports, removed_ports, changed_services } = data;
    const hasChanges = new_ports.length || removed_ports.length || changed_services.length;

    document.getElementById("exec-drift-value").textContent = hasChanges ? "Changed" : "Stable";

    if (!hasChanges) {
      exposureGrid.innerHTML = `<div class="exposure-empty">✓ No exposure changes detected</div>`;
      return;
    }

    let html = "";

    if (new_ports.length) {
      html += `
        <div class="exposure-card new">
          <h4>● New Ports Detected</h4>
          <ul>${new_ports.map(p => `<li>Port ${p.port} — ${escapeHtml(p.service)}</li>`).join("")}</ul>
        </div>`;
    }

    if (removed_ports.length) {
      html += `
        <div class="exposure-card removed">
          <h4>● Removed Ports</h4>
          <ul>${removed_ports.map(p => `<li>Port ${p.port} — ${escapeHtml(p.service)}</li>`).join("")}</ul>
        </div>`;
    }

    if (changed_services.length) {
      html += `
        <div class="exposure-card changed">
          <h4>● Service Changes Detected</h4>
          <ul>${changed_services.map(c => `<li>Port ${c.port}: ${escapeHtml(c.old)} → ${escapeHtml(c.new)}</li>`).join("")}</ul>
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
        exposureGrid.innerHTML = `<div class="exposure-empty">Unable to load exposure data.</div>`;
      });
  }

  // --- CVE table ---
  const cveBody = document.getElementById("cve-table-body");
  if (scanUid && cveBody) {
    fetch(`/api/cves/${scanUid}`)
      .then((r) => r.json())
      .then((cves) => {
        if (!cves.length) {
          cveBody.innerHTML = `<tr><td colspan="6" class="empty-row">No matching CVE records found for the detected service versions.</td></tr>`;
          return;
        }
        cveBody.innerHTML = cves.map((c) => {
          const score = c.cvss_score || 0;
          let sevLabel = "Low", sevClass = "badge-low", scoreColor = "var(--low)", scoreBg = "var(--low-soft)";
          if (score >= 9) { sevLabel = "Critical"; sevClass = "badge-critical"; scoreColor = "var(--critical)"; scoreBg = "var(--critical-soft)"; }
          else if (score >= 7) { sevLabel = "High"; sevClass = "badge-high"; scoreColor = "var(--high)"; scoreBg = "var(--high-soft)"; }
          else if (score >= 4) { sevLabel = "Medium"; sevClass = "badge-medium"; scoreColor = "var(--medium)"; scoreBg = "var(--medium-soft)"; }

          return `
            <tr>
              <td data-label="CVE ID" class="mono">${escapeHtml(c.cve_id)}</td>
              <td data-label="CVSS"><span class="cve-score" style="color:${scoreColor}; background:${scoreBg};">${score.toFixed(1)}</span></td>
              <td data-label="Severity"><span class="badge ${sevClass}">${sevLabel}</span></td>
              <td data-label="Service" class="mono">${escapeHtml(c.service)}:${c.port}</td>
              <td data-label="Description" class="cve-desc">${escapeHtml(c.description || "No description available.")}</td>
              <td data-label="NVD"><a class="nvd-link" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.cve_id)}" target="_blank" rel="noopener">View →</a></td>
            </tr>`;
        }).join("");
      })
      .catch(() => {
        cveBody.innerHTML = `<tr><td colspan="6" class="empty-row">Unable to load CVE data.</td></tr>`;
      });
  }

  // --- Severity distribution chart (this scan) ---
  function renderSeverityChart(findings) {
    const counts = {};
    findings.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
    const order = ["Critical", "High", "Medium", "Low", "Info"];
    const labels = order.filter((k) => counts[k]);
    const values = labels.map((k) => counts[k]);
    const colors = labels.map((k) => COLORS[k]);

    const legendEl = document.getElementById("severity-legend");
    const canvas = document.getElementById("chart-severity");
    if (!labels.length || !canvas) {
      if (legendEl) legendEl.innerHTML = "";
      if (canvas) canvas.parentElement.innerHTML = `<div class="empty-state">No findings to chart.</div>`;
      return;
    }
    legendEl.innerHTML = labels.map((l, i) => `
      <span class="chart-legend-item"><span class="chart-legend-dot" style="background:${colors[i]}"></span>${l} (${values[i]})</span>
    `).join("");

    new Chart(canvas.getContext("2d"), {
      type: "doughnut",
      data: { labels, datasets: [{ data: values, backgroundColor: colors, borderWidth: 0 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: "68%", plugins: { legend: { display: false } } },
    });
  }

  // --- Open port / service distribution chart ---
  function renderServicesChart(findings) {
    const counts = {};
    findings.forEach((f) => { counts[f.service] = (counts[f.service] || 0) + 1; });
    const labels = Object.keys(counts);
    const values = Object.values(counts);
    const canvas = document.getElementById("chart-services");
    if (!labels.length || !canvas) {
      if (canvas) canvas.parentElement.innerHTML = `<div class="empty-state">No open ports to chart.</div>`;
      return;
    }
    new Chart(canvas.getContext("2d"), {
      type: "bar",
      data: { labels, datasets: [{ data: values, backgroundColor: "#2563EB", borderRadius: 5, maxBarThickness: 28 }] },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: "#E2E8F0" } }, x: { grid: { display: false } } },
      },
    });
  }

  // --- Security recommendations, derived from this scan's findings ---
  function renderRecommendations(findings) {
    const list = document.getElementById("recommendation-list");
    if (!list) return;

    const bySeverity = { Critical: [], High: [], Medium: [] };
    findings.forEach((f) => { if (bySeverity[f.severity]) bySeverity[f.severity].push(f); });

    const recs = [];

    if (bySeverity.Critical.length) {
      recs.push({
        icon: "!", color: "var(--critical)", bg: "var(--critical-soft)",
        title: "Remediate critical exposures immediately",
        text: `${bySeverity.Critical.length} critical finding(s) detected, including ${bySeverity.Critical.map(f => f.service).join(", ")}. These should be patched, disabled, or firewalled within 24–48 hours.`,
      });
    }
    if (bySeverity.High.length) {
      recs.push({
        icon: "▲", color: "var(--high)", bg: "var(--high-soft)",
        title: "Prioritize high-severity services",
        text: `${bySeverity.High.length} high-severity service(s) are internet-reachable. Review access control lists and apply available patches.`,
      });
    }
    if (bySeverity.Medium.length) {
      recs.push({
        icon: "i", color: "var(--medium)", bg: "var(--medium-soft)",
        title: "Review medium-risk configuration",
        text: `${bySeverity.Medium.length} medium-risk service(s) found. Confirm these are intentionally exposed and hardened per vendor guidance.`,
      });
    }
    recs.push({
      icon: "✓", color: "var(--accent)", bg: "var(--accent-soft)",
      title: "Re-scan after remediation",
      text: "Run a follow-up scan after applying fixes to confirm exposure has been reduced and to update the baseline used for drift detection.",
    });

    list.innerHTML = recs.map((r) => `
      <div class="recommendation">
        <div class="recommendation-icon" style="color:${r.color}; background:${r.bg};">${r.icon}</div>
        <div class="recommendation-body">
          <div class="recommendation-title">${escapeHtml(r.title)}</div>
          <div class="recommendation-text">${escapeHtml(r.text)}</div>
        </div>
      </div>
    `).join("");
  }

  // --- Findings table: search ---
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

    // --- Sorting ---
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
