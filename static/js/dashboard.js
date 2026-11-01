(function () {
  const COLORS = window.CAEMP_SEVERITY_COLORS || {
    Critical: "#FF1744", High: "#FFAB00", Medium: "#FFD600", Low: "#00FF41", Info: "#00E5FF",
  };

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str == null ? "" : str;
    return div.innerHTML;
  }

  function relTime(dateStr) {
    if (!dateStr || dateStr.length < 15) return dateStr;
    const y = dateStr.slice(0, 4), mo = dateStr.slice(4, 6), d = dateStr.slice(6, 8);
    const h = dateStr.slice(9, 11), mi = dateStr.slice(11, 13);
    return `${y}-${mo}-${d} ${h}:${mi}`;
  }

  function riskBadgeClass(level) {
    const l = (level || "").toLowerCase();
    if (l === "high") return "badge-critical";
    if (l === "medium") return "badge-high";
    return "badge-low";
  }

  function severityBadgeClass(sev) {
    return `badge-${(sev || "info").toLowerCase()}`;
  }

  fetch("/api/dashboard/stats")
    .then((r) => r.json())
    .then(renderDashboard)
    .catch(() => {
      document.getElementById("recent-scans-list").innerHTML =
        `<div class="empty-state">Unable to query Omnitrix telemetry.</div>`;
      document.getElementById("recent-findings-list").innerHTML =
        `<div class="empty-state">Unable to query Omnitrix telemetry.</div>`;
    });

  function renderDashboard(data) {
    // Stat grid
    document.getElementById("stat-assets").textContent = data.total_assets ?? "0";
    document.getElementById("stat-critical").textContent = data.critical_findings ?? "0";
    document.getElementById("stat-avgrisk").textContent = data.avg_risk ?? "0";
    document.getElementById("stat-scans").textContent = data.total_scans ?? "0";

    // Recent scans widget
    const scansEl = document.getElementById("recent-scans-list");
    if (!data.recent_scans || !data.recent_scans.length) {
      scansEl.innerHTML = `<div class="empty-state">No surveillance missions cataloged. Calibrate the Omnitrix above.</div>`;
    } else {
      scansEl.innerHTML = data.recent_scans.map((s) => `
        <a class="list-row" href="/scan/${s.scan_uid}" style="text-decoration:none;">
          <div class="list-row-main">
            <span class="list-row-title mono">${escapeHtml(s.target)}</span>
            <span class="list-row-meta">${relTime(s.scan_date)} &middot; ${s.open_ports} exposed daemon${s.open_ports === 1 ? "" : "s"} &middot; Threat: ${s.total_risk}</span>
          </div>
          <div class="list-row-side">
            <span class="badge ${riskBadgeClass(s.risk_level)}">${escapeHtml(s.risk_level)}</span>
          </div>
        </a>
      `).join("");
    }

    // Recent findings widget
    const findingsEl = document.getElementById("recent-findings-list");
    if (!data.recent_findings || !data.recent_findings.length) {
      findingsEl.innerHTML = `<div class="empty-state">No elevated threat vulnerabilities detected.</div>`;
    } else {
      findingsEl.innerHTML = data.recent_findings.map((f) => `
        <div class="list-row">
          <div class="list-row-main">
            <span class="list-row-title mono">${escapeHtml(f.target)}:${f.port}/${escapeHtml(f.protocol)}</span>
            <span class="list-row-meta">${escapeHtml(f.service)} &middot; ${escapeHtml(f.finding)}</span>
          </div>
          <div class="list-row-side">
            <span class="badge ${severityBadgeClass(f.severity)}">${escapeHtml(f.severity)}</span>
          </div>
        </div>
      `).join("");
    }

    renderSeverityChart(data.severity_distribution || {});
    renderRiskTrendChart(data.risk_trend || []);
  }

  function renderSeverityChart(dist) {
    const order = ["Critical", "High", "Medium", "Low", "Info"];
    const labels = order.filter((k) => dist[k]);
    const values = labels.map((k) => dist[k]);
    const colors = labels.map((k) => COLORS[k] || "#00FF41");

    const legendEl = document.getElementById("severity-legend");
    const canvas = document.getElementById("chart-severity");
    if (!canvas) return;

    if (!labels.length) {
      if (legendEl) legendEl.innerHTML = "";
      canvas.parentElement.innerHTML = `<div class="empty-state">No exposure findings recorded yet.</div>`;
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

    const ctx = canvas.getContext("2d");
    new Chart(ctx, {
      type: "doughnut",
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: colors,
          borderColor: "#080D14",
          borderWidth: 3,
          hoverOffset: 6,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "72%",
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

  function renderRiskTrendChart(trend) {
    const canvas = document.getElementById("chart-risk-trend");
    if (!canvas) return;
    const wrap = canvas.parentElement;

    if (!trend.length) {
      wrap.innerHTML = `<div class="empty-state">No chronological mission history available to chart.</div>`;
      return;
    }

    const labels = trend.map((t) => relTime(t.scan_date).slice(5, 16));
    const values = trend.map((t) => t.total_risk);

    const ctx = canvas.getContext("2d");
    const gradient = ctx.createLinearGradient(0, 0, 0, 200);
    gradient.addColorStop(0, "rgba(0, 255, 65, 0.3)");
    gradient.addColorStop(1, "rgba(0, 255, 65, 0.0)");

    new Chart(ctx, {
      type: "line",
      data: {
        labels,
        datasets: [{
          label: "Omnitrix Threat Index",
          data: values,
          borderColor: "#00FF41",
          backgroundColor: gradient,
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 4,
          pointBackgroundColor: "#00FF41",
          pointBorderColor: "#05080E",
          pointBorderWidth: 2,
          pointHoverRadius: 6,
          pointHoverBackgroundColor: "#76FF03",
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
            grid: { color: "rgba(255, 255, 255, 0.06)" },
            ticks: {
              color: "#546578",
              font: { family: "'JetBrains Mono', monospace", size: 11 },
            },
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
})();
