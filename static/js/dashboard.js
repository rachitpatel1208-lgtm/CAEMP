(function () {
  const COLORS = window.CAEMP_SEVERITY_COLORS || {
    Critical: "#DC2626", High: "#EA580C", Medium: "#D97706", Low: "#16A34A", Info: "#0284C7",
  };

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str == null ? "" : str;
    return div.innerHTML;
  }

  function relTime(dateStr) {
    // scan_date stored as "%Y%m%d_%H%M%S"
    if (!dateStr || dateStr.length < 15) return dateStr;
    const y = dateStr.slice(0, 4), mo = dateStr.slice(4, 6), d = dateStr.slice(6, 8);
    const h = dateStr.slice(9, 11), mi = dateStr.slice(11, 13);
    return `${y}-${mo}-${d} ${h}:${mi}`;
  }

  function riskBadgeClass(level) {
    const l = (level || "").toLowerCase();
    if (l === "high") return "badge-critical";
    if (l === "medium") return "badge-medium";
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
        `<div class="empty-state">Unable to load dashboard data.</div>`;
      document.getElementById("recent-findings-list").innerHTML =
        `<div class="empty-state">Unable to load dashboard data.</div>`;
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
      scansEl.innerHTML = `<div class="empty-state">No scans yet. Run your first scan above to populate this dashboard.</div>`;
    } else {
      scansEl.innerHTML = data.recent_scans.map((s) => `
        <a class="list-row" href="/scan/${s.scan_uid}" style="text-decoration:none;">
          <div class="list-row-main">
            <span class="list-row-title mono">${escapeHtml(s.target)}</span>
            <span class="list-row-meta">${relTime(s.scan_date)} &middot; ${s.open_ports} open port${s.open_ports === 1 ? "" : "s"}</span>
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
      findingsEl.innerHTML = `<div class="empty-state">No critical or high severity findings detected yet.</div>`;
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
    const colors = labels.map((k) => COLORS[k]);

    const legendEl = document.getElementById("severity-legend");
    if (!labels.length) {
      legendEl.innerHTML = "";
      document.getElementById("chart-severity").parentElement.innerHTML =
        `<div class="empty-state">No findings recorded yet.</div>`;
      return;
    }

    legendEl.innerHTML = labels.map((l, i) => `
      <span class="chart-legend-item">
        <span class="chart-legend-dot" style="background:${colors[i]}"></span>${l} (${values[i]})
      </span>
    `).join("");

    const ctx = document.getElementById("chart-severity").getContext("2d");
    new Chart(ctx, {
      type: "doughnut",
      data: {
        labels,
        datasets: [{ data: values, backgroundColor: colors, borderWidth: 0 }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "68%",
        plugins: { legend: { display: false } },
      },
    });
  }

  function renderRiskTrendChart(trend) {
    const wrap = document.getElementById("chart-risk-trend").parentElement;
    if (!trend.length) {
      wrap.innerHTML = `<div class="empty-state">No scan history yet to chart.</div>`;
      return;
    }
    const labels = trend.map((t) => relTime(t.scan_date).slice(5, 16));
    const values = trend.map((t) => t.total_risk);

    const ctx = document.getElementById("chart-risk-trend").getContext("2d");
    new Chart(ctx, {
      type: "line",
      data: {
        labels,
        datasets: [{
          label: "Risk Score",
          data: values,
          borderColor: "#2563EB",
          backgroundColor: "rgba(37,99,235,0.08)",
          fill: true,
          tension: 0.35,
          pointRadius: 3,
          pointBackgroundColor: "#2563EB",
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, grid: { color: "#E2E8F0" } },
          x: { grid: { display: false } },
        },
      },
    });
  }
})();
