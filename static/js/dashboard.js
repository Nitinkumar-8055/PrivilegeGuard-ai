document.addEventListener("DOMContentLoaded", function () {
  loadDashboardStats();

  // Near-real-time polling: refresh every 5 seconds without full page reload
  setInterval(loadDashboardStats, 5000);
});

let severityChartInstance = null;
let timelineChartInstance = null;

async function loadDashboardStats() {
  try {
    const res = await fetch("/api/stats");
    if (!res.ok) return;
    const data = await res.json();

    // Update metric counters
    if (document.getElementById("stat-total-events")) {
      document.getElementById("stat-total-events").innerText = Number(data.total_events || 0).toLocaleString();
    }
    if (document.getElementById("stat-total-incidents")) {
      document.getElementById("stat-total-incidents").innerText = Number(data.total_incidents || 0).toLocaleString();
    }
    if (document.getElementById("stat-high-critical")) {
      document.getElementById("stat-high-critical").innerText = Number(data.high_critical_count || 0).toLocaleString();
    }
    if (document.getElementById("stat-affected-identities")) {
      document.getElementById("stat-affected-identities").innerText = Number(data.affected_identities_count || 0).toLocaleString();
    }

    renderCollectorStatus(data.collector);
    renderSeverityChart(data.severity_distribution || {});
    renderTimelineChart(data.activity_timeline || { labels: [], data: [] });
    renderRecentIncidents(data.recent_incidents || []);
    renderRecentEvents(data.recent_events || []);
  } catch (err) {
    console.error("Failed to load dashboard metrics:", err);
  }
}

function renderCollectorStatus(collector) {
  if (!collector) return;

  const statusBadge = document.getElementById("collector-status-badge");
  const sourceBadge = document.getElementById("collector-source-badge");
  const channelEl = document.getElementById("collector-channel");
  const checkpointEl = document.getElementById("collector-checkpoint");
  const lastPollEl = document.getElementById("collector-last-poll");
  const totalCollEl = document.getElementById("collector-total-collected");
  const intervalEl = document.getElementById("collector-interval");
  const errorBox = document.getElementById("collector-error-alert");
  const errorText = document.getElementById("collector-error-text");

  if (statusBadge) {
    statusBadge.innerText = (collector.status || "UNKNOWN").toUpperCase();
    statusBadge.className = "badge";
    if (collector.status === "Running") {
      statusBadge.classList.add("badge-contained"); // green
    } else if (collector.status === "Access Denied" || collector.status === "Error") {
      statusBadge.classList.add("badge-critical"); // red
    } else if (collector.status === "Simulated") {
      statusBadge.classList.add("badge-investigating"); // blue
    } else {
      statusBadge.classList.add("badge-new"); // yellow/gray
    }
  }

  if (sourceBadge && collector.source_type) {
    sourceBadge.innerText = collector.source_type;
  }
  if (channelEl && collector.channel) {
    channelEl.innerText = collector.channel;
  }
  if (checkpointEl) {
    checkpointEl.innerText = `#${collector.last_record_id || 0}`;
  }
  if (totalCollEl) {
    totalCollEl.innerText = Number(collector.total_events_collected || 0).toLocaleString();
  }
  if (intervalEl && collector.polling_interval_seconds) {
    intervalEl.innerText = `${collector.polling_interval_seconds}s`;
  }
  if (lastPollEl) {
    if (collector.last_poll_timestamp) {
      const dt = new Date(collector.last_poll_timestamp);
      lastPollEl.innerText = dt.toLocaleTimeString();
    } else {
      lastPollEl.innerText = "Never";
    }
  }

  if (errorBox && errorText) {
    if (collector.error_message) {
      errorText.innerText = collector.error_message;
      errorBox.style.display = "block";
    } else {
      errorBox.style.display = "none";
    }
  }
}

function renderSeverityChart(distribution) {
  const ctx = document.getElementById("severityChart");
  if (!ctx || typeof Chart === "undefined") return;

  const labels = ["Critical", "High", "Medium", "Low"];
  const values = [
    distribution.critical || 0,
    distribution.high || 0,
    distribution.medium || 0,
    distribution.low || 0
  ];

  if (severityChartInstance) {
    severityChartInstance.data.datasets[0].data = values;
    severityChartInstance.update();
    return;
  }

  severityChartInstance = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: labels,
      datasets: [{
        data: values,
        backgroundColor: ["#ef4444", "#f97316", "#eab308", "#10b981"],
        borderColor: "#0f1523",
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: { color: "#94a3b8", boxWidth: 12, padding: 15 }
        }
      },
      cutout: "70%"
    }
  });
}

function renderTimelineChart(timeline) {
  const ctx = document.getElementById("timelineChart");
  if (!ctx || typeof Chart === "undefined") return;

  const labels = timeline.labels && timeline.labels.length > 0 ? timeline.labels : ["No events"];
  const dataPoints = timeline.data && timeline.data.length > 0 ? timeline.data : [0];

  if (timelineChartInstance) {
    timelineChartInstance.data.labels = labels;
    timelineChartInstance.data.datasets[0].data = dataPoints;
    timelineChartInstance.update();
    return;
  }

  timelineChartInstance = new Chart(ctx, {
    type: "line",
    data: {
      labels: labels,
      datasets: [{
        label: "Events Ingested",
        data: dataPoints,
        borderColor: "#3b82f6",
        backgroundColor: "rgba(59, 130, 246, 0.08)",
        fill: true,
        tension: 0.3,
        pointBackgroundColor: "#3b82f6",
        pointRadius: 3
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          grid: { color: "#1e2c44" },
          ticks: { color: "#64748b", maxRotation: 45, minRotation: 45, font: { size: 10 } }
        },
        y: {
          grid: { color: "#1e2c44" },
          ticks: { color: "#64748b", precision: 0 }
        }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

function renderRecentIncidents(incidents) {
  const tbody = document.getElementById("recent-incidents-body");
  if (!tbody) return;

  if (!incidents || incidents.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2rem;">No security incidents detected yet. Start the Windows collector or ingest events.</td></tr>`;
    return;
  }

  let html = "";
  for (const inc of incidents) {
    const sevClass = `badge-${inc.severity.toLowerCase()}`;
    const statusClass = `badge-${inc.status.toLowerCase().replace(" ", "-")}`;

    html += `
      <tr>
        <td><strong><a href="/incidents/${inc.id}" style="color: var(--accent-cyan); text-decoration: none;">${escapeHtml(inc.incident_id)}</a></strong></td>
        <td>${escapeHtml(inc.title)}</td>
        <td><code>${escapeHtml(inc.affected_user)}</code></td>
        <td><span class="badge ${sevClass}">${escapeHtml(inc.severity.toUpperCase())}</span></td>
        <td><strong>${inc.risk_score}</strong> / 100</td>
        <td><span class="badge ${statusClass}">${escapeHtml(inc.status)}</span></td>
      </tr>
    `;
  }
  tbody.innerHTML = html;
}

function renderRecentEvents(events) {
  const tbody = document.getElementById("recent-events-body");
  if (!tbody) return;

  if (!events || events.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem;">No events collected yet. Awaiting Windows Security log ingestion.</td></tr>`;
    return;
  }

  let html = "";
  for (const ev of events) {
    const timeFormatted = ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : "N/A";
    const outcomeClass = ev.outcome === "success" ? "badge-contained" : "badge-critical";
    const displayAction = ev.action || ev.resource || ev.event_type;

    html += `
      <tr>
        <td><code>${escapeHtml(ev.event_id)}</code></td>
        <td style="color: var(--text-muted);">${timeFormatted}</td>
        <td><strong>${escapeHtml(ev.username)}</strong></td>
        <td><code>${escapeHtml(ev.event_type)}</code></td>
        <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(displayAction)}">${escapeHtml(displayAction)}</td>
        <td><code>${escapeHtml(ev.source_ip || "local")}</code></td>
        <td><span class="badge ${outcomeClass}">${escapeHtml(ev.outcome.toUpperCase())}</span></td>
      </tr>
    `;
  }
  tbody.innerHTML = html;
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
