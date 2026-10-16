document.addEventListener("DOMContentLoaded", function () {
  loadDashboardStats();

  // Refresh every 30 seconds if page is kept open
  setInterval(loadDashboardStats, 30000);
});

let severityChartInstance = null;
let timelineChartInstance = null;

async function loadDashboardStats() {
  try {
    const res = await fetch("/api/stats");
    if (!res.ok) return;
    const data = await res.json();

    // Update metric counters
    document.getElementById("stat-total-events").innerText = data.total_events.toLocaleString();
    document.getElementById("stat-total-incidents").innerText = data.total_incidents.toLocaleString();
    document.getElementById("stat-high-critical").innerText = data.high_critical_count.toLocaleString();
    document.getElementById("stat-affected-identities").innerText = data.affected_identities_count.toLocaleString();

    renderSeverityChart(data.severity_distribution);
    renderTimelineChart(data.activity_timeline);
    renderRecentIncidents(data.recent_incidents);
  } catch (err) {
    console.error("Failed to load dashboard metrics:", err);
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

  const labels = timeline.labels.length > 0 ? timeline.labels : ["No events"];
  const dataPoints = timeline.data.length > 0 ? timeline.data : [0];

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
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2rem;">No security incidents detected yet. Ingest events or generate a demo scenario.</td></tr>`;
    return;
  }

  let html = "";
  for (const inc of incidents) {
    const sevClass = `badge-${inc.severity.toLowerCase()}`;
    const statusClass = `badge-${inc.status.toLowerCase().replace(" ", "-")}`;
    const timeFormatted = inc.last_observed_at ? new Date(inc.last_observed_at).toLocaleString() : "N/A";

    html += `
      <tr>
        <td><strong><a href="/incidents/${inc.id}" style="color: var(--accent-cyan); text-decoration: none;">${inc.incident_id}</a></strong></td>
        <td>${escapeHtml(inc.title)}</td>
        <td><code>${escapeHtml(inc.affected_user)}</code></td>
        <td><span class="badge ${sevClass}">${inc.severity.toUpperCase()}</span></td>
        <td><strong>${inc.risk_score}</strong> / 100</td>
        <td><span class="badge ${statusClass}">${inc.status}</span></td>
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
