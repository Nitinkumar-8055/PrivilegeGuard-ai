async function updateStatus(incidentId, newStatus) {
  try {
    const res = await fetch(`/api/incidents/${incidentId}/status`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: newStatus })
    });
    const data = await res.json();
    if (data.success) {
      showToast(`Status updated to '${newStatus}'`, "success");
      // If on detail page, update badge
      const badge = document.getElementById("incident-status-badge");
      if (badge) {
        badge.innerText = newStatus;
        badge.className = `badge badge-${newStatus.toLowerCase().replace(" ", "-")}`;
      }
    } else {
      showToast(data.error || "Failed to update status", "error");
    }
  } catch (err) {
    showToast("Network error updating status", "error");
  }
}

async function triggerSimulation(incidentId, action) {
  if (!confirm(`Execute simulated response action: '${action}'? This will simulate remediation and log an audit trail.`)) {
    return;
  }

  try {
    const res = await fetch(`/api/incidents/${incidentId}/simulate_containment`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: action })
    });
    const data = await res.json();
    if (data.success) {
      showToast(data.message, "success");
      const badge = document.getElementById("incident-status-badge");
      if (badge) {
        badge.innerText = data.new_status;
        badge.className = `badge badge-${data.new_status.toLowerCase().replace(" ", "-")}`;
      }
      const simLog = document.getElementById("simulation-log");
      if (simLog) {
        const item = document.createElement("div");
        item.style.padding = "8px 12px";
        item.style.background = "var(--bg-card)";
        item.style.border = "1px solid var(--border-color)";
        item.style.borderRadius = "6px";
        item.style.marginBottom = "6px";
        item.style.borderLeft = "3px solid var(--sev-low)";
        item.innerHTML = `<strong>${new Date().toLocaleTimeString()}</strong>: ${escapeHtml(data.message)}`;
        simLog.prepend(item);
      }
    } else {
      showToast("Simulation execution failed", "error");
    }
  } catch (err) {
    showToast("Network error executing simulation", "error");
  }
}

function showToast(message, type = "info") {
  let toastContainer = document.getElementById("toast-container");
  if (!toastContainer) {
    toastContainer = document.createElement("div");
    toastContainer.id = "toast-container";
    toastContainer.style.position = "fixed";
    toastContainer.style.bottom = "20px";
    toastContainer.style.right = "20px";
    toastContainer.style.zIndex = "9999";
    toastContainer.style.display = "flex";
    toastContainer.style.flexDirection = "column";
    toastContainer.style.gap = "10px";
    document.body.appendChild(toastContainer);
  }

  const toast = document.createElement("div");
  toast.className = `alert-box alert-${type === "error" ? "error" : "success"}`;
  toast.style.margin = "0";
  toast.style.boxShadow = "0 4px 6px -1px rgba(0,0,0,0.5)";
  toast.innerText = message;

  toastContainer.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, 4000);
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
