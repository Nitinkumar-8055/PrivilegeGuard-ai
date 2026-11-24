/**
 * PrivilegeGuard AI — Real-time Notification & Alert Dropdown Client
 */

(function () {
    "use strict";

    const badgeEl = document.getElementById("nav-notification-badge");
    const btnEl = document.getElementById("nav-notification-btn");
    const dropdownEl = document.getElementById("nav-notification-dropdown");
    const listEl = document.getElementById("dropdown-list-content");
    const unreadPillEl = document.getElementById("dropdown-unread-pill");
    const markAllBtn = document.getElementById("btn-dropdown-mark-all");

    let isDropdownOpen = false;

    function formatTimeAgo(dateString) {
        if (!dateString) return "N/A";
        const date = new Date(dateString);
        const now = new Date();
        const diffMs = now - date;
        const diffSec = Math.floor(diffMs / 1000);
        if (diffSec < 60) return "Just now";
        const diffMin = Math.floor(diffSec / 60);
        if (diffMin < 60) return `${diffMin}m ago`;
        const diffHours = Math.floor(diffMin / 60);
        if (diffHours < 24) return `${diffHours}h ago`;
        const diffDays = Math.floor(diffHours / 24);
        return `${diffDays}d ago`;
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

    async function fetchUnreadCount() {
        try {
            const resp = await fetch("/api/notifications/unread-count");
            if (!resp.ok) return;
            const data = await resp.json();
            const count = data.unread_count || 0;

            if (badgeEl) {
                if (count > 0) {
                    badgeEl.textContent = count > 99 ? "99+" : count;
                    badgeEl.style.display = "flex";
                } else {
                    badgeEl.style.display = "none";
                }
            }

            if (unreadPillEl) {
                if (count > 0) {
                    unreadPillEl.textContent = `${count} New`;
                    unreadPillEl.style.display = "inline-block";
                } else {
                    unreadPillEl.style.display = "none";
                }
            }
        } catch (err) {
            console.debug("Unread count poll silently failed:", err);
        }
    }

    async function loadRecentNotifications() {
        if (!listEl) return;
        listEl.innerHTML = '<div class="dropdown-empty">Loading notifications...</div>';

        try {
            const resp = await fetch("/api/notifications/recent?limit=6");
            if (!resp.ok) throw new Error("Failed to load notifications");
            const data = await resp.json();
            const notifs = data.notifications || [];

            if (notifs.length === 0) {
                listEl.innerHTML = '<div class="dropdown-empty">No notifications available.</div>';
                return;
            }

            let html = "";
            notifs.forEach((n) => {
                const sev = (n.severity || "medium").toLowerCase();
                const unreadClass = n.is_read ? "" : "unread";
                const incRef = n.incident_ref || "";
                const timeAgo = formatTimeAgo(n.created_at);
                const channelLabel = n.channel === "email" ? "Email" : "In-App";

                html += `
                <div class="dropdown-item ${unreadClass}" data-id="${n.id}" data-incident="${escapeHtml(incRef)}">
                    <div class="dropdown-item-header">
                        <div style="display:flex; align-items:center; gap:6px;">
                            <span class="badge badge-${sev} badge-sm">${sev.toUpperCase()}</span>
                            <span class="badge badge-secondary badge-sm" style="font-size:0.65rem;">${channelLabel}</span>
                            ${!n.is_read ? '<span class="unread-dot"></span>' : ""}
                        </div>
                        <span class="dropdown-item-time">${timeAgo}</span>
                    </div>
                    <div class="dropdown-item-title">${escapeHtml(n.title)}</div>
                    <div class="dropdown-item-msg">${escapeHtml(n.message)}</div>
                </div>
                `;
            });

            listEl.innerHTML = html;

            // Attach click listeners to rows
            listEl.querySelectorAll(".dropdown-item").forEach((row) => {
                row.addEventListener("click", async () => {
                    const id = row.getAttribute("data-id");
                    const incRef = row.getAttribute("data-incident");

                    // Mark as read asynchronously
                    try {
                        await fetch(`/api/notifications/${id}/read`, { method: "POST" });
                    } catch (e) {
                        console.debug("Mark read failed:", e);
                    }

                    // Navigate to incident if associated
                    if (incRef) {
                        window.location.href = `/incidents/${incRef}`;
                    } else {
                        fetchUnreadCount();
                        loadRecentNotifications();
                    }
                });
            });

        } catch (err) {
            listEl.innerHTML = '<div class="dropdown-empty" style="color:var(--sev-critical);">Failed to load notifications.</div>';
        }
    }

    function toggleDropdown() {
        if (!dropdownEl) return;
        isDropdownOpen = !isDropdownOpen;
        if (isDropdownOpen) {
            dropdownEl.style.display = "block";
            loadRecentNotifications();
        } else {
            dropdownEl.style.display = "none";
        }
    }

    if (btnEl) {
        btnEl.addEventListener("click", (e) => {
            e.stopPropagation();
            toggleDropdown();
        });
    }

    if (markAllBtn) {
        markAllBtn.addEventListener("click", async (e) => {
            e.stopPropagation();
            try {
                const resp = await fetch("/api/notifications/mark-all-read", { method: "POST" });
                if (resp.ok) {
                    fetchUnreadCount();
                    loadRecentNotifications();
                }
            } catch (err) {
                console.error("Mark all read failed:", err);
            }
        });
    }

    // Close dropdown on click outside
    document.addEventListener("click", (e) => {
        if (isDropdownOpen && dropdownEl && !dropdownEl.contains(e.target) && e.target !== btnEl) {
            dropdownEl.style.display = "none";
            isDropdownOpen = false;
        }
    });

    // Initial count fetch & periodic polling every 15s
    fetchUnreadCount();
    setInterval(fetchUnreadCount, 15000);
})();
