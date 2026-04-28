// FEATURE ADDED: MTTD / MTTR Metrics
// FEATURE ADDED: Alert Correlation Engine
// FEATURE ADDED: Shift Handoff Report
// FEATURE ADDED: Response Playbook Checklist
// FEATURE ADDED: Sigma Rule Generator

const ALERT_TYPES = [
    "brute_force",
    "port_scan",
    "phishing_email",
    "malware_download",
    "suspicious_login",
    "powershell_execution",
    "command_and_control",
    "web_attack",
    "lateral_movement",
    "dns_tunneling",
    "privilege_escalation",
    "data_exfiltration"
];

const CHART_COLORS = {
    low: "#39ff88",
    medium: "#ffd166",
    high: "#ff9f1c",
    critical: "#ff3b3b",
    new: "#00e5ff",
    investigating: "#ffd166",
    escalated: "#ff3b3b",
    closed: "#39ff88",
    cyan: "#00e5ff",
    blue: "#3b82f6",
    purple: "#a855f7",
    muted: "#8aa4b2",
    panel: "#0b1117"
};

let allAlerts = [];
let filteredAlerts = [];
let currentStats = null;
let selectedAlert = null;
let selectedAlertId = null;
let liveSimulationTimer = null;
let charts = {};
let highlightedAlertId = null;
let lastSigmaYaml = "";
let activeWorkspaceId = "command-center";
let statsCache = null;
let statsCacheTime = 0;
let searchTimeout = null;
let sparkHistory = {
    total: [4, 5, 6, 5, 7, 8, 8, 9],
    critical: [1, 1, 2, 1, 2, 3, 2, 3],
    open: [2, 3, 4, 4, 5, 5, 6, 6],
    escalated: [0, 1, 1, 1, 2, 1, 2, 2]
};

/** Select one element from the document. */
function $(selector) {
    return document.querySelector(selector);
}

/** Select all matching elements as an array. */
function $all(selector) {
    return Array.prototype.slice.call(document.querySelectorAll(selector));
}

/** Escape API text before inserting into HTML. */
function escapeHtml(value) {
    return String(value === null || value === undefined ? "" : value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/** Parse SentinelOps second-precision timestamps. */
function parseTimestamp(timestamp) {
    return new Date(String(timestamp || "").replace(" ", "T"));
}

/** Return a pluralized unit label. */
function unitLabel(value, unit) {
    return `${value} ${unit}${value === 1 ? "" : "s"} ago`;
}

/** Render a live relative timestamp. */
function relativeTime(timestamp) {
    const parsed = parseTimestamp(timestamp);
    if (Number.isNaN(parsed.getTime())) {
        return "unknown";
    }
    const seconds = Math.max(Math.floor((Date.now() - parsed.getTime()) / 1000), 0);
    if (seconds < 60) {
        return unitLabel(seconds, "second");
    }
    if (seconds < 3600) {
        return unitLabel(Math.floor(seconds / 60), "minute");
    }
    if (seconds < 86400) {
        return unitLabel(Math.floor(seconds / 3600), "hour");
    }
    return unitLabel(Math.floor(seconds / 86400), "day");
}

/** Update every rendered relative timestamp in-place. */
function updateRelativeTimes() {
    const nodes = $all("[data-relative-time]");
    for (let index = 0; index < nodes.length; index += 1) {
        nodes[index].textContent = relativeTime(nodes[index].dataset.relativeTime);
    }
    if (selectedAlert && $("#detailMeta")) {
        $("#detailMeta").textContent = `${selectedAlert.alert_type} · ${selectedAlert.timestamp} · ${relativeTime(selectedAlert.timestamp)}`;
    }
}

/** Update the SOC clock every second. */
function updateClock() {
    const now = new Date();
    const clock = $("#liveClock");
    const date = $("#liveDate");
    if (clock) {
        clock.textContent = now.toLocaleTimeString("en-US", { hour12: false });
    }
    if (date) {
        date.textContent = now.toLocaleDateString("en-US", { weekday: "long", year: "numeric", month: "long", day: "numeric" });
    }
}

/** Fetch JSON through one central error-handled wrapper. */
async function apiFetch(url, options = {}) {
    try {
        const response = await fetch(url, options);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error("API error:", url, error);
        showToast("API request failed. Check the server connection.", "error");
        return null;
    }
}

/** Show a short UI-level message for async workflow errors or confirmations. */
function showUiMessage(message, type) {
    const node = $("#sigmaMessage");
    if (!node) {
        return;
    }
    node.textContent = message;
    node.className = `ui-message ${type || "info"}`;
    window.clearTimeout(showUiMessage.timer);
    showUiMessage.timer = window.setTimeout(function clearMessage() {
        node.textContent = "";
        node.className = "ui-message";
    }, 4500);
}

/** Show a lightweight non-blocking toast notification. */
function showToast(message, type = "info") {
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    window.setTimeout(function removeToast() {
        toast.remove();
    }, 3000);
}

/** Apply immediate loading feedback to a button while an async action runs. */
async function withButtonLoading(button, loadingText, action, successText) {
    if (!button) {
        return action();
    }
    const originalText = button.textContent;
    let successShown = false;
    button.disabled = true;
    button.textContent = loadingText;
    button.classList.add("btn-loading");
    try {
        const result = await action();
        if (successText && result !== false) {
            successShown = true;
            button.classList.remove("btn-loading");
            button.textContent = successText;
            window.setTimeout(function restoreText() {
                button.textContent = originalText;
            }, 2000);
        }
        return result;
    } finally {
        button.disabled = false;
        button.classList.remove("btn-loading");
        if (!successShown) {
            button.textContent = originalText;
        }
    }
}

/** Show one full-screen workspace and update the sidebar active state. */
function showWorkspace(workspaceId) {
    activeWorkspaceId = workspaceId;
    document.querySelectorAll(".workspace").forEach(function hideWorkspace(workspace) {
        workspace.style.display = "none";
        workspace.classList.remove("active");
    });
    document.querySelectorAll(".nav-item").forEach(function clearActive(item) {
        item.classList.remove("active");
    });
    const workspace = document.getElementById(`workspace-${workspaceId}`);
    if (workspace) {
        workspace.style.display = "block";
        workspace.classList.add("active");
    }
    const navItem = document.querySelector(`[data-workspace="${workspaceId}"]`);
    if (navItem) {
        navItem.classList.add("active");
    }
    if (workspaceId === "command-center") {
        loadCommandCenterStats();
    }
    if (workspaceId === "live-alert-feed") {
        loadAlertFeed();
    }
    if (workspaceId === "case-queue") {
        loadCaseQueue();
    }
    if (workspaceId === "mitre-heatmap") {
        loadMitreHeatmap();
    }
    if (workspaceId === "threat-intel-lookup") {
        loadThreatIntel();
    }
    if (workspaceId === "case-reports") {
        loadCaseReports();
    }
    if (workspaceId === "detection-lab") {
        loadDetectionLab();
    }
    window.setTimeout(resizeCharts, 80);
    window.scrollTo({ top: 0, behavior: "smooth" });
}

/** Compatibility wrapper for older call sites. */
function switchWorkspace(name) {
    const aliases = {
        command: "command-center",
        feed: "live-alert-feed",
        cases: "case-queue",
        investigation: "investigation-war-room",
        market: "threat-market-view",
        mitre: "mitre-heatmap",
        intel: "threat-intel-lookup",
        detection: "detection-lab",
        reports: "case-reports",
        profile: "analyst-profile"
    };
    showWorkspace(aliases[name] || name);
}

/** Resize charts after hidden workspaces become visible. */
function resizeCharts() {
    const ids = Object.keys(charts);
    for (let index = 0; index < ids.length; index += 1) {
        charts[ids[index]].resize();
    }
    renderVolatilityCanvas();
    renderSparklines();
}

/** Bind sidebar workspace buttons. */
function bindWorkspaceNavigation() {
    const buttons = $all(".nav-item");
    for (let index = 0; index < buttons.length; index += 1) {
        buttons[index].addEventListener("click", function handleWorkspaceClick(event) {
            showWorkspace(event.currentTarget.dataset.workspace);
        });
    }
}

/** Build alert query string from current filters. */
function alertQueryString() {
    const params = new URLSearchParams();
    const severity = $("#severityFilter")?.value || "";
    const status = $("#statusFilter")?.value || "";
    const alertType = $("#typeFilter")?.value || "";
    const search = $("#searchFilter")?.value || "";
    if (severity) {
        params.set("severity", severity);
    }
    if (status) {
        params.set("status", status);
    }
    if (alertType) {
        params.set("alert_type", alertType);
    }
    if (search.trim()) {
        params.set("search", search.trim());
    }
    return params.toString();
}

/** Load all alerts for case boards, market views, and selected-context modules. */
async function loadAllAlerts() {
    const payload = await apiFetch("/api/alerts");
    if (!payload) {
        return;
    }
    allAlerts = payload.alerts || [];
}

/** Load filtered alerts for the Live Alert Feed workspace. */
async function loadFilteredAlerts() {
    const query = alertQueryString();
    const payload = await apiFetch(`/api/alerts${query ? `?${query}` : ""}`);
    if (!payload) {
        return;
    }
    filteredAlerts = payload.alerts || [];
    renderAlertTable();
}

/** Load statistics and render data-driven panels. */
async function loadStats(force = false) {
    const now = Date.now();
    if (!force && statsCache && now - statsCacheTime < 10000) {
        currentStats = statsCache;
        renderMetrics(currentStats);
        renderCharts(currentStats);
        return currentStats;
    }
    const payload = await apiFetch("/api/stats");
    if (!payload) {
        return currentStats;
    }
    statsCache = payload;
    statsCacheTime = now;
    currentStats = payload;
    renderMetrics(currentStats);
    renderCharts(currentStats);
    return currentStats;
}

/** Load Command Center data on workspace activation. */
async function loadCommandCenterStats() {
    await loadStats();
    renderCommandSnapshot((currentStats && currentStats.latest_10_alerts) || []);
}

/** Load Live Alert Feed data on workspace activation. */
async function loadAlertFeed() {
    await loadFilteredAlerts();
}

/** Load Case Queue data on workspace activation. */
function loadCaseQueue() {
    renderCaseQueue();
}

/** Load MITRE Heatmap data on workspace activation. */
function loadMitreHeatmap() {
    renderMitreWorkspace();
}

/** Load Threat Intel data on workspace activation. */
function loadThreatIntel() {
    renderIntelWorkspace();
}

/** Load Case Reports data on workspace activation. */
function loadCaseReports() {
    renderReportsWorkspace();
}

/** Load Detection Lab data on workspace activation. */
function loadDetectionLab() {
    renderDetectionLab();
    renderSigmaMetadata();
}

/** Refresh all dashboard data without a page reload. */
async function refreshDashboard(newAlertId) {
    if (typeof newAlertId === "string") {
        highlightedAlertId = newAlertId;
    }
    await Promise.all([loadStats(), loadAllAlerts(), loadFilteredAlerts()]);
    if (!currentStats) {
        return;
    }
    renderCommandSnapshot(currentStats.latest_10_alerts || []);
    renderThreatMarket(currentStats);
    renderCaseQueue();
    renderMitreWorkspace();
    renderIntelWorkspace();
    populateSigmaAlertSelector();
    renderDetectionLab();
    renderSigmaMetadata();
    renderReportsWorkspace();
    if (selectedAlertId) {
        await refreshSelectedAlert();
    } else if (allAlerts.length) {
        await selectAlert(allAlerts[0].alert_id, false);
    }
    updateRelativeTimes();
}

/** Refresh all dashboard data from the manual refresh button. */
function handleRefreshClick(event) {
    withButtonLoading(event.currentTarget, "REFRESHING...", async function runRefresh() {
        statsCache = null;
        statsCacheTime = 0;
        await refreshDashboard();
    }, "REFRESHED");
}

/** Render top metric cards. */
function renderMetrics(stats) {
    if (!stats) {
        return;
    }
    $("#metricTotal").textContent = stats.total_alerts || 0;
    $("#metricCritical").textContent = stats.critical_alerts || 0;
    $("#metricOpen").textContent = stats.open_investigations || 0;
    $("#metricClosed").textContent = stats.closed_today || 0;
    $("#metricMttd").textContent = stats.mttd_formatted || "00:00:00";
    $("#metricMttr").textContent = stats.mttr_formatted || "00:00:00";
}

/** Create or update a Chart.js chart. */
function upsertChart(id, config) {
    const canvas = $(`#${id}`);
    if (!canvas || typeof Chart === "undefined") {
        return;
    }
    if (charts[id]) {
        charts[id].data = config.data;
        charts[id].options = config.options;
        charts[id].update();
        return;
    }
    charts[id] = new Chart(canvas, config);
}

/** Render all Chart.js reporting and MITRE charts. */
function renderCharts(stats) {
    const severity = stats.count_per_severity || {};
    const status = stats.count_per_status || {};
    const typeCounts = stats.alert_count_by_type || {};
    const mitre = stats.mitre_tactic_distribution || {};
    renderBarChart("severityChart", Object.keys(severity), Object.values(severity), [CHART_COLORS.low, CHART_COLORS.medium, CHART_COLORS.high, CHART_COLORS.critical]);
    renderDonutChart("statusChart", Object.keys(status), Object.values(status), [CHART_COLORS.new, CHART_COLORS.investigating, CHART_COLORS.escalated, CHART_COLORS.closed]);
    renderBarChart("typeChart", Object.keys(typeCounts), Object.values(typeCounts), Object.keys(typeCounts).map(colorForType));
    renderBarChart("mitreChart", Object.keys(mitre), Object.values(mitre), Object.keys(mitre).map(colorForType));
    renderBarChart("mitreMovementChart", Object.keys(mitre), Object.values(mitre), Object.keys(mitre).map(colorForType));
}

/** Pick a repeatable accent color for chart categories. */
function colorForType(label) {
    const palette = [CHART_COLORS.blue, CHART_COLORS.purple, CHART_COLORS.low, CHART_COLORS.high, CHART_COLORS.new, CHART_COLORS.critical];
    let total = 0;
    for (let index = 0; index < label.length; index += 1) {
        total += label.charCodeAt(index);
    }
    return palette[total % palette.length];
}

/** Render one bar chart with dark SOC styling. */
function renderBarChart(id, labels, data, colors) {
    upsertChart(id, {
        type: "bar",
        data: { labels: labels, datasets: [{ data: data, backgroundColor: colors, borderColor: colors, borderWidth: 1 }] },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: CHART_COLORS.muted, maxRotation: 45, minRotation: 0 }, grid: { color: "rgba(138,164,178,0.08)" } },
                y: { beginAtZero: true, ticks: { color: CHART_COLORS.muted, precision: 0 }, grid: { color: "rgba(138,164,178,0.1)" } }
            }
        }
    });
}

/** Render one donut chart with dark SOC styling. */
function renderDonutChart(id, labels, data, colors) {
    upsertChart(id, {
        type: "doughnut",
        data: { labels: labels, datasets: [{ data: data, backgroundColor: colors, borderColor: CHART_COLORS.panel, borderWidth: 3 }] },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            cutout: "64%",
            plugins: { legend: { labels: { color: CHART_COLORS.muted, font: { family: "JetBrains Mono" } } } }
        }
    });
}

/** Build severity badge markup. */
function severityBadge(severity) {
    return `<span class="severity-badge severity-${escapeHtml(severity)}">${escapeHtml(severity)}</span>`;
}

/** Build status badge markup. */
function statusBadge(status) {
    return `<span class="status-badge status-${escapeHtml(status)}">${escapeHtml(status)}</span>`;
}

/** Render the full-screen Live Alert Feed table. */
function renderAlertTable() {
    const body = $("#alertsTableBody");
    if (!body) {
        return;
    }
    if (!filteredAlerts.length) {
        body.innerHTML = '<tr><td colspan="10" class="empty">No alerts match the current filters.</td></tr>';
        return;
    }
    body.innerHTML = filteredAlerts.map(renderAlertRow).join("");
    const rows = $all("[data-alert-row]");
    for (let index = 0; index < rows.length; index += 1) {
        rows[index].addEventListener("click", handleAlertRowClick);
    }
}

/** Render one alert table row. */
function renderAlertRow(alert) {
    const rowClass = alert.alert_id === highlightedAlertId ? "new-alert" : "";
    return `
        <tr class="${rowClass}" data-alert-row="${escapeHtml(alert.alert_id)}">
            <td class="time-cell">${escapeHtml(alert.timestamp)}</td>
            <td class="time-cell" data-relative-time="${escapeHtml(alert.timestamp)}">${relativeTime(alert.timestamp)}</td>
            <td class="mono">${escapeHtml(alert.alert_id)}</td>
            <td class="ip-cell">${escapeHtml(alert.source_ip)}</td>
            <td class="ip-cell">${escapeHtml(alert.dest_ip)}</td>
            <td>${escapeHtml(alert.alert_type)}</td>
            <td>${severityBadge(alert.severity)}</td>
            <td>${escapeHtml(alert.mitre_tactic || "Unclassified")}</td>
            <td>${statusBadge(alert.status)}</td>
            <td><button class="ghost-btn" type="button">Investigate</button></td>
        </tr>
    `;
}

/** Handle row click and open the Investigation War Room. */
function handleAlertRowClick(event) {
    const alertId = event.currentTarget.dataset.alertRow;
    selectAlert(alertId, true);
}

/** Load and render a selected alert. */
async function selectAlert(alertId, openWarRoom) {
    selectedAlertId = alertId;
    selectedAlert = await apiFetch(`/api/alerts/${encodeURIComponent(alertId)}`);
    if (!selectedAlert) {
        return;
    }
    renderInvestigation(selectedAlert);
    await loadTimeline(alertId);
    await loadCorrelatedAlerts(alertId);
    await loadPlaybook(alertId);
    renderIntelWorkspace();
    populateSigmaAlertSelector();
    renderSigmaMetadata();
    renderDetectionLab();
    renderReportsWorkspace();
    if (openWarRoom) {
        showWorkspace("investigation-war-room");
    }
}

/** Refresh the selected alert after workflow changes. */
async function refreshSelectedAlert() {
    if (!selectedAlertId) {
        return;
    }
    selectedAlert = await apiFetch(`/api/alerts/${encodeURIComponent(selectedAlertId)}`);
    if (!selectedAlert) {
        return;
    }
    renderInvestigation(selectedAlert);
    await loadTimeline(selectedAlertId);
    await loadCorrelatedAlerts(selectedAlertId);
    await loadPlaybook(selectedAlertId);
    renderIntelWorkspace();
    renderSigmaMetadata();
    renderDetectionLab();
    renderReportsWorkspace();
}

/** Render alert details into the full-screen War Room. */
function renderInvestigation(alert) {
    $("#emptyInvestigation").classList.add("hidden");
    $("#investigationContent").classList.remove("hidden");
    $("#detailAlertId").textContent = alert.alert_id;
    $("#detailMeta").textContent = `${alert.alert_type} · ${alert.timestamp} · ${relativeTime(alert.timestamp)}`;
    $("#detailSeverity").className = `severity-badge severity-${alert.severity}`;
    $("#detailSeverity").textContent = alert.severity;
    $("#detailSource").textContent = alert.source_ip;
    $("#detailDest").textContent = alert.dest_ip;
    $("#detailStatus").textContent = alert.status;
    $("#detailReputation").textContent = alert.reputation_score || 0;
    $("#detailRawLog").textContent = alert.raw_log;
    $("#analystNotes").value = alert.analyst_notes || "";
    $("#investigationSummary").value = alert.investigation_summary || "";
    $("#statusSelect").value = alert.status;
    renderMitre(alert);
    renderReputation(alert);
    renderRecommendations(alert);
}

/** Render MITRE mapping details in the selected case. */
function renderMitre(alert) {
    const container = $("#detailMitre");
    if (!alert.mitre_tactic) {
        container.innerHTML = "No MITRE classification saved yet.";
        return;
    }
    container.innerHTML = `
        <strong>${escapeHtml(alert.mitre_tactic)}</strong><br>
        <span class="mono">${escapeHtml(alert.mitre_technique)}</span>
        <p>${escapeHtml(alert.mitre_description)}</p>
    `;
}

/** Render reputation enrichment result in the selected case. */
function renderReputation(alert) {
    const container = $("#detailReputationResult");
    if (!alert.reputation_result) {
        container.textContent = "No enrichment has been run yet.";
        return;
    }
    if (alert.reputation_result.trim().startsWith("{")) {
        try {
            const result = JSON.parse(alert.reputation_result);
            renderEnrichmentSuccess({
                source_ip: result.source_ip || alert.source_ip,
                reputation_score: result.reputation_score || alert.reputation_score || 0,
                malicious: result.malicious || 0,
                suspicious: result.suspicious || 0,
                harmless: result.harmless || 0,
                country: result.country || "Unknown"
            });
        } catch (error) {
            container.innerHTML = `<strong>Live reputation data saved.</strong><br><span class="mono">Risk score: ${escapeHtml(alert.reputation_score || 0)}</span>`;
        }
        return;
    }
    renderEnrichmentWarning(alert.reputation_result);
}

/** Pick gauge color class for a VirusTotal reputation score. */
function reputationGaugeClass(score) {
    if (score > 20) {
        return "danger";
    }
    if (score > 0) {
        return "warn";
    }
    return "clean";
}

/** Render a styled no-key warning in the enrichment panel. */
function renderEnrichmentWarning(message) {
    $("#detailReputationResult").innerHTML = `
        <div class="enrichment-box warning">
            <strong>⚠ VirusTotal API key not configured.</strong>
            <p>${escapeHtml(message || "Add VIRUSTOTAL_API_KEY=your_key to your .env file and restart the server.")}</p>
        </div>
    `;
}

/** Render a styled network/server error in the enrichment panel. */
function renderEnrichmentError() {
    $("#detailReputationResult").innerHTML = `
        <div class="enrichment-box error">
            <strong>⚠ Enrichment request failed.</strong>
            <p>Check that the server is running.</p>
        </div>
    `;
}

/** Render successful VirusTotal enrichment as a gauge and stat pills. */
function renderEnrichmentSuccess(result) {
    const score = Number(result.reputation_score || 0);
    const gaugeClass = reputationGaugeClass(score);
    $("#detailReputationResult").innerHTML = `
        <div class="enrichment-box success">
            <span>Source IP</span>
            <strong class="enrichment-ip">${escapeHtml(result.source_ip)}</strong>
            <div class="reputation-gauge ${gaugeClass}">
                <i style="width:${Math.min(100, Math.max(0, score))}%"></i>
            </div>
            <div class="reputation-score-row"><span>Reputation Score</span><strong>${score}/100</strong></div>
            <div class="vt-stat-grid">
                <span class="vt-pill malicious">Malicious ${escapeHtml(result.malicious || 0)}</span>
                <span class="vt-pill suspicious">Suspicious ${escapeHtml(result.suspicious || 0)}</span>
                <span class="vt-pill harmless">Harmless ${escapeHtml(result.harmless || 0)}</span>
            </div>
            <p>Country: <span class="mono">${escapeHtml(result.country || "Unknown")}</span></p>
        </div>
    `;
}

/** Render response recommendations for the selected alert type. */
function renderRecommendations(alert) {
    const recommendations = {
        brute_force: ["Confirm targeted account scope.", "Review successful logins after failures.", "Recommend MFA and source blocking if pattern persists."],
        port_scan: ["Validate if scanner is approved.", "Check destination exposure and subsequent exploit attempts.", "Correlate with firewall denies."],
        phishing_email: ["Review affected mailbox and URL detonation.", "Check for credential submission indicators.", "Search for similar sender infrastructure."],
        malware_download: ["Verify file hash reputation.", "Confirm endpoint containment state.", "Review proxy and EDR telemetry."],
        suspicious_login: ["Validate user travel and device context.", "Check MFA events.", "Reset credentials if account misuse is suspected."],
        powershell_execution: ["Review command line and parent process.", "Check encoded or hidden execution flags.", "Collect endpoint process tree."],
        command_and_control: ["Inspect beacon periodicity.", "Review DNS and proxy logs.", "Contain host if C2 is confirmed."],
        web_attack: ["Review WAF request context.", "Confirm application patch posture.", "Search for successful response codes."],
        lateral_movement: ["Validate remote service use.", "Check source host integrity.", "Review privileged account activity."],
        dns_tunneling: ["Inspect query entropy and volume.", "Review resolver logs.", "Block suspicious domain if validated."],
        privilege_escalation: ["Review vulnerable component exposure.", "Collect endpoint telemetry.", "Validate privilege changes."],
        data_exfiltration: ["Review egress volume and destination.", "Validate data sensitivity.", "Escalate to incident response if confirmed."]
    };
    const list = recommendations[alert.alert_type] || ["Review correlated telemetry.", "Validate source and destination context.", "Document triage rationale."];
    $("#responseRecommendations").innerHTML = list.map(function renderRecommendation(item) {
        return `<li>${escapeHtml(item)}</li>`;
    }).join("");
}

/** Load and render timeline events for a selected alert. */
async function loadTimeline(alertId) {
    const payload = await apiFetch(`/api/timeline/${encodeURIComponent(alertId)}`);
    if (!payload) {
        renderTimelineList("#timelineList", []);
        renderTimelineList("#reportTimelineList", []);
        return;
    }
    const events = payload.timeline || [];
    renderTimelineList("#timelineList", events);
    renderTimelineList("#reportTimelineList", events);
}

/** Render timeline events into a supplied container. */
function renderTimelineList(selector, events) {
    const list = $(selector);
    if (!list) {
        return;
    }
    if (!events.length) {
        list.innerHTML = '<div class="empty">No timeline events recorded.</div>';
        return;
    }
    list.innerHTML = events.map(renderTimelineEvent).join("");
}

/** Render one case timeline event. */
function renderTimelineEvent(event) {
    return `
        <div class="timeline-item">
            <strong>${escapeHtml(event.event_name)}</strong>
            <span>${escapeHtml(event.timestamp)} · <span data-relative-time="${escapeHtml(event.timestamp)}">${relativeTime(event.timestamp)}</span></span>
            <div>${escapeHtml(event.event_description)}</div>
        </div>
    `;
}

/** Load correlated alerts for the active investigation. */
async function loadCorrelatedAlerts(alertId) {
    const payload = await apiFetch(`/api/alerts/correlated/${encodeURIComponent(alertId)}`);
    if (!payload) {
        renderCorrelatedAlerts({ correlated: [], coordinated_attack: false, total: 0, error: true });
        showUiMessage("Unable to load correlated alerts.", "error");
        return;
    }
    renderCorrelatedAlerts(payload);
}

/** Render the correlated alert table and coordinated-attack indicator. */
function renderCorrelatedAlerts(payload) {
    const body = $("#correlatedAlertsBody");
    const badge = $("#correlationAlertBadge");
    if (!body || !badge) {
        return;
    }
    badge.classList.toggle("hidden", !payload.coordinated_attack);
    const alerts = payload.correlated || [];
    if (!alerts.length) {
        body.innerHTML = '<tr><td colspan="5" class="empty">No correlated activity detected.</td></tr>';
        return;
    }
    body.innerHTML = alerts.map(function renderCorrelation(alert) {
        return `
            <tr data-correlated-open="${escapeHtml(alert.alert_id)}">
                <td class="mono">${escapeHtml(alert.alert_id)}</td>
                <td>${escapeHtml(alert.alert_type)}</td>
                <td>${severityBadge(alert.severity)}</td>
                <td>${escapeHtml(alert.correlation_reason)}</td>
                <td class="time-cell">${escapeHtml(alert.timestamp)}</td>
            </tr>
        `;
    }).join("");
    const rows = $all("[data-correlated-open]");
    for (let index = 0; index < rows.length; index += 1) {
        rows[index].addEventListener("click", function handleCorrelatedOpen(event) {
            selectAlert(event.currentTarget.dataset.correlatedOpen, true);
        });
    }
}

/** Toggle the incident response playbook visibility. */
function togglePlaybookPanel() {
    const panel = $("#playbookPanel");
    if (panel) {
        panel.classList.toggle("collapsed");
    }
}

/** Load playbook progress for the active investigation. */
async function loadPlaybook(alertId) {
    const payload = await apiFetch(`/api/playbook/${encodeURIComponent(alertId)}`);
    if (!payload) {
        renderPlaybook({ steps: [], completed_count: 0, total_steps: 0, progress_percent: 0, complete: false, error: true });
        showUiMessage("Unable to load the incident response playbook.", "error");
        return;
    }
    renderPlaybook(payload);
}

/** Render the response playbook progress bar and checkbox list. */
function renderPlaybook(payload) {
    const text = $("#playbookProgressText");
    const fill = $("#playbookProgressFill");
    const list = $("#playbookSteps");
    const badge = $("#playbookCompleteBadge");
    if (!text || !fill || !list || !badge) {
        return;
    }
    const completed = payload.completed_count || 0;
    const total = payload.total_steps || (payload.steps || []).length;
    text.textContent = `${completed} of ${total} steps completed`;
    fill.style.width = `${payload.progress_percent || 0}%`;
    badge.classList.toggle("hidden", !payload.complete);
    const steps = payload.steps || [];
    if (!steps.length) {
        list.innerHTML = '<div class="empty">No playbook is mapped for this alert type.</div>';
        return;
    }
    list.innerHTML = steps.map(function renderStep(step) {
        return `
            <label class="playbook-step ${step.completed ? "completed" : ""}">
                <input type="checkbox" data-playbook-step="${step.index}" ${step.completed ? "checked" : ""}>
                <span>
                    <strong>${escapeHtml(step.text)}</strong>
                    ${step.completed_at ? `<small>Completed ${escapeHtml(step.completed_at)}</small>` : ""}
                </span>
            </label>
        `;
    }).join("");
    const checkboxes = $all("[data-playbook-step]");
    for (let index = 0; index < checkboxes.length; index += 1) {
        checkboxes[index].addEventListener("change", togglePlaybookStep);
    }
}

/** Toggle one playbook step on the backend and re-render progress. */
async function togglePlaybookStep(event) {
    if (!selectedAlertId) {
        return;
    }
    const stepIndex = event.currentTarget.dataset.playbookStep;
    event.currentTarget.disabled = true;
    const payload = await apiFetch(`/api/playbook/${encodeURIComponent(selectedAlertId)}/${encodeURIComponent(stepIndex)}`, { method: "POST" });
    event.currentTarget.disabled = false;
    if (!payload) {
        event.currentTarget.checked = !event.currentTarget.checked;
        showUiMessage("Unable to update playbook progress.", "error");
        return;
    }
    renderPlaybook(payload.playbook);
    await loadTimeline(selectedAlertId);
}

/** Render a compact recent alert feed in Command Center. */
function renderCommandSnapshot(latestAlerts) {
    const feed = $("#commandRecentSnapshot");
    if (!feed) {
        return;
    }
    if (!latestAlerts.length) {
        feed.innerHTML = '<div class="empty">Waiting for telemetry...</div>';
        return;
    }
    feed.innerHTML = latestAlerts.slice(0, 5).map(renderFeedItem).join("");
}

/** Render one live feed item. */
function renderFeedItem(alert) {
    return `
        <div class="feed-item">
            <strong>${escapeHtml(alert.alert_type)} ${severityBadge(alert.severity)} ${statusBadge(alert.status)}</strong>
            <span>${escapeHtml(alert.timestamp)} · <span data-relative-time="${escapeHtml(alert.timestamp)}">${relativeTime(alert.timestamp)}</span></span>
            <div class="mono">${escapeHtml(alert.alert_id)} · ${escapeHtml(alert.source_ip)} → ${escapeHtml(alert.dest_ip)}</div>
        </div>
    `;
}

/** Render the case management board grouped by status. */
function renderCaseQueue() {
    const board = $("#caseQueueColumns");
    if (!board) {
        return;
    }
    const statuses = ["new", "investigating", "escalated", "closed"];
    board.innerHTML = statuses.map(function renderColumn(status) {
        const cards = allAlerts.filter(function filterByStatus(alert) {
            return alert.status === status;
        }).slice(0, 12);
        return `
            <section class="case-column">
                <h2>${escapeHtml(status.toUpperCase())} (${allAlerts.filter(function countStatus(alert) { return alert.status === status; }).length})</h2>
                ${cards.length ? cards.map(renderCaseCard).join("") : '<div class="empty">No cases in this state.</div>'}
            </section>
        `;
    }).join("");
    const buttons = $all("[data-case-open]");
    for (let index = 0; index < buttons.length; index += 1) {
        buttons[index].addEventListener("click", function handleCaseOpen(event) {
            selectAlert(event.currentTarget.dataset.caseOpen, true);
        });
    }
}

/** Render one case card for the Case Queue workspace. */
function renderCaseCard(alert) {
    const rowClass = alert.alert_id === highlightedAlertId ? "new-alert" : "";
    return `
        <article class="case-card ${rowClass}">
            <strong>${escapeHtml(alert.alert_id)}</strong>
            <span>${escapeHtml(alert.alert_type)} · ${escapeHtml(alert.source_ip)}</span>
            <div>${severityBadge(alert.severity)}</div>
            <button class="ghost-btn" type="button" data-case-open="${escapeHtml(alert.alert_id)}">Open Case</button>
        </article>
    `;
}

/** Count alerts matching a predicate. */
function countAlerts(predicate) {
    return allAlerts.filter(predicate).length;
}

/** Calculate repeated source IP count for volatility scoring. */
function repeatedSourceIpCount() {
    const counts = {};
    for (let index = 0; index < allAlerts.length; index += 1) {
        counts[allAlerts[index].source_ip] = (counts[allAlerts[index].source_ip] || 0) + 1;
    }
    return Object.values(counts).filter(function isRepeated(count) {
        return count > 1;
    }).length;
}

/** Calculate the simulated Threat Volatility Index. */
function calculateVolatilityIndex(stats) {
    const severity = stats.count_per_severity || {};
    const status = stats.count_per_status || {};
    const types = stats.alert_count_by_type || {};
    const value =
        (severity.critical || 0) * 5 +
        (severity.high || 0) * 3 +
        (stats.open_investigations || 0) * 1.2 +
        (status.escalated || 0) * 4 +
        repeatedSourceIpCount() * 3 +
        (types.command_and_control || 0) * 4 +
        (types.malware_download || 0) * 3;
    return Math.min(100, Math.round(value));
}

/** Map volatility score to a SOC level label. */
function volatilityLevel(score) {
    if (score >= 85) {
        return "SEVERE";
    }
    if (score >= 68) {
        return "HIGH";
    }
    if (score >= 45) {
        return "ELEVATED";
    }
    if (score >= 22) {
        return "GUARDED";
    }
    return "LOW";
}

/** Render all Threat Market View visuals. */
function renderThreatMarket(stats) {
    renderThreatTicker(stats);
    renderVolatilityIndex(stats);
    renderPressureBoard(stats);
    updateSparkHistory(stats);
    renderSparklines();
    renderThreatMovementFeed(stats);
    window.requestAnimationFrame(renderVolatilityCanvas);
}

/** Render the horizontal threat ticker tape. */
function renderThreatTicker(stats) {
    const track = $("#threatTickerTrack");
    if (!track) {
        return;
    }
    const severity = stats.count_per_severity || {};
    const types = stats.alert_count_by_type || {};
    const items = [
        `CRITICAL +${severity.critical || 0}`,
        `HIGH +${severity.high || 0}`,
        `BRUTE_FORCE +${types.brute_force || 0}`,
        `PHISHING +${types.phishing_email || 0}`,
        `C2_TRAFFIC +${types.command_and_control || 0}`,
        `POWERSHELL +${types.powershell_execution || 0}`,
        `WEB_ATTACK +${types.web_attack || 0}`
    ];
    track.innerHTML = items.map(function renderTickerItem(item) {
        const isHot = item.includes("CRITICAL") || item.includes("HIGH") || item.includes("C2");
        return `<span class="${isHot ? "ticker-hot" : "ticker-cool"}">${escapeHtml(item)}</span>`;
    }).join(" | ");
}

/** Render the Threat Volatility Index card. */
function renderVolatilityIndex(stats) {
    const score = calculateVolatilityIndex(stats);
    $("#volatilityScore").textContent = score;
    $("#volatilityLevel").textContent = volatilityLevel(score);
}

/** Render case pressure rows with percentage bars. */
function renderPressureBoard(stats) {
    const board = $("#pressureBoard");
    if (!board) {
        return;
    }
    const severity = stats.count_per_severity || {};
    const status = stats.count_per_status || {};
    const rows = [
        ["Critical Queue", severity.critical || 0, CHART_COLORS.critical],
        ["High Queue", severity.high || 0, CHART_COLORS.high],
        ["Medium Queue", severity.medium || 0, CHART_COLORS.medium],
        ["Low Queue", severity.low || 0, CHART_COLORS.low],
        ["Escalated Cases", status.escalated || 0, CHART_COLORS.critical],
        ["Closed Cases", status.closed || 0, CHART_COLORS.closed]
    ];
    const max = Math.max.apply(null, rows.map(function rowValue(row) { return row[1]; }).concat([1]));
    board.innerHTML = rows.map(function renderPressureRow(row) {
        const width = Math.max(4, Math.round((row[1] / max) * 100));
        return `
            <div class="pressure-row">
                <span>${escapeHtml(row[0])}</span>
                <strong class="mono">${row[1]}</strong>
                <div class="pressure-bar"><i style="width:${width}%; color:${row[2]}; background:${row[2]}"></i></div>
            </div>
        `;
    }).join("");
}

/** Push current values into sparkline history arrays. */
function updateSparkHistory(stats) {
    const status = stats.count_per_status || {};
    const values = {
        total: stats.total_alerts || 0,
        critical: stats.critical_alerts || 0,
        open: stats.open_investigations || 0,
        escalated: status.escalated || 0
    };
    const keys = Object.keys(values);
    for (let index = 0; index < keys.length; index += 1) {
        const key = keys[index];
        const last = sparkHistory[key][sparkHistory[key].length - 1];
        if (last !== values[key]) {
            sparkHistory[key].push(values[key]);
            if (sparkHistory[key].length > 18) {
                sparkHistory[key].shift();
            }
        }
    }
}

/** Render all mini sparkline canvases. */
function renderSparklines() {
    renderSparkline("sparkTotal", sparkHistory.total, CHART_COLORS.cyan || "#00e5ff");
    renderSparkline("sparkCritical", sparkHistory.critical, CHART_COLORS.critical);
    renderSparkline("sparkOpen", sparkHistory.open, CHART_COLORS.high);
    renderSparkline("sparkEscalated", sparkHistory.escalated, CHART_COLORS.critical);
}

/** Render one mini sparkline. */
function renderSparkline(id, points, color) {
    const canvas = $(`#${id}`);
    if (!canvas) {
        return;
    }
    const ctx = canvas.getContext("2d");
    const width = canvas.width;
    const height = canvas.height;
    const max = Math.max.apply(null, points.concat([1]));
    ctx.clearRect(0, 0, width, height);
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.beginPath();
    for (let index = 0; index < points.length; index += 1) {
        const x = points.length === 1 ? 0 : (index / (points.length - 1)) * width;
        const y = height - 5 - (points[index] / max) * (height - 10);
        if (index === 0) {
            ctx.moveTo(x, y);
        } else {
            ctx.lineTo(x, y);
        }
    }
    ctx.stroke();
}

/** Build 5-minute simulated SOC candles from recent alert windows. */
function buildCandles() {
    const sorted = allAlerts.slice().sort(function sortByTime(a, b) {
        return parseTimestamp(a.timestamp) - parseTimestamp(b.timestamp);
    });
    const latest = sorted.slice(-60);
    const candles = [];
    for (let index = 0; index < 12; index += 1) {
        const segment = latest.slice(index * 5, index * 5 + 5);
        const prev = index === 0 ? Math.max(segment.length - 1, 0) : candles[index - 1].close;
        const weighted = segment.reduce(function severityWeight(sum, alert) {
            return sum + ({ low: 1, medium: 2, high: 3, critical: 5 }[alert.severity] || 1);
        }, 0);
        const close = segment.length + Math.round(weighted / 4);
        candles.push({
            open: prev,
            high: Math.max(prev, close) + Math.max(1, Math.round(weighted / 6)),
            low: Math.max(0, Math.min(prev, close) - 1),
            close: close,
            label: `${index * 5}m`
        });
    }
    return candles;
}

/** Render the custom candlestick-style Alert Volatility Monitor. */
function renderVolatilityCanvas() {
    const canvas = $("#volatilityCanvas");
    if (!canvas) {
        return;
    }
    const ctx = canvas.getContext("2d");
    const width = canvas.width;
    const height = canvas.height;
    const candles = buildCandles();
    const max = Math.max.apply(null, candles.map(function candleMax(candle) { return candle.high; }).concat([1]));
    const pad = 36;
    const slot = (width - pad * 2) / candles.length;
    ctx.clearRect(0, 0, width, height);
    ctx.strokeStyle = "rgba(138,164,178,0.14)";
    ctx.lineWidth = 1;
    for (let line = 0; line < 5; line += 1) {
        const y = pad + ((height - pad * 2) / 4) * line;
        ctx.beginPath();
        ctx.moveTo(pad, y);
        ctx.lineTo(width - pad, y);
        ctx.stroke();
    }
    for (let index = 0; index < candles.length; index += 1) {
        drawCandle(ctx, candles[index], index, slot, pad, width, height, max);
    }
}

/** Convert a candle value into a canvas Y coordinate. */
function candleY(value, height, pad, max) {
    return height - pad - (value / max) * (height - pad * 2);
}

/** Draw one alert-volatility candle. */
function drawCandle(ctx, candle, index, slot, pad, width, height, max) {
    const center = pad + slot * index + slot / 2;
    const openY = candleY(candle.open, height, pad, max);
    const closeY = candleY(candle.close, height, pad, max);
    const highY = candleY(candle.high, height, pad, max);
    const lowY = candleY(candle.low, height, pad, max);
    const increased = candle.close > candle.open;
    const color = increased ? CHART_COLORS.high : CHART_COLORS.low;
    const bodyTop = Math.min(openY, closeY);
    const bodyHeight = Math.max(Math.abs(closeY - openY), 5);
    ctx.strokeStyle = color;
    ctx.fillStyle = increased ? "rgba(255,159,28,0.42)" : "rgba(0,229,255,0.34)";
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(center, highY);
    ctx.lineTo(center, lowY);
    ctx.stroke();
    ctx.fillRect(center - slot * 0.22, bodyTop, slot * 0.44, bodyHeight);
    ctx.strokeRect(center - slot * 0.22, bodyTop, slot * 0.44, bodyHeight);
}

/** Render live market movement feed messages. */
function renderThreatMovementFeed(stats) {
    const feed = $("#marketMovementFeed");
    if (!feed) {
        return;
    }
    const now = new Date().toLocaleTimeString("en-US", { hour12: false });
    const severity = stats.count_per_severity || {};
    const status = stats.count_per_status || {};
    const mitre = stats.mitre_tactic_distribution || {};
    const topMitre = Object.entries(mitre).sort(function sortByCount(a, b) { return b[1] - a[1]; })[0] || ["MITRE tactic mapping", 0];
    const messages = [
        `[${now}] CRITICAL alert volume at ${severity.critical || 0}`,
        `[${now}] Open investigations ${Number(status.new || 0) + Number(status.investigating || 0) + Number(status.escalated || 0)}`,
        `[${now}] ${topMitre[0]} activity count ${topMitre[1]}`,
        `[${now}] Threat Volatility Index ${calculateVolatilityIndex(stats)} / 100`
    ];
    feed.innerHTML = messages.map(function renderMovement(message) {
        return `<div class="feed-item"><strong>${escapeHtml(message)}</strong><span>simulated SOC movement</span></div>`;
    }).join("");
}

/** Render MITRE workspace technique cards and heatmap matrix. */
function renderMitreWorkspace() {
    const cards = $("#techniqueCards");
    const matrix = $("#mitreMatrix");
    if (!cards || !matrix) {
        return;
    }
    const classified = allAlerts.filter(function hasMitre(alert) {
        return Boolean(alert.mitre_tactic);
    });
    cards.innerHTML = classified.slice(0, 12).map(function renderTechnique(alert) {
        return `
            <div class="technique-card">
                <strong>${escapeHtml(alert.mitre_technique || "Unclassified")}</strong>
                <span>${escapeHtml(alert.alert_type)} · ${escapeHtml(alert.alert_id)}</span>
                <p>${escapeHtml(alert.mitre_description || "Classify this alert to populate ATT&CK context.")}</p>
            </div>
        `;
    }).join("") || '<div class="empty">Classify alerts from the War Room to populate technique cards.</div>';
    const counts = currentStats ? currentStats.mitre_tactic_distribution || {} : {};
    matrix.innerHTML = Object.keys(counts).map(function renderMatrixCell(tactic) {
        const count = counts[tactic];
        const heat = count >= 5 ? "hot" : count >= 2 ? "warm" : "cool";
        return `<div class="matrix-cell ${heat}"><strong>${escapeHtml(tactic)}</strong><span class="mono">${count} mapped alerts</span></div>`;
    }).join("") || '<div class="empty">No mapped tactics yet.</div>';
}

/** Render threat intelligence workspace for the selected case. */
function renderIntelWorkspace() {
    const summary = $("#intelSourceSummary");
    const repeated = $("#repeatedSourceIps");
    const iocs = $("#iocSummary");
    if (!summary || !repeated || !iocs) {
        return;
    }
    if (!selectedAlert) {
        summary.textContent = "Select an alert to inspect source reputation.";
    } else {
        summary.innerHTML = `
            <div class="detail-grid">
                <div class="detail-box"><span>Source IP</span><strong>${escapeHtml(selectedAlert.source_ip)}</strong></div>
                <div class="detail-box"><span>Reputation Score</span><strong>${escapeHtml(selectedAlert.reputation_score || 0)}</strong></div>
                <div class="detail-box"><span>Enrichment Status</span><strong>${selectedAlert.reputation_result ? "Available" : "Not Run"}</strong></div>
                <div class="detail-box"><span>Alert ID</span><strong>${escapeHtml(selectedAlert.alert_id)}</strong></div>
            </div>
            <p>${escapeHtml(selectedAlert.reputation_result || "Run Enrich IP in the War Room to save a VirusTotal result or no-key fallback message.")}</p>
        `;
    }
    renderRepeatedSources(repeated);
    renderIocSummary(iocs);
}

/** Render repeated source IP indicators. */
function renderRepeatedSources(container) {
    const counts = {};
    for (let index = 0; index < allAlerts.length; index += 1) {
        counts[allAlerts[index].source_ip] = (counts[allAlerts[index].source_ip] || 0) + 1;
    }
    const rows = Object.entries(counts).sort(function sortSources(a, b) { return b[1] - a[1]; }).slice(0, 8);
    container.innerHTML = rows.map(function renderSource(row) {
        return `<div class="pressure-row"><span class="mono">${escapeHtml(row[0])}</span><strong>${row[1]} alerts</strong></div>`;
    }).join("") || '<div class="empty">No repeated source indicators.</div>';
}

/** Extract simple IOCs from the selected raw log. */
function extractIocs(text) {
    const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    const domainRegex = /\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
    const ips = Array.from(new Set((text.match(ipRegex) || [])));
    const domains = Array.from(new Set((text.match(domainRegex) || [])));
    return { ips: ips, domains: domains };
}

/** Render IOC summary cards. */
function renderIocSummary(container) {
    if (!selectedAlert) {
        container.innerHTML = '<div class="empty">Select an alert to extract IOCs.</div>';
        return;
    }
    const iocs = extractIocs(selectedAlert.raw_log || "");
    const cards = [];
    for (let index = 0; index < iocs.ips.length; index += 1) {
        cards.push(`<div class="ioc-card"><strong>IP</strong><span class="mono">${escapeHtml(iocs.ips[index])}</span></div>`);
    }
    for (let index = 0; index < iocs.domains.length; index += 1) {
        cards.push(`<div class="ioc-card"><strong>DOMAIN</strong><span class="mono">${escapeHtml(iocs.domains[index])}</span></div>`);
    }
    container.innerHTML = cards.join("") || '<div class="empty">No IOCs extracted from selected raw log.</div>';
}

/** Render Detection Engineering Lab content. */
function renderDetectionLab() {
    const container = $("#detectionGuidance");
    if (!container) {
        return;
    }
    const type = selectedAlert ? selectedAlert.alert_type : "select_alert";
    const guidance = detectionGuidance(type);
    container.innerHTML = guidance.map(function renderGuidance(card) {
        return `<article class="detection-card"><strong>${escapeHtml(card.title)}</strong><p>${escapeHtml(card.body)}</p></article>`;
    }).join("");
}

/** Populate the Sigma alert selector without duplicating options. */
function populateSigmaAlertSelector() {
    const select = $("#sigmaAlertSelect");
    if (!select) {
        return;
    }
    const currentValue = select.value || selectedAlertId || "";
    const options = ['<option value="">Select an alert</option>'].concat(allAlerts.map(function renderOption(alert) {
        return `<option value="${escapeHtml(alert.alert_id)}">${escapeHtml(alert.alert_id)} · ${escapeHtml(alert.alert_type)}</option>`;
    }));
    select.innerHTML = options.join("");
    if (currentValue && allAlerts.some(function hasAlert(alert) { return alert.alert_id === currentValue; })) {
        select.value = currentValue;
    } else if (selectedAlertId) {
        select.value = selectedAlertId;
    }
}

/** Render selected alert metadata for Sigma generation context. */
function renderSigmaMetadata() {
    const meta = $("#sigmaAlertMeta");
    const select = $("#sigmaAlertSelect");
    if (!meta || !select) {
        return;
    }
    const alertId = select.value || selectedAlertId;
    const alert = allAlerts.find(function findAlert(item) {
        return item.alert_id === alertId;
    }) || selectedAlert;
    if (!alert) {
        meta.textContent = "Select an alert to review detection context.";
        return;
    }
    if (!select.value) {
        select.value = alert.alert_id;
    }
    meta.innerHTML = `
        <span>${escapeHtml(alert.alert_type)}</span>
        ${severityBadge(alert.severity)}
        <span>${escapeHtml(alert.mitre_tactic || "Unclassified MITRE tactic")}</span>
    `;
}

/** Handle a Sigma alert selection change. */
function handleSigmaSelectionChange() {
    lastSigmaYaml = "";
    $("#sigmaOutput").textContent = "# Sigma output will appear here after generation.";
    renderSigmaMetadata();
}

/** Generate a Sigma YAML rule for the selected alert. */
async function generateSigmaRule(event) {
    const select = $("#sigmaAlertSelect");
    const output = $("#sigmaOutput");
    if (!select || !select.value) {
        showUiMessage("Select an alert before generating a Sigma rule.", "error");
        return;
    }
    await withButtonLoading(event.currentTarget, "GENERATING...", async function runSigmaGeneration() {
        const payload = await apiFetch(`/api/sigma/${encodeURIComponent(select.value)}`);
        if (!payload) {
            output.textContent = "# Sigma generation failed. Check the API response and selected alert.";
            showUiMessage("Unable to generate Sigma rule.", "error");
            return;
        }
        lastSigmaYaml = payload.sigma_yaml || "";
        output.textContent = lastSigmaYaml || "# No Sigma YAML returned.";
        showUiMessage(`Sigma rule generated for ${payload.alert_id}.`, "success");
    });
}

/** Copy the latest Sigma YAML to the clipboard. */
async function copySigmaRule(event) {
    if (!lastSigmaYaml) {
        showUiMessage("Generate a Sigma rule before copying.", "error");
        return;
    }
    await withButtonLoading(event.currentTarget, "COPYING...", async function runCopy() {
        try {
            await navigator.clipboard.writeText(lastSigmaYaml);
            showUiMessage("Sigma rule copied to clipboard.", "success");
        } catch (error) {
            showUiMessage("Clipboard copy failed in this browser.", "error");
        }
    }, "COPIED");
}

/** Return detection guidance cards for an alert type. */
function detectionGuidance(type) {
    const base = {
        brute_force: ["Authentication logs, VPN logs, IAM events", "source_ip, username, failure_count, success_after_failure", "Known scanners, password manager retries, misconfigured services"],
        port_scan: ["Firewall denies, IDS alerts, NetFlow", "source_ip, dest_ip, dest_port, connection_count", "Approved vulnerability scanners and asset discovery tools"],
        phishing_email: ["Mail gateway, URL sandbox, identity logs", "sender, recipient, url, subject, verdict", "Security awareness tests and legitimate bulk mail"],
        malware_download: ["Proxy, EDR, file reputation", "filename, hash, source_ip, download_url", "Admin tools and software distribution packages"],
        suspicious_login: ["IAM, VPN, MFA, endpoint logs", "user, source_ip, device_id, geo, mfa_result", "Travel, new corporate devices, VPN egress changes"],
        powershell_execution: ["EDR process telemetry, command line logs", "process_name, parent_process, command_line, host", "Admin scripts and IT automation"],
        command_and_control: ["Proxy, DNS, NetFlow, EDR network events", "beacon_interval, domain, user_agent, process", "Monitoring agents and updater traffic"],
        web_attack: ["WAF, web server, application logs", "uri, method, status_code, payload_pattern", "Scanners and benign input validation failures"],
        lateral_movement: ["Windows event logs, EDR, SMB/RDP telemetry", "source_host, dest_host, user, logon_type", "Admin maintenance and backup jobs"],
        dns_tunneling: ["DNS resolver logs, proxy, EDR DNS events", "query, query_length, entropy, count", "CDNs and telemetry-heavy SaaS domains"],
        privilege_escalation: ["EDR process and privilege events", "process, user, integrity_level, exploit_indicator", "Installer processes and approved admin tools"],
        data_exfiltration: ["DLP, proxy, firewall, cloud audit logs", "bytes_out, destination, user, data_classification", "Backups, reporting exports, approved transfers"],
        select_alert: ["Select a case", "Choose an alert from Live Alert Feed or Case Queue.", "Detection guidance will adapt to the alert type."]
    };
    const row = base[type] || base.select_alert;
    return [
        { title: "Required Logs", body: row[0] },
        { title: "Useful Fields", body: row[1] },
        { title: "False Positive Considerations", body: row[2] },
        { title: "Sigma-Style Rule Idea", body: `Detect ${type.replaceAll("_", " ")} patterns where key fields exceed baseline thresholds and context is not allowlisted.` }
    ];
}

/** Render report-ready summary for the selected case. */
function renderReportsWorkspace() {
    const caseSummary = $("#reportCaseSummary");
    const analystSummary = $("#reportAnalystSummary");
    if (!caseSummary || !analystSummary) {
        return;
    }
    if (!selectedAlert) {
        caseSummary.textContent = "Select an alert to build a report.";
        analystSummary.textContent = "No analyst notes loaded.";
        return;
    }
    caseSummary.innerHTML = `
        <strong>${escapeHtml(selectedAlert.alert_id)}</strong>
        <p>${escapeHtml(selectedAlert.alert_type)} · ${severityBadge(selectedAlert.severity)} · ${statusBadge(selectedAlert.status)}</p>
        <p class="mono">${escapeHtml(selectedAlert.source_ip)} → ${escapeHtml(selectedAlert.dest_ip)}</p>
        <p>${escapeHtml(selectedAlert.raw_log)}</p>
    `;
    analystSummary.innerHTML = `
        <strong>Notes</strong><p>${escapeHtml(selectedAlert.analyst_notes || "No analyst notes saved.")}</p>
        <strong>Investigation Summary</strong><p>${escapeHtml(selectedAlert.investigation_summary || "No investigation summary saved.")}</p>
    `;
}

/** Generate and render an eight-hour SOC shift handoff report. */
async function generateShiftReport(event) {
    await withButtonLoading(event.currentTarget, "GENERATING...", async function runShiftReport() {
        const report = await apiFetch("/api/reports/shift");
        if (!report) {
            showUiMessage("Unable to generate shift handoff report.", "error");
            return;
        }
        renderShiftReport(report);
        showToast("Shift report generated.", "success");
    });
}

/** Render shift report JSON into a print-ready analyst handoff panel. */
function renderShiftReport(report) {
    const panel = $("#shiftReportPanel");
    const content = $("#shiftReportContent");
    if (!panel || !content) {
        return;
    }
    if (!report) {
        return;
    }
    panel.classList.remove("hidden");
    const severity = report.by_severity || {};
    const status = report.by_status || {};
    const topMitre = report.top_mitre_tactics || [];
    const criticalOpen = report.critical_open || [];
    content.innerHTML = `
        <div class="shift-report-header">
            <h2>SentinelOps SOC Shift Handoff</h2>
            <p><strong>Analyst:</strong> ${escapeHtml(report.analyst)} · <strong>Generated:</strong> ${escapeHtml(report.report_generated_at)} · <strong>Period:</strong> ${escapeHtml(report.period)}</p>
        </div>
        <div class="shift-stat-grid">
            <div><span>Total Alerts</span><strong>${escapeHtml(report.total_alerts)}</strong></div>
            <div><span>Closed This Shift</span><strong>${escapeHtml(report.closed_this_shift)}</strong></div>
            <div><span>MTTD</span><strong>${escapeHtml(report.mttd_this_shift)}</strong></div>
            <div><span>MTTR</span><strong>${escapeHtml(report.mttr_this_shift)}</strong></div>
        </div>
        <div class="shift-report-columns">
            <section>
                <h3>Severity Breakdown</h3>
                ${renderReportRows(severity)}
            </section>
            <section>
                <h3>Status Breakdown</h3>
                ${renderReportRows(status)}
            </section>
            <section>
                <h3>Top MITRE Tactics</h3>
                ${topMitre.length ? topMitre.map(function renderMitreRow(item) {
                    return `<div class="report-row"><span>${escapeHtml(item.tactic)}</span><strong>${escapeHtml(item.count)}</strong></div>`;
                }).join("") : '<div class="empty">No mapped MITRE tactics this shift.</div>'}
            </section>
        </div>
        <section class="shift-critical-section">
            <h3>Critical / High Open Items</h3>
            ${criticalOpen.length ? `
                <div class="table-wrap compact-table">
                    <table>
                        <thead><tr><th>Alert ID</th><th>Type</th><th>Source IP</th><th>Timestamp</th></tr></thead>
                        <tbody>
                            ${criticalOpen.map(function renderCritical(alert) {
                                return `<tr><td class="mono">${escapeHtml(alert.alert_id)}</td><td>${escapeHtml(alert.alert_type)}</td><td class="ip-cell">${escapeHtml(alert.source_ip)}</td><td class="time-cell">${escapeHtml(alert.timestamp)}</td></tr>`;
                            }).join("")}
                        </tbody>
                    </table>
                </div>
            ` : '<div class="empty">No critical or high open items in this shift window.</div>'}
        </section>
    `;
}

/** Render simple key/count rows inside the shift report. */
function renderReportRows(rows) {
    const entries = Object.entries(rows || {});
    if (!entries.length) {
        return '<div class="empty">No data available.</div>';
    }
    return entries.map(function renderRow(row) {
        return `<div class="report-row"><span>${escapeHtml(row[0])}</span><strong>${escapeHtml(row[1])}</strong></div>`;
    }).join("");
}

/** Print the visible shift report through the browser native print dialog. */
function printShiftReport() {
    window.print();
}

/** Hide the generated shift report panel. */
function closeShiftReport() {
    const panel = $("#shiftReportPanel");
    if (panel) {
        panel.classList.add("hidden");
    }
}

/** Update one alert in local state without forcing a full API refresh. */
function updateLocalAlert(updatedAlert) {
    if (!updatedAlert) {
        return;
    }
    allAlerts = allAlerts.map(function replaceAlert(alert) {
        return alert.alert_id === updatedAlert.alert_id ? updatedAlert : alert;
    });
    filteredAlerts = filteredAlerts.map(function replaceFilteredAlert(alert) {
        return alert.alert_id === updatedAlert.alert_id ? updatedAlert : alert;
    });
    if (selectedAlertId === updatedAlert.alert_id) {
        selectedAlert = updatedAlert;
    }
}

/** Classify the selected alert with MITRE ATT&CK mapping. */
async function classifySelectedAlert(event) {
    if (!selectedAlertId) {
        return;
    }
    await withButtonLoading(event.currentTarget, "CLASSIFYING...", async function runClassification() {
        const payload = await apiFetch(`/api/classify/${encodeURIComponent(selectedAlertId)}`, { method: "POST" });
        if (!payload) {
            return;
        }
        updateLocalAlert(payload.alert);
        statsCache = null;
        renderInvestigation(payload.alert);
        await loadTimeline(selectedAlertId);
        await refreshDashboard();
        showToast("MITRE classification saved.", "success");
    });
}

/** Enrich the selected alert source IP. */
async function enrichSelectedAlert(event) {
    if (!selectedAlertId) {
        return;
    }
    await withButtonLoading(event.currentTarget, "ENRICHING...", async function runEnrichment() {
        const payload = await apiFetch(`/api/enrich/${encodeURIComponent(selectedAlertId)}`, { method: "POST" });
        if (!payload) {
            renderEnrichmentError();
            return;
        }
        if (payload.alert) {
            updateLocalAlert(payload.alert);
            $("#detailReputation").textContent = payload.alert.reputation_score || 0;
        }
        if (payload.status === "no_key") {
            renderEnrichmentWarning("Add VIRUSTOTAL_API_KEY=your_key to your .env file and restart the server.");
            showToast("VirusTotal API key is not configured.", "info");
        } else if (payload.status === "success") {
            renderEnrichmentSuccess(payload);
            showToast("VirusTotal enrichment completed.", "success");
        } else {
            renderEnrichmentError();
        }
        await loadTimeline(selectedAlertId);
        renderIntelWorkspace();
    });
}

/** Save analyst notes and investigation summary for the selected alert. */
async function saveSelectedNotes(event) {
    if (!selectedAlertId) {
        return;
    }
    await withButtonLoading(event.currentTarget, "SAVING...", async function runSaveNotes() {
        const payload = await apiFetch(`/api/update_notes/${encodeURIComponent(selectedAlertId)}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                analyst_notes: $("#analystNotes").value,
                investigation_summary: $("#investigationSummary").value
            })
        });
        if (!payload) {
            return;
        }
        updateLocalAlert(payload.alert);
        await loadTimeline(selectedAlertId);
        renderReportsWorkspace();
    }, "SAVED ✓");
}

/** Update the selected alert status. */
async function updateSelectedStatus(event) {
    if (!selectedAlertId) {
        return;
    }
    const oldStatus = selectedAlert ? selectedAlert.status : "";
    const newStatus = $("#statusSelect").value;
    const originalAlert = selectedAlert ? Object.assign({}, selectedAlert) : null;
    if (selectedAlert) {
        updateLocalAlert(Object.assign({}, selectedAlert, { status: newStatus }));
    }
    $("#detailStatus").textContent = newStatus;
    renderAlertTable();
    await withButtonLoading(event.currentTarget, "UPDATING...", async function runStatusUpdate() {
        const payload = await apiFetch(`/api/update_status/${encodeURIComponent(selectedAlertId)}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: newStatus })
        });
        if (!payload) {
            if (originalAlert) {
                updateLocalAlert(Object.assign({}, originalAlert, { status: oldStatus }));
            }
            $("#detailStatus").textContent = oldStatus;
            $("#statusSelect").value = oldStatus;
            renderAlertTable();
            showToast("Status update failed and was reverted.", "error");
            return;
        }
        updateLocalAlert(payload.alert);
        statsCache = null;
        await loadStats(true);
        await loadTimeline(selectedAlertId);
        renderCaseQueue();
        renderReportsWorkspace();
        showToast("Status updated.", "success");
    });
}

/** Export the selected investigation as a JSON download. */
async function exportSelectedInvestigation(event) {
    if (!selectedAlertId) {
        return;
    }
    await withButtonLoading(event.currentTarget, "EXPORTING...", async function runExport() {
        const payload = await apiFetch(`/api/export/${encodeURIComponent(selectedAlertId)}`);
        if (!payload) {
            return;
        }
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `${selectedAlertId}-investigation.json`;
        link.click();
        URL.revokeObjectURL(url);
        showToast("Investigation JSON exported.", "success");
    });
}

/** Update visible simulation state indicators. */
function setSimulationState(active) {
    const readout = $("#simulationState");
    const readiness = $("#readinessSimulation");
    if (readout) {
        readout.textContent = active ? "ACTIVE" : "PAUSED";
        readout.classList.toggle("active", active);
    }
    if (readiness) {
        readiness.textContent = active ? "Running" : "Paused";
    }
}

/** Start live simulation mode and create alerts every five seconds. */
async function startLiveSimulation(button) {
    if (liveSimulationTimer) {
        return;
    }
    setSimulationState(true);
    const started = await withButtonLoading(button, "STARTING...", simulateOneAlert, "RUNNING");
    if (started) {
        liveSimulationTimer = window.setInterval(simulateOneAlert, 5000);
    }
}

/** Pause live simulation mode. */
function pauseLiveSimulation() {
    window.clearInterval(liveSimulationTimer);
    liveSimulationTimer = null;
    setSimulationState(false);
}

/** Request one safe simulated alert from the backend. */
async function simulateOneAlert() {
    const payload = await apiFetch("/api/simulate_alert", { method: "POST" });
    if (!payload || !payload.alert) {
        pauseLiveSimulation();
        showUiMessage("Live simulation paused because alert generation failed.", "error");
        return false;
    }
    applySimulatedAlert(payload.alert);
    return true;
}

/** Apply one simulated alert to visible tables and metric cards without redrawing every chart. */
function applySimulatedAlert(alert) {
    highlightedAlertId = alert.alert_id;
    allAlerts.unshift(alert);
    if (alertMatchesCurrentFilters(alert)) {
        filteredAlerts.unshift(alert);
    }
    if (currentStats) {
        currentStats.total_alerts = Number(currentStats.total_alerts || 0) + 1;
        currentStats.latest_10_alerts = [alert].concat(currentStats.latest_10_alerts || []).slice(0, 10);
        currentStats.count_per_severity = currentStats.count_per_severity || {};
        currentStats.count_per_status = currentStats.count_per_status || {};
        currentStats.count_per_severity[alert.severity] = Number(currentStats.count_per_severity[alert.severity] || 0) + 1;
        currentStats.count_per_status[alert.status] = Number(currentStats.count_per_status[alert.status] || 0) + 1;
        if (alert.severity === "critical") {
            currentStats.critical_alerts = Number(currentStats.critical_alerts || 0) + 1;
        }
        if (["new", "investigating", "escalated"].includes(alert.status)) {
            currentStats.open_investigations = Number(currentStats.open_investigations || 0) + 1;
        }
        statsCache = currentStats;
        statsCacheTime = Date.now();
        renderMetrics(currentStats);
    }
    renderAlertTable();
    updateRelativeTimes();
    showToast("New simulated alert ingested.", "success");
}

/** Check if an alert should be visible under the current table filters. */
function alertMatchesCurrentFilters(alert) {
    const severity = $("#severityFilter")?.value || "";
    const status = $("#statusFilter")?.value || "";
    const alertType = $("#typeFilter")?.value || "";
    const search = ($("#searchFilter")?.value || "").trim().toLowerCase();
    if (severity && alert.severity !== severity) {
        return false;
    }
    if (status && alert.status !== status) {
        return false;
    }
    if (alertType && alert.alert_type !== alertType) {
        return false;
    }
    if (search) {
        const haystack = `${alert.alert_id} ${alert.source_ip} ${alert.dest_ip}`.toLowerCase();
        return haystack.includes(search);
    }
    return true;
}

/** Add a subtle pulse to live panels every second. */
function pulseLivePanels() {
    const panels = [$(".ticker-shell"), $(".feed-panel")].filter(Boolean);
    for (let index = 0; index < panels.length; index += 1) {
        panels[index].classList.remove("pulse-refresh");
        void panels[index].offsetWidth;
        panels[index].classList.add("pulse-refresh");
    }
}

/** Populate the alert type dropdown. */
function populateTypeFilter() {
    const select = $("#typeFilter");
    if (!select || select.children.length > 1) {
        return;
    }
    for (let index = 0; index < ALERT_TYPES.length; index += 1) {
        const option = document.createElement("option");
        option.value = ALERT_TYPES[index];
        option.textContent = ALERT_TYPES[index];
        select.appendChild(option);
    }
}

/** Bind filter controls and case workflow actions. */
function bindEvents() {
    $("#refreshAlerts").addEventListener("click", handleRefreshClick);
    $("#severityFilter").addEventListener("change", loadFilteredAlerts);
    $("#statusFilter").addEventListener("change", loadFilteredAlerts);
    $("#typeFilter").addEventListener("change", loadFilteredAlerts);
    $("#searchFilter").addEventListener("input", function handleSearchInput() {
        window.clearTimeout(searchTimeout);
        searchTimeout = window.setTimeout(loadAlertFeed, 300);
    });
    $("#classifyBtn").addEventListener("click", classifySelectedAlert);
    $("#enrichBtn").addEventListener("click", enrichSelectedAlert);
    $("#saveNotesBtn").addEventListener("click", saveSelectedNotes);
    $("#updateStatusBtn").addEventListener("click", updateSelectedStatus);
    $("#exportBtn").addEventListener("click", exportSelectedInvestigation);
    $("#reportExportBtn").addEventListener("click", exportSelectedInvestigation);
    $("#playbookToggle").addEventListener("click", togglePlaybookPanel);
    $("#generateShiftReportBtn").addEventListener("click", generateShiftReport);
    $("#printShiftReportBtn").addEventListener("click", printShiftReport);
    $("#closeShiftReportBtn").addEventListener("click", closeShiftReport);
    $("#sigmaAlertSelect").addEventListener("change", handleSigmaSelectionChange);
    $("#generateSigmaBtn").addEventListener("click", generateSigmaRule);
    $("#copySigmaBtn").addEventListener("click", copySigmaRule);
    const simButtons = $all("[data-sim-action]");
    for (let index = 0; index < simButtons.length; index += 1) {
        simButtons[index].addEventListener("click", function handleSimClick(event) {
            if (event.currentTarget.dataset.simAction === "start") {
                startLiveSimulation(event.currentTarget);
            } else {
                pauseLiveSimulation();
            }
        });
    }
}

/** Execute the one-second monitoring tick. */
function runSecondTick() {
    updateClock();
    updateRelativeTimes();
    pulseLivePanels();
}

/** Run recurring one-second visual monitoring updates. */
function startSecondBySecondMonitoring() {
    updateClock();
    updateRelativeTimes();
    window.setInterval(runSecondTick, 1000);
}

/** Initialize the SentinelOps dashboard application. */
async function initDashboard() {
    populateTypeFilter();
    bindWorkspaceNavigation();
    bindEvents();
    startSecondBySecondMonitoring();
    await refreshDashboard();
    showWorkspace(activeWorkspaceId);
}

document.addEventListener("DOMContentLoaded", initDashboard);
