/**
 * QuantumGuard Frontend Application Controller.
 * Manages real-time scanning, Mosca risk scatter charts, CBOM filtering, and code diffs.
 */

let currentScanId = null;
let currentFindings = [];
let currentSummary = null;
let scatterChartInstance = null;
let doughnutChartInstance = null;
let pollInterval = null;

// On Page Load
document.addEventListener("DOMContentLoaded", () => {
    initApp();
    setupEventListeners();
});

async function initApp() {
    await loadSettings();
    await loadScansList();
}

function setupEventListeners() {
    document.getElementById("scanSelector").addEventListener("change", (e) => {
        if (e.target.value) {
            loadScan(parseInt(e.target.value));
        }
    });

    document.getElementById("searchInput").addEventListener("input", filterAndRenderTable);
    document.getElementById("filterRisk").addEventListener("change", filterAndRenderTable);
    document.getElementById("filterType").addEventListener("change", filterAndRenderTable);
    const timeline = document.getElementById("timelineYear");
    if (timeline) timeline.addEventListener("input", updateExecutiveLayer);
}

// --- API Calls ---

async function loadScansList() {
    try {
        const res = await fetch("/api/scans");
        const data = await res.json();
        const selector = document.getElementById("scanSelector");
        selector.innerHTML = "";

        if (!data.scans || data.scans.length === 0) {
            const opt = document.createElement("option");
            opt.value = "";
            opt.textContent = "No audits yet - Launch a scan";
            selector.appendChild(opt);
            // Auto open scan modal or load sample
            openNewScanModal();
            return;
        }

        data.scans.forEach((s) => {
            const opt = document.createElement("option");
            opt.value = s.id;
            opt.textContent = `#${s.id} - ${s.name} (${s.target_type}) - ${s.status}`;
            selector.appendChild(opt);
        });

        // Load the latest scan
        currentScanId = data.scans[0].id;
        selector.value = currentScanId;
        await loadScan(currentScanId);
    } catch (err) {
        console.error("Error loading scans list:", err);
    }
}

async function loadScan(scanId) {
    currentScanId = scanId;
    try {
        const res = await fetch(`/api/scans/${scanId}`);
        const data = await res.json();
        currentFindings = data.findings || [];

        // Also fetch dashboard aggregated summary
        const sumRes = await fetch(`/api/dashboard?scan_id=${scanId}`);
        currentSummary = await sumRes.json();

        updateKPIs(currentSummary);
        renderCharts(currentFindings, currentSummary);
        filterAndRenderTable();
        updateExecutiveLayer();

        // Select the highest risk finding for the diff studio by default
        if (currentFindings.length > 0) {
            selectFindingForDiff(currentFindings[0]);
        }
    } catch (err) {
        console.error("Error loading scan details:", err);
    }
}

async function loadSettings() {
    try {
        const res = await fetch("/api/settings");
        const data = await res.json();
        if (data.crqc_horizon_year) {
            document.getElementById("settingHorizon").value = data.crqc_horizon_year;
            const timeline = document.getElementById("timelineYear");
            if (timeline) timeline.value = Math.max(Number(timeline.min), Math.min(Number(timeline.max), Number(data.crqc_horizon_year)));
        }
        if (data.default_migration_time_years) {
            document.getElementById("settingMigration").value = data.default_migration_time_years;
        }
        if (data.default_shelf_life_years) {
            document.getElementById("settingShelf").value = data.default_shelf_life_years;
        }
    } catch (err) {
        console.error("Error loading settings:", err);
    }
}

// --- UI Updates ---

function updateKPIs(summary) {
    if (!summary) return;

    const readiness = summary.readiness_pct !== undefined ? summary.readiness_pct : 0;
    const critical = summary.hndl_critical !== undefined ? summary.hndl_critical : 0;
    const total = summary.total_assets !== undefined ? summary.total_assets : 0;

    document.getElementById("kpiReadiness").textContent = `${readiness}%`;
    document.getElementById("kpiCritical").textContent = critical;
    document.getElementById("kpiTotal").textContent = total;

    // Runway: (CRQC Year - 2026) - Migration Time
    const horizonYear = summary.scan_meta?.raw_summary?.crqc_horizon_year || 2033;
    const migYears = summary.scan_meta?.raw_summary?.migration_years || 3.0;
    const runway = Math.max(0, (horizonYear - 2026) - migYears);
    document.getElementById("kpiRunway").textContent = `${runway.toFixed(1)} yrs`;

    // Threat banner
    document.getElementById("bannerThreatCount").textContent = `${critical} Assets at Immediate HNDL Risk`;

    // Stats
    const shorCount = currentFindings.filter(f => f.shor_vulnerable).length;
    const groverCount = currentFindings.filter(f => f.grover_vulnerable).length;
    const safeCount = currentFindings.filter(f => f.severity === "QUANTUM_SAFE").length;

    document.getElementById("statShor").textContent = shorCount;
    document.getElementById("statGrover").textContent = groverCount;
    document.getElementById("statSafe").textContent = safeCount;
}

// --- Chart Rendering ---

function renderCharts(findings, summary) {
    renderScatterChart(findings);
    renderDoughnutChart(summary?.tier_breakdown || {});
}

function renderScatterChart(findings) {
    const ctx = document.getElementById("moscaScatterChart").getContext("2d");
    if (scatterChartInstance) {
        scatterChartInstance.destroy();
    }

    const scatterData = findings.map(f => {
        let color = "#ef4444"; // red
        if (f.severity === "HIGH") color = "#f59e0b"; // amber
        else if (f.severity === "MEDIUM") color = "#3b82f6"; // blue
        else if (f.severity === "LOW") color = "#94a3b8"; // slate
        else if (f.severity === "QUANTUM_SAFE") color = "#10b981"; // emerald

        return {
            x: f.data_shelf_life_years,
            y: f.q_score,
            assetName: f.asset_name,
            algorithm: f.algorithm,
            moscaGap: f.mosca_gap_years,
            severity: f.severity,
            color: color
        };
    });

    scatterChartInstance = new Chart(ctx, {
        type: "scatter",
        data: {
            datasets: [{
                label: "Cryptographic Assets",
                data: scatterData,
                backgroundColor: scatterData.map(d => d.color),
                borderColor: scatterData.map(d => d.color),
                pointRadius: 6,
                pointHoverRadius: 9
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    title: {
                        display: true,
                        text: "Data Confidentiality Shelf-Life X (Years)",
                        color: "#94a3b8",
                        font: { size: 11 }
                    },
                    grid: { color: "rgba(255, 255, 255, 0.05)" },
                    ticks: { color: "#94a3b8" }
                },
                y: {
                    min: 0,
                    max: 105,
                    title: {
                        display: true,
                        text: "Quantum Risk Q-Score (0 - 100)",
                        color: "#94a3b8",
                        font: { size: 11 }
                    },
                    grid: { color: "rgba(255, 255, 255, 0.05)" },
                    ticks: { color: "#94a3b8" }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: "#0f172a",
                    borderColor: "#334155",
                    borderWidth: 1,
                    titleColor: "#38bdf8",
                    bodyColor: "#f1f5f9",
                    callbacks: {
                        label: function(context) {
                            const p = context.raw;
                            return [
                                `Asset: ${p.assetName}`,
                                `Algorithm: ${p.algorithm}`,
                                `Shelf-Life (X): ${p.x} yrs`,
                                `Q-Score: ${p.y}`,
                                `Mosca Gap (Δ): ${p.moscaGap} yrs`,
                                `Tier: ${p.severity}`
                            ];
                        }
                    }
                }
            }
        }
    });
}

function renderDoughnutChart(breakdown) {
    const ctx = document.getElementById("severityDoughnutChart").getContext("2d");
    if (doughnutChartInstance) {
        doughnutChartInstance.destroy();
    }

    const labels = ["Critical", "High", "Medium", "Low", "Quantum Safe"];
    const counts = [
        breakdown.CRITICAL || 0,
        breakdown.HIGH || 0,
        breakdown.MEDIUM || 0,
        breakdown.LOW || 0,
        breakdown.QUANTUM_SAFE || 0
    ];

    doughnutChartInstance = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels: labels,
            datasets: [{
                data: counts,
                backgroundColor: ["#ef4444", "#f59e0b", "#3b82f6", "#64748b", "#10b981"],
                borderColor: "#090d16",
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: "right",
                    labels: { color: "#94a3b8", font: { size: 10 }, boxWidth: 10 }
                }
            },
            cutout: "65%"
        }
    });
}

// --- CBOM Table & Filter ---

function filterAndRenderTable() {
    const searchVal = document.getElementById("searchInput").value.toLowerCase().trim();
    const riskVal = document.getElementById("filterRisk").value;
    const typeVal = document.getElementById("filterType").value;

    const filtered = currentFindings.filter(f => {
        const matchesSearch = !searchVal || 
            f.asset_name.toLowerCase().includes(searchVal) ||
            f.algorithm.toLowerCase().includes(searchVal) ||
            f.location.toLowerCase().includes(searchVal);

        const matchesRisk = riskVal === "ALL" || f.severity === riskVal;
        const matchesType = typeVal === "ALL" || f.asset_type === typeVal;

        return matchesSearch && matchesRisk && matchesType;
    });

    renderTableBody(filtered);
    document.getElementById("tableCountBadge").textContent = `${filtered.length} Items`;
}

function renderTableBody(findings) {
    const tbody = document.getElementById("findingsTableBody");
    tbody.innerHTML = "";

    if (findings.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="10" class="py-8 text-center text-slate-500">
                    No cryptographic primitives matched your filter criteria.
                </td>
            </tr>
        `;
        return;
    }

    findings.forEach((f) => {
        const tr = document.createElement("tr");
        tr.className = "hover:bg-slate-900/80 transition cursor-pointer group";
        tr.onclick = (e) => {
            // If click wasn't on button, select for diff
            if (!e.target.closest("button")) {
                selectFindingForDiff(f);
            }
        };

        const badgeClass = getSeverityBadgeClass(f.severity);
        const gapColor = f.mosca_gap_years > 0 ? "text-red-400 font-bold" : "text-emerald-400";

        tr.innerHTML = `
            <td class="py-3 px-4">
                <div class="font-semibold text-slate-200 group-hover:text-cyan-400 transition">${escapeHtml(f.asset_name)}</div>
                <div class="text-[10px] text-slate-500 font-mono truncate max-w-xs">${escapeHtml(f.location)}${f.line_number ? ':' + f.line_number : ''}</div>
            </td>
            <td class="py-3 px-4">
                <span class="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono border border-slate-700">${f.asset_type}</span>
            </td>
            <td class="py-3 px-4">
                <span class="font-bold text-slate-200">${escapeHtml(f.algorithm)}</span>
                ${f.key_size ? `<span class="text-[10px] text-slate-400 font-mono ml-1">(${f.key_size}-bit)</span>` : ''}
            </td>
            <td class="py-3 px-4 text-[11px] text-slate-300">
                ${f.exposure_level}
            </td>
            <td class="py-3 px-4 font-mono text-amber-300 text-center">
                ${f.data_shelf_life_years} yrs
            </td>
            <td class="py-3 px-4 font-mono ${gapColor} text-center">
                ${f.mosca_gap_years > 0 ? '+' : ''}${f.mosca_gap_years} yrs
            </td>
            <td class="py-3 px-4 font-mono font-bold text-purple-400 text-center">
                ${f.q_score}
            </td>
            <td class="py-3 px-4 text-center">
                <span class="text-[10px] font-bold px-2.5 py-0.5 rounded-full ${badgeClass}">${f.severity}</span>
            </td>
            <td class="py-3 px-4 min-w-56">
                ${renderRiskDrivers(f)}
            </td>
            <td class="py-3 px-4 text-center">
                <button onclick='openInspectModal(${JSON.stringify(f).replace(/'/g, "&#39;")})' 
                        class="p-1.5 rounded bg-slate-800 hover:bg-cyan-950 hover:text-cyan-400 text-slate-400 transition" title="Inspect Deep Metadata">
                    <i class="fa-solid fa-eye"></i>
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function renderRiskDrivers(f) {
    if (f.severity === "QUANTUM_SAFE") return '<span class="inline-block rounded border border-emerald-800 bg-emerald-950/50 px-2 py-1 text-[10px] text-emerald-300">PQC / hybrid gate · score 0</span><div class="text-[10px] leading-relaxed text-slate-400 mt-1">Validate implementation and inventory completeness.</div>';
    const factors = f.risk_factors || {};
    const top = Object.values(factors).sort((a, b) => Number(b.weighted_points || 0) - Number(a.weighted_points || 0)).slice(0, 2);
    const chips = top.map(x => `<span class="inline-block mr-1 mb-1 rounded border border-slate-700 bg-slate-900 px-1.5 py-0.5 text-[10px] text-amber-200">${escapeHtml(x.label)} ${escapeHtml(String(x.score))}</span>`).join("");
    return `<div>${chips || '<span class="text-slate-500">Factor details available in inspector</span>'}<div class="text-[10px] leading-relaxed text-slate-300 mt-1">${escapeHtml(recommendedActionForFinding(f))}</div></div>`;
}

function recommendedActionForFinding(f) {
    if (f.severity === "QUANTUM_SAFE") return "Verify implementation and inventory completeness; retain in CBOM.";
    const algo = String(f.algorithm || "").toUpperCase();
    if (f.shor_vulnerable || /RSA|ECDH|ECDSA|ED25519|X25519|DIFFIE|DSA/.test(algo)) {
        return "Inventory dependencies; validate supported ML-KEM / ML-DSA or hybrid migration in staging.";
    }
    if (f.grover_vulnerable || /AES-128|AES128/.test(algo)) {
        return "Review effective security strength and assess AES-256 or approved parameter upgrades.";
    }
    if (Number(f.q_score || 0) >= 65) return "Confirm asset owner, sensitivity and lifetime; prioritize a migration assessment.";
    return "Validate the detected primitive and context; assign an owner and track in the migration roadmap.";
}

function renderInspectRiskFactors(f) {
    const host = document.getElementById("inspectRiskFactors");
    if (!host) return;
    const factors = Object.values(f.risk_factors || {});
    if (!factors.length) {
        host.innerHTML = '<p class="text-amber-200">This is a legacy finding without stored factor breakdown. Run a new scan to calculate the explainable score.</p>';
        return;
    }
    host.innerHTML = factors.map(factor => {
        const score = Math.max(0, Math.min(100, Number(factor.score || 0)));
        const weight = Number(factor.weight_pct || 0);
        const points = Number(factor.weighted_points || 0);
        const assumption = /assum|infer|validate/i.test(String(factor.observed_or_assumed || "") + " " + String(factor.source || ""));
        return `<div class="rounded-lg border border-slate-800 p-2.5"><div class="flex justify-between gap-2"><span class="text-slate-200 font-semibold">${escapeHtml(factor.label || "Risk factor")}</span><span class="font-mono text-cyan-300">${score.toFixed(0)}/100</span></div><div class="h-1.5 bg-slate-800 rounded-full overflow-hidden mt-2"><div class="h-full bg-cyan-500 rounded-full" style="width:${score}%"></div></div><div class="flex justify-between gap-2 text-[10px] text-slate-400 mt-1"><span>Weight ${weight}% · contributes ${points.toFixed(1)} points</span><span>${assumption ? 'ASSUMPTION / VALIDATE' : 'EVIDENCE / MODEL'}</span></div><p class="text-[10px] text-slate-400 mt-1">${escapeHtml(factor.source || "Source not recorded")}</p></div>`;
    }).join("");
}

function getSeverityBadgeClass(sev) {
    switch (sev) {
        case "CRITICAL": return "badge-critical";
        case "HIGH": return "badge-high";
        case "MEDIUM": return "badge-medium";
        case "LOW": return "badge-low";
        case "QUANTUM_SAFE": return "badge-safe";
        default: return "bg-slate-800 text-slate-300";
    }
}

// --- Migration Diff Studio ---

function selectFindingForDiff(f) {
    document.getElementById("diffTitle").textContent = f.code_diff_title || `Migrate ${f.algorithm} to Post-Quantum Standard`;
    document.getElementById("diffSubtitle").textContent = `Remediation path for ${f.asset_name} (${f.location})`;
    document.getElementById("diffStandardBadge").textContent = f.standard_reference || "NIST FIPS 203 / 204";
    
    document.getElementById("diffOldPrimitive").textContent = f.algorithm;
    document.getElementById("diffOldCode").textContent = f.current_code_snippet || "# Current implementation";
    
    document.getElementById("diffNewPrimitive").textContent = f.nist_standard_replacement || "ML-KEM-768";
    document.getElementById("diffNewCode").textContent = f.migrated_code_snippet || "# Post-quantum migration code";

    document.getElementById("diffRecipeText").textContent = f.configuration_recipe || "Implement NIST standardized post-quantum cryptographic primitives.";

    // Scroll slightly if user clicked row
    const diffSection = document.getElementById("remediationStudio");
    diffSection.classList.add("ring-1", "ring-cyan-500/50");
    setTimeout(() => diffSection.classList.remove("ring-1", "ring-cyan-500/50"), 1200);
}

// --- Modals & Scan Handling ---

function openNewScanModal() {
    document.getElementById("newScanModal").classList.remove("hidden");
    updateTargetPlaceholder();
}

function closeNewScanModal() {
    document.getElementById("newScanModal").classList.add("hidden");
    if (pollInterval) clearInterval(pollInterval);
}

function updateTargetPlaceholder() {
    const selected = document.querySelector('input[name="scanType"]:checked').value;
    const input = document.getElementById("scanPathInput");
    const label = document.getElementById("targetPathLabel");
    const help = document.getElementById("targetHelpText");

    const dropZone = document.getElementById("uploadDropZone");
    if (dropZone) dropZone.classList.toggle("hidden", selected === "network_tls");
    if (selected === "local_directory") {
        label.textContent = "Target Directory Path:";
        input.placeholder = "C:\\path\\to\\project\\or\\certs";
        help.textContent = "Point to any codebase folder, system certificate directory, or web project.";
    } else if (selected === "network_tls") {
        label.textContent = "Target Network Host & Port:";
        input.placeholder = "google.com:443 (or cloudflare.com:443)";
        help.textContent = "Initiates a real socket TLS handshake and inspects negotiated cipher suites and certificates.";
    } else {
        label.textContent = "Combined Target (Directory / Host):";
        input.placeholder = "C:\\path\\to\\code OR hostname:443";
        help.textContent = "Executes both local file parsing and live network TLS probes.";
    }
}

async function loadSampleTarget() {
    try {
        const res = await fetch("/api/sample-path");
        const data = await res.json();
        document.getElementById("scanPathInput").value = data.path;
    } catch (err) {
        console.error("Error loading sample path:", err);
    }
}

async function handleStartScan(e) {
    e.preventDefault();
    const name = document.getElementById("scanNameInput").value;
    const type = document.querySelector('input[name="scanType"]:checked').value;
    const path = document.getElementById("scanPathInput").value;

    const btn = document.getElementById("btnSubmitScan");
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i><span>Scanning...</span>`;

    const consoleWrapper = document.getElementById("scanConsoleWrapper");
    consoleWrapper.classList.remove("hidden");
    const consoleBox = document.getElementById("scanConsole");
    consoleBox.innerHTML = '<div class="text-cyan-400">> Initializing QuantumGuard discovery engine...</div>';

    try {
        const res = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: name, target_type: type, target_path: path })
        });
        const data = await res.json();
        const scanId = data.scan_id;

        // Poll logs
        pollInterval = setInterval(async () => {
            const logRes = await fetch(`/api/scans/${scanId}/logs`);
            const logData = await logRes.json();
            consoleBox.innerHTML = "";
            (logData.logs || []).forEach(l => {
                const color = l.level === "SUCCESS" ? "text-emerald-400" :
                              l.level === "ERROR" ? "text-red-400" :
                              l.level === "WARNING" ? "text-amber-400" : "text-slate-300";
                consoleBox.innerHTML += `<div class="${color}">[${l.level}] ${escapeHtml(l.message)}</div>`;
            });
            consoleBox.scrollTop = consoleBox.scrollHeight;

            // Check scan status
            const statusRes = await fetch(`/api/scans/${scanId}`);
            const statusData = await statusRes.json();
            if (statusData.scan && statusData.scan.status !== "RUNNING" && statusData.scan.status !== "PENDING") {
                clearInterval(pollInterval);
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-check"></i><span>Completed</span>`;
                setTimeout(async () => {
                    closeNewScanModal();
                    await loadScansList();
                }, 1000);
            }
        }, 800);

    } catch (err) {
        console.error("Scan launch error:", err);
        btn.disabled = false;
        btn.innerHTML = `Start Real Discovery`;
    }
}

// --- Inspect Modal ---

function openInspectModal(f) {
    document.getElementById("inspectModal").classList.remove("hidden");
    document.getElementById("inspectTitle").textContent = f.asset_name;
    document.getElementById("inspectLocation").textContent = `${f.location}${f.line_number ? ' (Line ' + f.line_number + ')' : ''}`;
    document.getElementById("inspectAlgo").textContent = f.algorithm;
    document.getElementById("inspectKeySize").textContent = f.key_size ? `${f.key_size} bits` : "N/A";
    document.getElementById("inspectExposure").textContent = f.exposure_level;
    document.getElementById("inspectShelf").textContent = `${f.data_shelf_life_years} years`;
    document.getElementById("inspectMoscaGap").textContent = `${f.mosca_gap_years > 0 ? '+' : ''}${f.mosca_gap_years} years`;
    document.getElementById("inspectQScore").textContent = `${f.q_score} / 100`;
    document.getElementById("inspectExplanation").textContent = f.explanation;
    renderInspectRiskFactors(f);
    document.getElementById("inspectNextAction").textContent = recommendedActionForFinding(f);
    document.getElementById("inspectSnippet").textContent = f.code_snippet || JSON.stringify(f.raw_metadata, null, 2);
}

function closeInspectModal() {
    document.getElementById("inspectModal").classList.add("hidden");
}

// --- Settings Modal ---

function openSettingsModal() {
    document.getElementById("settingsModal").classList.remove("hidden");
}

function closeSettingsModal() {
    document.getElementById("settingsModal").classList.add("hidden");
}

async function handleSaveSettings(e) {
    e.preventDefault();
    const horizon = parseInt(document.getElementById("settingHorizon").value);
    const mig = parseFloat(document.getElementById("settingMigration").value);
    const shelf = parseFloat(document.getElementById("settingShelf").value);

    try {
        await fetch("/api/settings", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                crqc_horizon_year: horizon,
                default_migration_time_years: mig,
                default_shelf_life_years: shelf
            })
        });
        closeSettingsModal();
        if (currentScanId) {
            await loadScan(currentScanId);
        }
    } catch (err) {
        console.error("Save settings error:", err);
    }
}

// --- CBOM Export ---

async function exportCurrentCBOM() {
    if (!currentScanId) {
        alert("Please run or select a scan first.");
        return;
    }
    const button = document.getElementById("btnExportCBOM");
    const originalHTML = button ? button.innerHTML : "";
    if (button) { button.disabled = true; button.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i><span>Preparing CBOM…</span>'; }
    try {
        const response = await fetch(`/api/scans/${encodeURIComponent(currentScanId)}/cbom`, { headers: { "Accept": "application/json" } });
        if (!response.ok) {
            let detail = `Server returned ${response.status}`;
            try { const payload = await response.json(); detail = payload.error || detail; } catch (_) {}
            throw new Error(detail);
        }
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `cbom-scan-${currentScanId}.json`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
        console.error("CBOM export failed:", error);
        alert(`CBOM export failed: ${error.message}. Check that the local QuantumGuard server is running, then try again.`);
    } finally {
        if (button) { button.disabled = false; button.innerHTML = originalHTML; }
    }
}

// Helper
function escapeHtml(str) {
    if (!str) return "";
    return String(str).replace(/[&<>"']/g, function(m) {
        return {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        }[m];
    });
}


// --- Executive intelligence layer (uses selected scan evidence; scenarios are explicitly assumptions) ---
let plainMode = true;
const industryContexts = {
    hospital: {title: "Patient confidentiality can outlive today's encryption", text: "If the scan finds vulnerable public-key cryptography in systems handling patient records, copied encrypted data could remain sensitive for years. Prioritize long-lived clinical records, identity systems, backups and vendor dependencies; this is a scenario, not proof that data was intercepted.", actions: ["Inventory patient-data flows and systems that protect them.", "Prioritize long-retention records and externally exposed key exchange.", "Validate vendor PQC roadmaps and test hybrid migration in a staging environment."], x: 15},
    bank: {title: "Long-lived financial and identity data deserves early planning", text: "Vulnerable key exchange or signatures may affect customer identity, transaction trust and archived financial records. Use findings to identify owners and dependencies, then plan controlled migration and interoperability testing; a scanner finding alone is not evidence of a breach.", actions: ["Map affected payment, identity, API and certificate dependencies.", "Prioritize high-impact systems and long-lived customer data.", "Coordinate vendor readiness, crypto-agility and hybrid testing."], x: 12},
    college: {title: "Student records and identity systems need a lifecycle view", text: "Student identity, research and administrative records may be retained long after collection. If vulnerable algorithms protect these systems, migration lead time and retention period should inform priority—not the algorithm name alone.", actions: ["Map student records, research archives and identity services.", "Assign an owner and retention period to each finding.", "Create a phased upgrade plan for certificates, libraries and vendors."], x: 10},
    iot: {title: "Embedded devices can be hard to update after deployment", text: "Devices may stay in service for many years and depend on vendor firmware or fixed cryptographic libraries. Confirm whether findings are in deployed products, assess update mechanisms and prioritize systems with long service lives or safety impact.", actions: ["Map device families, firmware ownership and support dates.", "Check secure-update capability and vendor cryptographic roadmaps.", "Pilot hybrid/PQC support before fleet-wide changes."], x: 15},
    general: {title: "Start migration planning before dependencies become urgent", text: "Cryptographic migration can span applications, certificates, hardware, vendors and testing. Findings are a starting inventory; confirm business criticality, data lifetime and actual deployment context before setting deadlines.", actions: ["Validate each finding and identify a technical owner.", "Record data confidentiality lifetime and migration lead time.", "Build a staged roadmap and rescan after remediation."], x: 10}
};
function togglePlainMode() {
    plainMode = !plainMode;
    const button = document.getElementById("plainModeToggle");
    button.innerHTML = plainMode ? '<i class="fa-solid fa-language mr-1"></i> Executive language: ON' : '<i class="fa-solid fa-code mr-1"></i> Technical language: ON';
    updateExecutiveLayer();
}
function updateExecutiveLayer() {
    const contextKey = document.getElementById("industryPreset")?.value || "hospital";
    const ctx = industryContexts[contextKey] || industryContexts.general;
    const findings = Array.isArray(currentFindings) ? currentFindings : [];
    const total = findings.length;
    const tierOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "QUANTUM_SAFE"];
    const topTier = tierOrder.find(t => findings.some(f => String(f.severity || "").toUpperCase() === t)) || (total ? "UNRATED" : "NO DATA");
    const count = document.getElementById("execAssetCount");
    if (!count) return;
    count.textContent = String(total);
    document.getElementById("execTopTier").textContent = topTier;
    document.getElementById("execCoverage").textContent = total ? `${new Set(findings.map(f => f.asset_type || f.type || "unknown")).size} types` : "No scan";
    document.getElementById("execImpactTitle").textContent = plainMode ? ctx.title : `Context: ${contextKey.toUpperCase()} | ${total} observed findings`;
    document.getElementById("execImpactText").textContent = plainMode ? ctx.text : `Observed assets: ${total}. Highest observed severity tier: ${topTier}. Treat this as scanner evidence requiring owner validation; severity and Q-score are model outputs, not proof of exploitability or compromise.`;
    document.getElementById("execImpactLabel").textContent = plainMode ? "Why leadership should care" : "Technical interpretation";
    const actions = document.getElementById("execActions");
    actions.replaceChildren();
    const items = total ? ctx.actions : ["Run a local scan against the included sample_targets folder to see the workflow.", "Run a TLS check only against a host you own or have permission to assess.", "After findings appear, validate evidence and then export the briefing."];
    items.forEach((action, i) => { const li = document.createElement("li"); li.className = "flex gap-2"; const n = document.createElement("span"); n.className = "text-cyan-400 font-bold"; n.textContent = `${i+1}.`; const t = document.createElement("span"); t.textContent = action; li.append(n,t); actions.appendChild(li); });
    document.getElementById("execEvidenceNote").textContent = total ? `Selected scan #${currentScanId ?? "—"} contains ${total} findings. Counts and tiers come from the current scanner output. Industry impact is contextual guidance selected by you, not automatically inferred from the scanned system. No breach, compliance status, or future quantum date is asserted.` : "No scan findings are loaded yet. Start a sample, local-directory, or authorized TLS scan first. Scenario text is guidance only and does not fabricate assets.";
    const year = Number(document.getElementById("timelineYear").value || 2033);
    document.getElementById("timelineYearLabel").textContent = String(year);
    // Industry profiles supply a transparent scenario X; the general profile uses the configured default shelf-life.
    const x = contextKey === "general" ? Number(document.getElementById("settingShelf")?.value || ctx.x) : Number(ctx.x);
    const y = Number(document.getElementById("settingMigration")?.value || 3);
    const baselineYear = 2026;
    const z = Math.max(0, year - baselineYear);
    document.getElementById("timelineX").textContent = `${x}y`;
    document.getElementById("timelineY").textContent = `${y}y`;
    document.getElementById("timelineZ").textContent = `${z}y`;
    const gap = x + y - z;
    const verdict = document.getElementById("timelineVerdict");
    verdict.className = gap > 0 ? "rounded-lg border border-red-800/70 bg-red-950/35 p-3 text-xs leading-relaxed text-red-100" : "rounded-lg border border-emerald-800/70 bg-emerald-950/30 p-3 text-xs leading-relaxed text-emerald-100";
    verdict.textContent = gap > 0 ? `Scenario flags a planning gap: X + Y = ${(x+y).toFixed(1)} years, which exceeds Z = ${z} years by ${gap.toFixed(1)} years. Begin prioritization now; this is conditional on the selected assumptions, not a prediction.` : `Under these assumptions, X + Y = ${(x+y).toFixed(1)} years does not exceed Z = ${z} years. Continue inventory and crypto-agility work; the result can change if retention, migration duration or horizon assumptions change.`;
}
async function quickTLS(endpoint) {
    const status = document.getElementById("quickTLSStatus");
    status.textContent = `Launching real TLS discovery for ${endpoint}…`;
    try {
        const res = await fetch("/api/scan", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({name:`Quick TLS check — ${endpoint}`, target_type:"network_tls", target_path:endpoint})});
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Could not queue scan");
        status.textContent = `Scan #${data.scan_id} queued for ${endpoint}. It will appear in Audit History; select it after completion.`;
        await loadScansList();
    } catch (err) { status.textContent = `Could not launch scan: ${err.message}`; }
}
async function handleFileSelection(event) { await uploadScanFiles(event.target.files); event.target.value = ""; }
async function handleFileDrop(event) { event.preventDefault(); event.currentTarget.classList.remove("border-cyan-400"); await uploadScanFiles(event.dataTransfer.files); }
async function uploadScanFiles(fileList) {
    const status = document.getElementById("uploadStatus");
    if (!fileList || !fileList.length) return;
    const form = new FormData();
    Array.from(fileList).forEach(file => form.append("files", file));
    status.textContent = "Validating files and uploading to the local app…";
    try {
        const res = await fetch("/api/upload-target", {method:"POST", body:form});
        const data = await res.json();
        if (!res.ok) throw new Error([data.error, ...(data.rejected || [])].filter(Boolean).join(" · "));
        document.getElementById("scanPathInput").value = data.path;
        document.querySelector('input[name="scanType"][value="local_directory"]').checked = true;
        updateTargetPlaceholder();
        status.textContent = `Ready: ${data.accepted.join(", ")}. ${data.rejected?.length ? "Rejected: " + data.rejected.join("; ") : "All selected files accepted."} Click Start Real Discovery. Uploaded files remain in data/uploaded_targets until removed.`;
    } catch (err) { status.textContent = `Upload not completed: ${err.message}`; }
}
function exportExecutiveBriefing() {
    if (!currentSummary || !currentScanId) { alert("Run or select a scan first. The briefing uses actual findings from that scan."); return; }
    const findings = currentFindings || [];
    const context = industryContexts[document.getElementById("industryPreset")?.value || "general"] || industryContexts.general;
    const year = document.getElementById("timelineYear")?.value || "2033";
    const xYears = document.getElementById("timelineX")?.textContent || "—";
    const yYears = document.getElementById("timelineY")?.textContent || "—";
    const zYears = document.getElementById("timelineZ")?.textContent || "—";
    const timelineVerdict = document.getElementById("timelineVerdict")?.textContent || "—";
    const scan = currentSummary.scan_meta || {};
    const summary = currentSummary;
    const rows = findings.map(f => { const drivers = Object.values(f.risk_factors || {}).sort((a,b) => Number(b.weighted_points || 0) - Number(a.weighted_points || 0)).slice(0,2).map(x => `${x.label}: ${x.score}/100 (${x.weight_pct}% weight)`).join("; ") || "Legacy record — rescan for factor detail"; return `<tr><td>${escapeHtml(f.asset_name || "Unnamed asset")}</td><td>${escapeHtml(f.asset_type || f.type || "—")}</td><td>${escapeHtml(f.algorithm || "—")}</td><td>${escapeHtml(f.severity || "—")}</td><td>${escapeHtml(String(f.q_score ?? "—"))}/100</td><td>${escapeHtml(drivers)}</td><td>${escapeHtml(recommendedActionForFinding(f))}</td><td>${escapeHtml(f.location || "—")}</td></tr>`; }).join("");
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>QuantumGuard Executive Briefing</title><style>body{font:13px Arial,sans-serif;color:#172033;margin:36px;line-height:1.45}h1{color:#0e7490;margin-bottom:4px}h2{font-size:16px;margin-top:24px;color:#164e63}.sub{color:#64748b;font-size:11px}.grid{display:flex;gap:12px;margin:18px 0}.metric{border:1px solid #cbd5e1;border-radius:8px;padding:12px;flex:1}.metric strong{display:block;font-size:22px;color:#0e7490}table{border-collapse:collapse;width:100%;font-size:10px}th,td{border:1px solid #cbd5e1;padding:6px;text-align:left;word-break:break-word}th{background:#e2e8f0}.note{background:#f1f5f9;border-left:4px solid #0891b2;padding:10px}.actions li{margin-bottom:7px}.foot{margin-top:28px;color:#64748b;font-size:10px}@media print{body{margin:15mm}button{display:none}}</style></head><body><h1>QUANTUMGUARD</h1><div class="sub">Post-quantum cryptography discovery · Executive briefing · Generated ${new Date().toLocaleString()}</div><h2>Audit snapshot</h2><p><b>Scan:</b> #${escapeHtml(String(currentScanId))} · <b>Status:</b> ${escapeHtml(scan.status || "Selected scan")} · <b>Scope:</b> ${escapeHtml(scan.target_path || scan.target || "See scan history")}</p><div class="grid"><div class="metric"><span>Discovered assets</span><strong>${findings.length}</strong></div><div class="metric"><span>Critical HNDL findings</span><strong>${escapeHtml(String(summary.hndl_critical ?? 0))}</strong></div><div class="metric"><span>Readiness indicator</span><strong>${escapeHtml(String(summary.readiness_pct ?? 0))}%</strong></div><div class="metric"><span>Average Q-score</span><strong>${escapeHtml(String(summary.avg_q_score ?? 0))}</strong></div></div><h2>Business context: ${escapeHtml(document.getElementById("industryPreset")?.selectedOptions?.[0]?.textContent || "General enterprise")}</h2><p>${escapeHtml(context.text)}</p><h2>Prioritized next moves</h2><ol class="actions">${context.actions.map(a=>`<li>${escapeHtml(a)}</li>`).join("")}</ol><h2>What-if timeline</h2><p>Assumed CRQC horizon: ${escapeHtml(String(year))}; remaining scenario horizon Z: ${escapeHtml(String(zYears))}; data confidentiality lifetime X: ${escapeHtml(String(xYears))}; migration duration Y: ${escapeHtml(String(yYears))}. The selected horizon is a scenario parameter, not a forecast.</p><div class="note">${escapeHtml(timelineVerdict)}</div><p>Mosca-style planning compares X + Y against Z. Industry X values are scenario assumptions; validate them with the asset owner and data-retention policy.</p><h2>Observed findings (${findings.length})</h2><table><thead><tr><th>Asset</th><th>Type</th><th>Algorithm</th><th>Tier</th><th>Q-score</th><th>Top weighted drivers</th><th>Recommended next action</th><th>Location</th></tr></thead><tbody>${rows || '<tr><td colspan="8">No findings were returned by this scan.</td></tr>'}</tbody></table><div class="note"><b>Interpretation limits:</b> This report summarizes the selected scan's output. It is not a compliance certification, proof of compromise, or prediction of quantum-computer arrival. Validate findings, asset owners, deployment context and vendor support before making migration decisions.</div><div class="foot">QuantumGuard · Generated locally in the browser. To save as PDF, choose “Save as PDF” in the print dialog.</div><script>window.onload=()=>setTimeout(()=>window.print(),350);</script></body></html>`;
    // Download the briefing as a standalone HTML file instead of relying on pop-ups.
    // The user can open it in a browser and use Print > Save as PDF.
    try {
        const blob = new Blob([html], { type: "text/html;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `quantumguard-executive-briefing-scan-${currentScanId}.html`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
        console.error("Executive briefing export failed:", error);
        alert(`Executive briefing export failed: ${error.message}`);
    }
}
