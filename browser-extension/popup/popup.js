/**
 * Quantum NIDS Browser Guard - Enhanced Popup Interface
 * 
 * Provides interactive security auditing, live risk telemetry,
 * structured finding presentation, and actionable remediation workflows.
 * Hardened against DOM XSS with strict DOM element construction (no unsafe innerHTML).
 */

document.addEventListener("DOMContentLoaded", async () => {
    let currentTab = null;

    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        currentTab = tab;
    } catch (e) {
        console.warn("[Quantum NIDS] Failed to query active tab:", e);
    }

    const siteNameEl = document.getElementById("site-name");
    const statusTextEl = document.getElementById("status-text");
    const riskScoreEl = document.getElementById("risk-score");
    const riskBarEl = document.getElementById("risk-bar");
    const alertsListEl = document.getElementById("alerts-list");
    const recCard = document.getElementById("recommendations-card");
    const recText = document.getElementById("recommendations-text");
    const scanBtn = document.getElementById("run-scan");
    const scanProgressCard = document.getElementById("scan-progress-card");
    const scanProgressBar = document.getElementById("scan-progress-bar");
    const scanStepText = document.getElementById("scan-step-text");
    const findingsSection = document.getElementById("findings-section");
    const findingsContainer = document.getElementById("findings-container");
    const findingsCountEl = document.getElementById("findings-count");
    const scanTimestampEl = document.getElementById("scan-timestamp");

    if (!currentTab || !currentTab.url) {
        siteNameEl.textContent = "No active page";
        statusTextEl.textContent = "RESTRICTED";
        statusTextEl.className = "badge gray";
        scanBtn.disabled = true;
        return;
    }

    // Display hostname or protocol
    let isHttpOrHttps = false;
    try {
        const urlObj = new URL(currentTab.url);
        siteNameEl.textContent = urlObj.hostname;
        siteNameEl.title = urlObj.href;
        isHttpOrHttps = urlObj.protocol === "http:" || urlObj.protocol === "https:";
    } catch {
        siteNameEl.textContent = currentTab.url;
    }

    if (!isHttpOrHttps) {
        statusTextEl.textContent = "RESTRICTED";
        statusTextEl.className = "badge gray";
        scanBtn.disabled = true;
        scanBtn.textContent = "Scan Unavailable";
        renderAlerts(["Browser security policies restrict extension access on this page."]);
        return;
    }

    // Load initial tab data from service worker
    chrome.runtime.sendMessage({ type: "GET_TAB_DATA", tabId: currentTab.id }, (response) => {
        if (!response) {
            statusTextEl.textContent = "UNSUPPORTED";
            statusTextEl.className = "badge gray";
            recCard.style.display = "none";
            return;
        }

        renderTabState(response);
    });

    /**
     * Renders tab risk score, badges, and alerts.
     */
    function renderTabState(data) {
        const { riskScore = 0, alerts = [], isSupported = true, findings = [] } = data;
        
        const roundedScore = Math.round(riskScore);
        riskScoreEl.textContent = roundedScore;
        updateRiskBar(roundedScore);

        if (!isSupported) {
            statusTextEl.textContent = "UNSUPPORTED";
            statusTextEl.className = "badge gray";
        } else if (roundedScore < 20) {
            statusTextEl.textContent = "SAFE";
            statusTextEl.className = "badge safe";
            recCard.style.display = "none";
        } else if (roundedScore < 50) {
            statusTextEl.textContent = "WARNING";
            statusTextEl.className = "badge warn";
            recCard.style.display = "block";
            setSafeRecommendation("Review third-party scripts. Avoid entering sensitive credentials until page authenticity is verified.");
        } else {
            statusTextEl.textContent = "HIGH RISK";
            statusTextEl.className = "badge high";
            recCard.style.display = "block";
            setSafeRecommendation("DO NOT enter payment details! Potential security anomaly detected during active browsing.");
        }

        if (alerts && alerts.length > 0) {
            renderAlerts(alerts);
        }

        if (findings && findings.length > 0) {
            renderFindings(findings);
        }
    }

    /**
     * Updates the risk bar meter.
     */
    function updateRiskBar(score) {
        if (!riskBarEl) return;
        const clamped = Math.max(0, Math.min(100, score));
        riskBarEl.style.width = `${clamped}%`;

        if (clamped < 20) {
            riskBarEl.style.backgroundColor = "#2e7d32"; // Green
        } else if (clamped < 50) {
            riskBarEl.style.backgroundColor = "#f57c00"; // Orange
        } else {
            riskBarEl.style.backgroundColor = "#d32f2f"; // Red
        }
    }

    /**
     * Safely sets recommendation text.
     */
    function setSafeRecommendation(text) {
        while (recText.firstChild) {
            recText.removeChild(recText.firstChild);
        }
        const p = document.createElement("p");
        p.style.fontSize = "12px";
        p.style.color = "#37474f";
        p.style.margin = "0";
        p.style.lineHeight = "1.4";
        p.textContent = text;
        recText.appendChild(p);
    }

    /**
     * Safely renders list of alerts into #alerts-list.
     */
    function renderAlerts(alerts) {
        while (alertsListEl.firstChild) {
            alertsListEl.removeChild(alertsListEl.firstChild);
        }

        if (!alerts || alerts.length === 0) {
            const li = document.createElement("li");
            li.className = "safe";
            li.textContent = "✓ No suspicious activity detected yet.";
            alertsListEl.appendChild(li);
            return;
        }

        alerts.forEach(alertText => {
            const li = document.createElement("li");
            li.className = "warn";
            li.textContent = "⚠ " + alertText;
            alertsListEl.appendChild(li);
        });
    }

    /**
     * Safely renders deep security findings into #findings-container.
     */
    function renderFindings(findings) {
        if (!findings || findings.length === 0) {
            findingsSection.style.display = "none";
            return;
        }

        findingsSection.style.display = "block";
        findingsCountEl.textContent = findings.length;

        while (findingsContainer.firstChild) {
            findingsContainer.removeChild(findingsContainer.firstChild);
        }

        findings.forEach(finding => {
            const item = document.createElement("div");
            item.className = `finding-item severity-${finding.severity}`;

            // Title row
            const titleRow = document.createElement("div");
            titleRow.className = "finding-title-row";

            const title = document.createElement("h4");
            title.className = "finding-title";
            title.textContent = finding.title;
            titleRow.appendChild(title);

            const badge = document.createElement("span");
            const sevClass = finding.severity ? finding.severity.toLowerCase() : "info";
            badge.className = `badge ${sevClass}`;
            badge.textContent = finding.severity || "INFO";
            titleRow.appendChild(badge);

            item.appendChild(titleRow);

            // Metadata row
            const meta = document.createElement("div");
            meta.className = "finding-meta";
            meta.textContent = `Status: ${finding.status || 'NORMAL'} | Confidence: ${finding.confidence || 'MEDIUM'} | Detected: ${finding.detectedAt || 'Just now'}`;
            item.appendChild(meta);

            // Why It Matters
            if (finding.whyItMatters) {
                const callout = document.createElement("div");
                callout.className = finding.severity === 'HIGH' || finding.severity === 'CRITICAL' ? "finding-callout warning" : "finding-callout";
                callout.textContent = `Why It Matters: ${finding.whyItMatters}`;
                item.appendChild(callout);
            }

            // Recommended Actions
            if (finding.recommendedActions && finding.recommendedActions.length > 0) {
                const actionsLabel = document.createElement("div");
                actionsLabel.style.fontWeight = "600";
                actionsLabel.style.fontSize = "11px";
                actionsLabel.style.marginTop = "6px";
                actionsLabel.style.color = "#37474f";
                actionsLabel.textContent = "What to do:";
                item.appendChild(actionsLabel);

                const ul = document.createElement("ul");
                ul.className = "finding-actions";
                finding.recommendedActions.forEach(action => {
                    const li = document.createElement("li");
                    li.textContent = action;
                    ul.appendChild(li);
                });
                item.appendChild(ul);
            }

            // Expandable Technical Details
            const details = document.createElement("details");
            details.className = "technical-details";

            const summary = document.createElement("summary");
            summary.textContent = "Technical Evidence & Investigation Steps";
            details.appendChild(summary);

            // Affected Resource
            if (finding.affectedResource) {
                const resLabel = document.createElement("div");
                resLabel.style.marginTop = "6px";
                resLabel.style.fontWeight = "600";
                resLabel.textContent = "Affected Resource:";
                details.appendChild(resLabel);

                const code = document.createElement("div");
                code.className = "tech-content";
                code.textContent = finding.affectedResource;
                details.appendChild(code);
            }

            // Technical Evidence
            if (finding.technicalEvidence) {
                const evLabel = document.createElement("div");
                evLabel.style.marginTop = "6px";
                evLabel.style.fontWeight = "600";
                evLabel.textContent = "Observed Evidence:";
                details.appendChild(evLabel);

                const evBox = document.createElement("div");
                evBox.className = "tech-content";
                evBox.textContent = finding.technicalEvidence;
                details.appendChild(evBox);
            }

            // Investigation Steps
            if (finding.investigationSteps && finding.investigationSteps.length > 0) {
                const invLabel = document.createElement("div");
                invLabel.style.marginTop = "6px";
                invLabel.style.fontWeight = "600";
                invLabel.textContent = "Investigation Steps:";
                details.appendChild(invLabel);

                const ol = document.createElement("ol");
                ol.className = "investigation-list";
                finding.investigationSteps.forEach(step => {
                    const li = document.createElement("li");
                    li.textContent = step;
                    ol.appendChild(li);
                });
                details.appendChild(ol);
            }

            item.appendChild(details);
            findingsContainer.appendChild(item);
        });
    }

    /**
     * Executes the detailed security audit when user clicks button.
     */
    scanBtn.addEventListener("click", () => {
        if (!currentTab || !currentTab.id) return;

        scanBtn.disabled = true;
        scanBtn.textContent = "Scanning...";
        scanProgressCard.style.display = "block";
        scanProgressBar.style.width = "10%";
        scanStepText.textContent = "Analyzing domain authenticity & TLS context...";

        const step1 = setTimeout(() => {
            scanProgressBar.style.width = "40%";
            scanStepText.textContent = "Auditing session & attribution cookies...";
        }, 300);

        const step2 = setTimeout(() => {
            scanProgressBar.style.width = "70%";
            scanStepText.textContent = "Inspecting DOM scripts, iframes & forms...";
        }, 600);

        const step3 = setTimeout(() => {
            scanProgressBar.style.width = "90%";
            scanStepText.textContent = "Evaluating network telemetry & synthesizing findings...";
        }, 900);

        chrome.runtime.sendMessage({ type: "RUN_DETAILED_SCAN", tabId: currentTab.id }, (report) => {
            clearTimeout(step1);
            clearTimeout(step2);
            clearTimeout(step3);

            scanProgressBar.style.width = "100%";
            scanStepText.textContent = "Security Audit Complete";

            setTimeout(() => {
                scanProgressCard.style.display = "none";
                scanBtn.textContent = "Run Detailed Scan";
                scanBtn.disabled = false;

                if (!report) {
                    renderAlerts(["Scan communication failed. Service worker did not respond."]);
                    return;
                }

                // Update UI with report
                riskScoreEl.textContent = report.riskScore;
                updateRiskBar(report.riskScore);

                // Update status badge
                statusTextEl.textContent = report.status;
                if (report.status === "SAFE") {
                    statusTextEl.className = "badge safe";
                } else if (report.status === "SUSPICIOUS ACTIVITY") {
                    statusTextEl.className = "badge warn";
                } else if (report.status === "HIGH-RISK ACTIVITY") {
                    statusTextEl.className = "badge high";
                } else if (report.status === "CONFIRMED MALICIOUS INDICATOR") {
                    statusTextEl.className = "badge critical";
                } else {
                    statusTextEl.className = "badge gray";
                }

                if (report.scanCompletedAt) {
                    scanTimestampEl.textContent = `Completed at ${report.scanCompletedAt}`;
                }

                // Recommendations card
                if (report.riskScore >= 20 || report.findings.some(f => f.severity === 'HIGH' || f.severity === 'CRITICAL')) {
                    recCard.style.display = "block";
                    setSafeRecommendation(report.summary || "Review findings below and take appropriate actions.");
                } else {
                    recCard.style.display = "none";
                }

                // Render findings
                renderFindings(report.findings);

                // Update alerts summary list
                if (report.findings && report.findings.length > 0) {
                    const alertSummaries = report.findings
                        .filter(f => f.severity !== 'INFO')
                        .map(f => f.title);
                    renderAlerts(alertSummaries);
                }
            }, 350);
        });
    });

    // Listen for live risk telemetry updates from background without resetting user state
    chrome.runtime.onMessage.addListener((msg) => {
        if (msg.type === "RISK_UPDATE" && msg.tabId === currentTab.id && msg.data) {
            renderTabState(msg.data);
        }
    });
});
