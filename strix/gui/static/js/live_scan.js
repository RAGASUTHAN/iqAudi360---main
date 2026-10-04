/**
 * iqAudi360 - Real-Time Live Scan SSE Client & UI State Controller
 */

class LiveScanClient {
  constructor(scanId) {
    this.scanId = scanId;
    this.eventSource = null;
    this.autoScroll = true;
    this.terminalEl = document.getElementById("terminalLogs");
    this.statusBadgeEl = document.getElementById("scanStatusBadge");
    this.liveStatusPillEl = document.getElementById("liveStatusPill");
    this.livePulseTagEl = document.getElementById("livePulseTag");
    this.liveIndicatorTextEl = document.getElementById("liveIndicatorText");
    this.agentListEl = document.getElementById("agentActivityList");
    this.findingsCounterEl = document.getElementById("liveFindingsCounter");
    this.completedBannerEl = document.getElementById("completedBanner");
    this.stopBtn = document.getElementById("stopScanBtn");
    
    this.init();
  }

  init() {
    this.initScrollListener();
    this.initControls();
    this.connectSSE();
  }

  initScrollListener() {
    if (!this.terminalEl) return;
    this.terminalEl.addEventListener("scroll", () => {
      const atBottom = this.terminalEl.scrollHeight - this.terminalEl.scrollTop <= this.terminalEl.clientHeight + 50;
      this.autoScroll = atBottom;
    });
  }

  initControls() {
    // Clear logs button
    const clearBtn = document.getElementById("clearLogsBtn");
    if (clearBtn && this.terminalEl) {
      clearBtn.addEventListener("click", () => {
        this.terminalEl.innerHTML = '<div class="terminal-line" style="color: #64748b;">[Logs cleared from view]</div>';
      });
    }
  }

  connectSSE() {
    const streamUrl = `/api/scans/${this.scanId}/stream`;
    this.eventSource = new EventSource(streamUrl);

    this.eventSource.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        this.handleEvent(data);
      } catch (err) {
        console.debug("SSE Parse error:", err);
      }
    };

    this.eventSource.onerror = (err) => {
      console.debug("SSE connection interrupted, retrying...", err);
    };
  }

  handleEvent(data) {
    if (data.type === "log") {
      this.appendLog(data.line);
    } else if (data.type === "progress") {
      this.updateProgress(data);
    } else if (data.type === "status") {
      this.updateStatus(data);
    }
  }

  formatLogLine(line) {
    if (!line) return "";
    return line
      .replace(/strix\.report\.coverage/g, "iqAudi360 Coverage")
      .replace(/strix\.llm\.request_log/g, "iqAudi360 LLM Activity")
      .replace(/strix\.core\.runner/g, "iqAudi360 Engine")
      .replace(/strix\.core\.agents/g, "iqAudi360 Agent Coordinator")
      .replace(/strix\.agents\.factory/g, "iqAudi360 Agent Factory")
      .replace(/strix\.agents\.prompt/g, "iqAudi360 Prompts")
      .replace(/strix\.report\.sarif/g, "iqAudi360 SARIF Emitter")
      .replace(/strix\.report\.state/g, "iqAudi360 Report State")
      .replace(/strix\.report\.writer/g, "iqAudi360 Report Writer")
      .replace(/strix\.runtime\.docker_client/g, "iqAudi360 Sandbox Client")
      .replace(/strix\.runtime\.session_manager/g, "iqAudi360 Session Manager")
      .replace(/strix\.runtime\.backends/g, "iqAudi360 Runtime")
      .replace(/strix\.runtime\.caido_bootstrap/g, "iqAudi360 Proxy Client")
      .replace(/strix\.skills/g, "iqAudi360 Skills")
      .replace(/strix\.telemetry/g, "iqAudi360 Telemetry")
      .replace(/strix-sandbox/g, "iqAudi360-sandbox")
      .replace(/ghcr\.io\/usestrix\//g, "ghcr.io/iqaudi360/")
      .replace(/strix_runs/g, "iqaudi360_runs")
      .replace(/strix\.log/g, "iqAudi360.log")
      .replace(/\bStrix\b/g, "iqAudi360")
      .replace(/\bstrix\b/g, "iqaudi360");
  }

  appendLog(line) {
    if (!this.terminalEl) return;
    const cleanLine = this.formatLogLine(line);
    const div = document.createElement("div");
    div.className = "terminal-line";

    // Syntax color highlighting for terminal output
    if (cleanLine.includes("ERROR") || cleanLine.includes("[!]") || cleanLine.includes("FAILED")) {
      div.style.color = "#f87171";
    } else if (cleanLine.includes("WARNING") || cleanLine.includes("[?]")) {
      div.style.color = "#fbbf24";
    } else if (cleanLine.includes("SUCCESS") || cleanLine.includes("[+]") || cleanLine.includes("completed")) {
      div.style.color = "#34d399";
    } else if (cleanLine.includes("INFO") || cleanLine.includes("[*]")) {
      div.style.color = "#38bdf8";
    }

    div.textContent = cleanLine;
    this.terminalEl.appendChild(div);

    if (this.autoScroll) {
      this.terminalEl.scrollTop = this.terminalEl.scrollHeight;
    }
  }

  updateProgress(data) {
    if (data.findings_count !== undefined && this.findingsCounterEl) {
      this.findingsCounterEl.textContent = data.findings_count;
    }

    if (data.agents && this.agentListEl) {
      this.renderAgents(data.agents);
    }
  }

  renderAgents(agents) {
    if (!agents || agents.length === 0) return;

    this.agentListEl.innerHTML = "";
    agents.forEach((agent) => {
      const item = document.createElement("div");
      const isRunning = agent.status === "running";
      item.className = `agent-item ${isRunning ? "running" : ""}`;

      const icon = isRunning 
        ? '<span class="status-dot-pulse" style="background:#00d2ff; box-shadow:0 0 8px #00d2ff;"></span>'
        : '<span style="color:#10b981; font-weight:bold;">✓</span>';

      item.innerHTML = `
        <div class="agent-name">
          ${icon}
          <div>
            <div>${agent.name}</div>
            <div style="font-size: 11px; color: #64748b; font-weight: normal;">ID: ${agent.id}</div>
          </div>
        </div>
        <div>
          <span class="badge badge-status ${agent.status.toLowerCase()}">${agent.status.toUpperCase()}</span>
        </div>
      `;
      this.agentListEl.appendChild(item);
    });
  }

  updateStatus(data) {
    const rawStatus = data.status || "completed";
    const status = rawStatus.toLowerCase();

    // 1. Update Status Badges
    if (this.statusBadgeEl) {
      this.statusBadgeEl.className = `badge badge-status ${status}`;
      this.statusBadgeEl.textContent = rawStatus.toUpperCase();
    }
    if (this.liveStatusPillEl) {
      this.liveStatusPillEl.className = `badge badge-status ${status}`;
      this.liveStatusPillEl.textContent = rawStatus.toUpperCase();
    }

    // 2. Synchronize LIVE Indicator and Stop Button states
    if (status === "running") {
      if (this.livePulseTagEl) {
        this.livePulseTagEl.style.display = "inline-flex";
      }
      if (this.liveIndicatorTextEl) {
        this.liveIndicatorTextEl.textContent = "LIVE SCAN";
      }
      if (this.stopBtn) {
        this.stopBtn.style.display = "inline-flex";
      }
    } else if (status === "starting") {
      if (this.livePulseTagEl) {
        this.livePulseTagEl.style.display = "inline-flex";
      }
      if (this.liveIndicatorTextEl) {
        this.liveIndicatorTextEl.textContent = "INITIALIZING";
      }
      if (this.stopBtn) {
        this.stopBtn.style.display = "inline-flex";
      }
    } else {
      // Completed, Stopped, Interrupted, Failed -> Remove Live Indicator & Hide Stop Button
      if (this.livePulseTagEl) {
        this.livePulseTagEl.style.display = "none";
      }
      if (this.stopBtn) {
        this.stopBtn.style.display = "none";
      }

      if (this.completedBannerEl) {
        this.completedBannerEl.style.display = "block";
      }

      // Close EventSource
      if (this.eventSource) {
        this.eventSource.close();
      }

      // Redirect to scan results dashboard after 2 seconds
      const targetRun = data.run_name || this.scanId;
      setTimeout(() => {
        window.location.href = `/scan/${targetRun}`;
      }, 2000);
    }
  }

  stopScan() {
    fetch(`/api/scans/${this.scanId}/stop`, { method: "POST" })
      .then((res) => res.json())
      .then((data) => {
        if (data.ok) {
          showToast("Scan stopped by user.", "info");
          this.updateStatus({ status: "stopped", run_name: this.scanId });
        } else {
          showToast(data.error || "Failed to stop scan.", "error");
        }
      })
      .catch((err) => {
        showToast("Error stopping scan: " + err, "error");
      });
  }
}
