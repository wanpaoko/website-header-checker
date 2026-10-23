/**
 * Popup UI Logic:
 * Supports standard extension popup and standalone floating alert window.
 * Parses ?tabId= and ?auto=true query parameters, renders multi-technology stack chips,
 * vulnerability cards for PHP / Node.js / Apache / Nginx / IIS / Tomcat,
 * security header checklist, manual URL scanning, report copying, and auto-popup toggle.
 */

document.addEventListener('DOMContentLoaded', async () => {
  const autoAlertNoticeEl = document.getElementById('auto-alert-notice');
  const targetUrlEl = document.getElementById('target-url');
  const statusBannerEl = document.getElementById('status-banner');
  const statusIconEl = document.getElementById('status-icon');
  const statusTextEl = document.getElementById('status-text');
  const techChipsContainerEl = document.getElementById('tech-chips-container');
  const cveCountChipEl = document.getElementById('cve-count-chip');
  const vulnerabilitiesContainerEl = document.getElementById('vulnerabilities-container');
  const headersCheckContainerEl = document.getElementById('headers-check-container');
  const manualUrlInputEl = document.getElementById('manual-url-input');
  const btnManualAuditEl = document.getElementById('btn-manual-audit');
  const btnRescanEl = document.getElementById('btn-rescan');
  const btnCopyReportEl = document.getElementById('btn-copy-report');
  const toggleAutoPopupEl = document.getElementById('toggle-auto-popup');

  let currentAuditData = null;
  let activeTabId = null;

  // Check query params for standalone popup window
  const urlParams = new URLSearchParams(window.location.search);
  const isAutoOpened = urlParams.get('auto') === 'true';
  const paramTabId = urlParams.get('tabId') ? parseInt(urlParams.get('tabId'), 10) : null;

  if (isAutoOpened && autoAlertNoticeEl) {
    autoAlertNoticeEl.style.display = 'block';
  }

  // Initialize auto-popup setting toggle (default true)
  chrome.storage.local.get(['autoPopupOnRed'], (res) => {
    const isEnabled = res.autoPopupOnRed !== false;
    toggleAutoPopupEl.checked = isEnabled;
  });

  toggleAutoPopupEl.addEventListener('change', (e) => {
    chrome.storage.local.set({ autoPopupOnRed: e.target.checked });
  });

  /**
   * Render audit data to Popup UI
   */
  function renderAudit(data) {
    currentAuditData = data;
    const audit = data.audit || {};
    const url = data.url || '未知網址';

    // 1. Display URL
    try {
      const parsedUrl = new URL(url);
      targetUrlEl.textContent = `${parsedUrl.hostname}${parsedUrl.pathname}`;
      targetUrlEl.title = url;
    } catch {
      targetUrlEl.textContent = url;
    }

    // 2. Status Banner
    const risk = audit.riskLevel || 'NONE';
    statusBannerEl.className = `status-banner ${risk}`;

    if (risk === 'CRITICAL') {
      statusIconEl.textContent = '🚨';
      statusTextEl.textContent = '高危警示：發現重大已知漏洞 (CVE)！';
    } else if (risk === 'HIGH') {
      statusIconEl.textContent = '⚠️';
      statusTextEl.textContent = '重大風險：存在嚴重漏洞或 EOL 終止維護版本';
    } else if (risk === 'WARNING') {
      statusIconEl.textContent = '⚠️';
      statusTextEl.textContent = '安全警告：版本標頭暴露或缺少重要防禦設定';
    } else if (risk === 'INFO') {
      statusIconEl.textContent = 'ℹ️';
      statusTextEl.textContent = '已識別後端/伺服器架構（無公開高危漏洞曝險）';
    } else if (risk === 'SAFE') {
      statusIconEl.textContent = '🛡️';
      statusTextEl.textContent = '伺服器防禦良好，未發現已知漏洞與版本洩漏';
    } else {
      statusIconEl.textContent = '⚪';
      statusTextEl.textContent = '未在此頁面偵測到已知後端或伺服器特徵';
    }

    // 3. Render Tech Stack Chips
    const detectedTechs = audit.detectedTechs || [];
    const vulns = audit.vulnerabilities || [];
    const vulnerableTechSet = new Set(vulns.map(v => v.tech));

    if (detectedTechs.length === 0) {
      techChipsContainerEl.innerHTML = '<span class="tech-chip">未發現明顯伺服器指紋</span>';
    } else {
      let chipsHtml = '';
      for (const t of detectedTechs) {
        const isVuln = vulnerableTechSet.has(t.tech);
        const icon = t.tech === 'PHP' ? '🐘' :
                     t.tech === 'NODEJS' ? '🟢' :
                     t.tech === 'APACHE' ? '🪶' :
                     t.tech === 'NGINX' ? '🟩' :
                     t.tech === 'IIS' ? '🪟' :
                     t.tech === 'TOMCAT' ? '🐱' : '⚙️';
        const verStr = t.version ? `v${t.version}` : '版本已隱藏';
        chipsHtml += `
          <span class="tech-chip ${isVuln ? 'vulnerable' : ''}" title="${t.category} (${(t.sources || []).map(s => s.name).join(', ')})">
            <span>${icon}</span>
            <span><strong>${t.name}</strong> ${verStr}</span>
            ${isVuln ? '<span>⚠️</span>' : ''}
          </span>
        `;
      }
      techChipsContainerEl.innerHTML = chipsHtml;
    }

    // 4. Vulnerabilities
    cveCountChipEl.textContent = `${vulns.length} 個`;
    cveCountChipEl.style.background = vulns.length > 0 ? '#ef4444' : '#334155';

    if (vulns.length === 0) {
      vulnerabilitiesContainerEl.innerHTML = `
        <div class="card empty-state" style="border-left: 3px solid #10b981;">
          🛡️ 未在此站檢測版本中發現 CVE-2024-4577、CVE-2023-25690、CVE-2024-27980 等已知近期重大漏洞。
        </div>
      `;
    } else {
      let html = '';
      for (const v of vulns) {
        const remedyList = Array.isArray(v.remediation)
          ? v.remediation.map(r => `<div>• ${r}</div>`).join('')
          : `<div>• ${v.remediation}</div>`;

        html += `
          <div class="cve-card ${v.severity}">
            <div class="cve-top">
              <div class="cve-id-group">
                <span class="cve-tech-tag">${v.tech || 'SERVER'}</span>
                <span class="cve-id">${v.id}</span>
              </div>
              <span class="cvss-tag ${v.severity}">CVSS ${v.cvss || 'N/A'} ${v.severity}</span>
            </div>
            <div class="cve-name">${v.name}</div>
            <div class="cve-desc">${v.summary}</div>
            <div style="font-size:11px; color:#cbd5e1; margin-bottom:4px;">
              <strong>受影響版本:</strong> ${v.affected}
            </div>
            <div style="font-size:11px; color:#34d399; margin-bottom:6px;">
              <strong>修復版本:</strong> ${v.fixed}
            </div>
            <div class="cve-remedy">
              <div class="cve-remedy-title">🛠️ 防禦與修復指引</div>
              ${remedyList}
            </div>
          </div>
        `;
      }
      vulnerabilitiesContainerEl.innerHTML = html;
    }

    // 5. Security Headers Checklist
    const checks = audit.checks || [];
    if (checks.length === 0) {
      headersCheckContainerEl.innerHTML = '<div class="empty-state">尚未取得標頭資料</div>';
    } else {
      let checksHtml = '';
      for (const c of checks) {
        checksHtml += `
          <div class="check-item">
            <div>
              <div class="check-name"><strong>${c.name}</strong></div>
              <div style="font-size:11px; color:#94a3b8; margin-top:2px;">${c.message}</div>
            </div>
            <span class="check-status ${c.status}">${c.status === 'PASS' ? '通過' : '未配置'}</span>
          </div>
        `;
      }
      headersCheckContainerEl.innerHTML = checksHtml;
    }
  }

  /**
   * Load audit data for a specific tab ID
   */
  function fetchAuditForTab(tabId, fallbackUrl) {
    activeTabId = tabId;
    if (fallbackUrl && fallbackUrl.startsWith('http')) {
      manualUrlInputEl.value = fallbackUrl;
    }

    chrome.runtime.sendMessage({ type: "GET_TAB_AUDIT", tabId }, async (response) => {
      if (response && response.ok && response.data) {
        renderAudit(response.data);
      } else if (fallbackUrl) {
        triggerTabScan({ id: tabId, url: fallbackUrl });
      } else {
        targetUrlEl.textContent = '尚無分頁審查資料';
      }
    });
  }

  /**
   * Load active tab audit from background service worker
   */
  async function loadActiveTabAudit() {
    // If opened with paramTabId, use it directly
    if (paramTabId) {
      chrome.tabs.get(paramTabId, (tab) => {
        const url = (tab && tab.url) || '';
        fetchAuditForTab(paramTabId, url);
      });
      return;
    }

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.id) {
        targetUrlEl.textContent = '無法取得當前分頁';
        return;
      }
      fetchAuditForTab(tab.id, tab.url);
    } catch (err) {
      console.warn("Failed to query active tab:", err);
    }
  }

  /**
   * Trigger immediate scan for tab
   */
  async function triggerTabScan(tab) {
    if (!tab || !tab.url || !tab.url.startsWith('http')) {
      renderAudit({
        url: tab ? tab.url : '非 HTTP 網頁',
        audit: {
          riskLevel: 'NONE',
          detectedTechs: [],
          vulnerabilities: [],
          checks: []
        }
      });
      return;
    }

    statusIconEl.textContent = '⏳';
    statusTextEl.textContent = '正在發送請求分析伺服器標頭...';

    chrome.runtime.sendMessage({
      type: "AUDIT_MANUAL_URL",
      url: tab.url,
      tabId: tab.id
    }, (resp) => {
      if (resp && resp.ok && resp.data) {
        renderAudit(resp.data);
      } else {
        statusBannerEl.className = 'status-banner NONE';
        statusIconEl.textContent = '⚠️';
        statusTextEl.textContent = resp ? resp.error : '未能取得頁面回應標頭';
      }
    });
  }

  // Event: Re-scan Current Page
  btnRescanEl.addEventListener('click', async () => {
    if (activeTabId) {
      chrome.tabs.get(activeTabId, (tab) => {
        if (tab) triggerTabScan(tab);
      });
    } else {
      loadActiveTabAudit();
    }
  });

  // Event: Manual URL Audit
  btnManualAuditEl.addEventListener('click', () => {
    let inputUrl = manualUrlInputEl.value.trim();
    if (!inputUrl) return;

    if (!/^https?:\/\//i.test(inputUrl)) {
      inputUrl = 'https://' + inputUrl;
      manualUrlInputEl.value = inputUrl;
    }

    statusBannerEl.className = 'status-banner NONE';
    statusIconEl.textContent = '⏳';
    statusTextEl.textContent = `正在檢測目標: ${inputUrl} ...`;

    chrome.runtime.sendMessage({
      type: "AUDIT_MANUAL_URL",
      url: inputUrl
    }, (resp) => {
      if (resp && resp.ok && resp.data) {
        renderAudit(resp.data);
      } else {
        statusBannerEl.className = 'status-banner CRITICAL';
        statusIconEl.textContent = '❌';
        statusTextEl.textContent = resp ? resp.error : '檢測連線失敗';
      }
    });
  });

  // Event: Copy Report to Clipboard
  btnCopyReportEl.addEventListener('click', () => {
    if (!currentAuditData || !currentAuditData.audit) {
      alert("尚未有檢測資料可複製。");
      return;
    }

    const audit = currentAuditData.audit;
    const url = currentAuditData.url || '未知網址';
    const timeStr = new Date(audit.timestamp || Date.now()).toLocaleString();

    let report = `# 網站伺服器與後端安全檢測報告\n\n`;
    report += `- **檢測目標**: ${url}\n`;
    report += `- **檢測時間**: ${timeStr}\n`;
    report += `- **綜合安全等級**: ${audit.riskLevel}\n\n`;

    report += `### ⚙️ 偵測到的架構與技術棧\n`;
    const detectedTechs = audit.detectedTechs || [];
    if (detectedTechs.length === 0) {
      report += `- 未偵測到明確伺服器技術指紋\n\n`;
    } else {
      for (const t of detectedTechs) {
        report += `- **${t.name}** (${t.category}): ${t.version ? '版本 `' + t.version + '`' : '版本已隱藏'}\n`;
        if (t.sources && t.sources.length > 0) {
          report += `  - 指紋依據: ${t.sources.map(s => `${s.name}: ${s.value}`).join(' | ')}\n`;
        }
      }
      report += `\n`;
    }

    report += `### 🚨 重大 CVE 漏洞檢測結果 (${(audit.vulnerabilities || []).length} 個)\n`;
    if (!audit.vulnerabilities || audit.vulnerabilities.length === 0) {
      report += `未在此檢測版本中發現已知近期重大 CVE 漏洞。\n\n`;
    } else {
      for (const v of audit.vulnerabilities) {
        report += `#### [${v.tech || 'SERVER'}] [${v.severity}] ${v.id}: ${v.name}\n`;
        report += `- **CVSS 評分**: ${v.cvss || 'N/A'}\n`;
        report += `- **受影響版本**: ${v.affected}\n`;
        report += `- **官方修復版本**: ${v.fixed}\n`;
        report += `- **漏洞概述**: ${v.summary}\n`;
        report += `- **潛在危害**: ${v.impact}\n`;
        report += `- **防禦修復建議**:\n`;
        if (Array.isArray(v.remediation)) {
          for (const r of v.remediation) {
            report += `  - ${r}\n`;
          }
        } else {
          report += `  - ${v.remediation}\n`;
        }
        report += `\n`;
      }
    }

    report += `### 🛡️ 安全防禦標頭檢查\n`;
    for (const c of (audit.checks || [])) {
      report += `- **${c.name}**: [${c.status === 'PASS' ? '通過' : '未配置'}] - ${c.message}\n`;
      if (c.value && c.value !== '(未設定)') {
        report += `  - 標頭內容: \`${c.value}\`\n`;
      }
    }

    report += `\n---\n*報告產生自 網站伺服器與後端漏洞檢測器 (Web Server & Backend Security Auditor)*\n`;

    navigator.clipboard.writeText(report).then(() => {
      const origText = btnCopyReportEl.textContent;
      btnCopyReportEl.textContent = '✅ 已複製報告！';
      setTimeout(() => {
        btnCopyReportEl.textContent = origText;
      }, 2000);
    }).catch(err => {
      console.error("Clipboard copy failed:", err);
    });
  });

  // Initial load
  loadActiveTabAudit();
});
