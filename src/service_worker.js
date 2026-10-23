/**
 * Service Worker: Real-time network header monitoring,
 * Multi-server vulnerability auditing, badge updates, and automatic popup alert on Red (high risk).
 */

try {
  importScripts('cve_database.js');
} catch (e) {
  try {
    importScripts('src/cve_database.js');
  } catch (e2) {
    console.error('Failed to load cve_database.js in service worker:', e2);
  }
}

// Red is the default brand and danger icon
const ICONS = {
  SAFE: {
    16: "icons/icon16-green.png",
    48: "icons/icon48-green.png",
    128: "icons/icon128-green.png"
  },
  DANGER: {
    16: "icons/icon16-red.png",
    48: "icons/icon48-red.png",
    128: "icons/icon128-red.png"
  },
  DEFAULT: {
    16: "icons/icon16-red.png",
    48: "icons/icon48-red.png",
    128: "icons/icon128-red.png"
  }
};

// In-memory tab audit cache & deduplication set for auto-popups
const tabAudits = new Map();
const alertedTabs = new Set();

/**
 * Updates browser action badge and icon based on audit result
 */
function updateTabUI(tabId, audit) {
  if (!tabId || tabId < 0 || !audit) return;

  try {
    chrome.action.setBadgeText({ tabId, text: audit.badgeText || "" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: audit.badgeColor || "#ef4444" });

    let iconPath = ICONS.DEFAULT;
    if (audit.riskLevel === 'CRITICAL' || audit.riskLevel === 'HIGH') {
      iconPath = ICONS.DANGER;
    } else if (audit.riskLevel === 'SAFE') {
      iconPath = ICONS.SAFE;
    } else {
      iconPath = ICONS.DEFAULT;
    }

    chrome.action.setIcon({ tabId, path: iconPath });
  } catch (err) {
    console.warn(`Failed to update UI for tab ${tabId}:`, err);
  }
}

/**
 * Automatically open popup window when a website is Red (CRITICAL / HIGH vulnerability)
 */
async function maybeAutoOpenPopup(tabId, url, audit) {
  if (!tabId || tabId < 0 || !audit) return;

  // Only trigger on Red status (CRITICAL or HIGH risk)
  const isRed = audit.riskLevel === 'CRITICAL' || audit.riskLevel === 'HIGH';
  if (!isRed) return;

  // Check user setting (default is true)
  const settings = await chrome.storage.local.get(['autoPopupOnRed']);
  if (settings.autoPopupOnRed === false) return;

  let host = '';
  try {
    host = new URL(url).hostname;
  } catch (e) {
    host = url;
  }

  // Deduplicate per tab and hostname so we don't spam windows
  const alertKey = `${tabId}_${host}`;
  if (alertedTabs.has(alertKey)) return;
  alertedTabs.add(alertKey);

  try {
    const tab = await chrome.tabs.get(tabId);
    if (!tab) return;

    let opened = false;
    // 1. Try native chrome.action.openPopup if available
    if (chrome.action && typeof chrome.action.openPopup === 'function') {
      try {
        await chrome.action.openPopup({ windowId: tab.windowId });
        opened = true;
      } catch (openErr) {
        opened = false;
      }
    }

    // 2. Fallback: Create dedicated floating popup window
    if (!opened) {
      const popupUrl = chrome.runtime.getURL(`popup.html?tabId=${tabId}&auto=true`);
      await chrome.windows.create({
        url: popupUrl,
        type: 'popup',
        width: 440,
        height: 640,
        focused: true
      });
    }
  } catch (err) {
    console.warn('Auto open popup error:', err);
  }
}

/**
 * Perform audit and persist state for a tab
 */
function auditAndSaveTab(tabId, state) {
  if (!self.PhpSecAudit) return null;

  const audit = self.PhpSecAudit.auditTarget({
    url: state.url,
    headers: state.headers || {},
    cookies: state.cookies || "",
    domEvidence: state.domEvidence || {}
  });

  const merged = {
    ...state,
    audit
  };

  tabAudits.set(tabId, merged);

  const storageKey = `tab_${tabId}`;
  chrome.storage.local.set({ [storageKey]: merged }).catch(() => {});

  updateTabUI(tabId, audit);

  // Check if we should trigger auto-popup on Red vulnerabilities
  maybeAutoOpenPopup(tabId, state.url, audit);

  return merged;
}

// Monitor HTTP response headers
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    const tabId = details.tabId;
    if (!tabId || tabId < 0) return;

    const existing = tabAudits.get(tabId) || {
      tabId,
      url: details.url,
      headers: {},
      cookies: "",
      domEvidence: {}
    };

    if (details.type === 'main_frame') {
      // Clear previous alert key if navigating to a different origin
      try {
        const newHost = new URL(details.url).hostname;
        const oldHost = existing.url ? new URL(existing.url).hostname : '';
        if (newHost !== oldHost) {
          alertedTabs.delete(`${tabId}_${oldHost}`);
        }
      } catch (e) {}

      existing.url = details.url;
      existing.headers = {};
    }

    if (details.responseHeaders) {
      for (const h of details.responseHeaders) {
        if (!h.name) continue;
        const lowerName = h.name.toLowerCase();
        if (existing.headers[lowerName]) {
          existing.headers[lowerName] += `, ${h.value || ""}`;
        } else {
          existing.headers[lowerName] = h.value || "";
        }
      }
    }

    auditAndSaveTab(tabId, existing);
  },
  {
    urls: ["<all_urls>"],
    types: ["main_frame", "sub_frame", "xmlhttprequest"]
  },
  ["responseHeaders"]
);

// Clean up tabs on close
chrome.tabs.onRemoved.addListener((tabId) => {
  tabAudits.delete(tabId);
  for (const key of alertedTabs) {
    if (key.startsWith(`${tabId}_`)) {
      alertedTabs.delete(key);
    }
  }
  chrome.storage.local.remove([`tab_${tabId}`]).catch(() => {});
});

// Handle messages from content script or popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) return;

  const tabId = (sender.tab && sender.tab.id) || message.tabId;

  // 1. Content script sends DOM findings & document cookies
  if (message.type === "CONTENT_DOM_EVIDENCE") {
    if (!tabId) return;
    const existing = tabAudits.get(tabId) || {
      tabId,
      url: message.url || (sender.tab && sender.tab.url) || "",
      headers: {},
      cookies: "",
      domEvidence: {}
    };

    existing.cookies = message.cookies || existing.cookies;
    existing.domEvidence = {
      ...(existing.domEvidence || {}),
      ...(message.evidence || {})
    };

    const saved = auditAndSaveTab(tabId, existing);
    sendResponse({ ok: true, audit: saved ? saved.audit : null });
    return true;
  }

  // 2. Popup requests current tab audit state
  if (message.type === "GET_TAB_AUDIT") {
    if (!tabId) {
      sendResponse({ ok: false, error: "No active tab ID" });
      return;
    }

    const current = tabAudits.get(tabId);
    if (current && current.audit) {
      sendResponse({ ok: true, data: current });
      return;
    }

    chrome.storage.local.get([`tab_${tabId}`], (res) => {
      const stored = res[`tab_${tabId}`];
      if (stored) {
        tabAudits.set(tabId, stored);
        sendResponse({ ok: true, data: stored });
      } else {
        sendResponse({ ok: false, notAudited: true });
      }
    });
    return true;
  }

  // 3. Manual URL Audit triggered from popup
  if (message.type === "AUDIT_MANUAL_URL") {
    const targetUrl = message.url;
    if (!targetUrl || !self.PhpSecAudit) {
      sendResponse({ ok: false, error: "Invalid target URL" });
      return;
    }

    (async () => {
      try {
        let resp = null;
        try {
          resp = await fetch(targetUrl, { method: 'HEAD', cache: 'no-store' });
        } catch (headErr) {
          resp = await fetch(targetUrl, { method: 'GET', cache: 'no-store' });
        }

        const headers = {};
        for (const [key, value] of resp.headers.entries()) {
          headers[key.toLowerCase()] = value;
        }

        const audit = self.PhpSecAudit.auditTarget({
          url: targetUrl,
          headers,
          cookies: "",
          domEvidence: {}
        });

        sendResponse({
          ok: true,
          data: {
            url: targetUrl,
            headers,
            audit
          }
        });
      } catch (err) {
        sendResponse({
          ok: false,
          error: `無法連線至目標 URL (${err.message})。可能受 CORS、HTTPS 憑證或網路連線限制。`
        });
      }
    })();
    return true;
  }
});
