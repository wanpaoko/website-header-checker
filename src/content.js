/**
 * Content Script: Extracts DOM and client-side indicators for multi-server environments:
 * PHP, Node.js (Next.js / Nuxt / Express), Tomcat (JSESSIONID), etc.
 */

(function () {
  'use strict';

  function extractDomEvidence() {
    let generator = null;
    const metaGen = document.querySelector('meta[name="generator" i]');
    if (metaGen && metaGen.content) {
      generator = metaGen.content.trim();
    }

    // Check for Next.js / React SSR
    const hasNextData = Boolean(document.getElementById('__NEXT_DATA__'));
    const hasNextScripts = Boolean(document.querySelector('script[src*="/_next/"]'));
    const isNextJs = hasNextData || hasNextScripts;

    // Check for Nuxt / Vue SSR
    const isNuxt = Boolean(document.getElementById('__NUXT__') || document.querySelector('script[src*="/_nuxt/"]'));

    const phpEndpoints = new Set();
    const isPhpUrl = (url) => {
      if (!url) return false;
      return /\.php($|\?|#)/i.test(url);
    };

    // Check forms
    const forms = document.querySelectorAll('form[action]');
    for (const f of forms) {
      const act = f.getAttribute('action');
      if (isPhpUrl(act)) {
        phpEndpoints.add(act);
        if (phpEndpoints.size >= 3) break;
      }
    }

    // Check links
    if (phpEndpoints.size < 3) {
      const links = document.querySelectorAll('a[href]');
      for (const a of links) {
        const href = a.getAttribute('href');
        if (isPhpUrl(href)) {
          phpEndpoints.add(href);
          if (phpEndpoints.size >= 3) break;
        }
      }
    }

    const hasPhpLinks = phpEndpoints.size > 0 || isPhpUrl(window.location.pathname);

    return {
      generator,
      isNextJs,
      isNuxt,
      hasPhpLinks,
      phpEndpoints: Array.from(phpEndpoints)
    };
  }

  function reportEvidence() {
    try {
      const evidence = extractDomEvidence();
      chrome.runtime.sendMessage({
        type: "CONTENT_DOM_EVIDENCE",
        url: window.location.href,
        cookies: document.cookie || "",
        evidence
      }, () => {
        if (chrome.runtime.lastError) {
          // ignore
        }
      });
    } catch (e) {
      // Content script context may be invalidated during reload
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', reportEvidence);
  } else {
    reportEvidence();
  }

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg && msg.type === "TRIGGER_CONTENT_SCAN") {
      const evidence = extractDomEvidence();
      sendResponse({
        ok: true,
        url: window.location.href,
        cookies: document.cookie || "",
        evidence
      });
    }
  });
})();
