/**
 * Multi-Server & Backend Vulnerability Knowledge Base
 * Supports: PHP, Node.js (Express / Next.js), Apache HTTP Server, Nginx, Microsoft IIS, Apache Tomcat.
 * Provides passive fingerprint extraction, semantic version parsing, CVE vulnerability matching,
 * and security header evaluations.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PhpSecAudit = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // --- Version Parsers ---

  function parseGenericVersion(str, regex) {
    if (!str || typeof str !== 'string') return null;
    const match = str.match(regex);
    if (!match) return null;

    const major = parseInt(match[1], 10);
    const minor = match[2] !== undefined ? parseInt(match[2], 10) : 0;
    const patch = match[3] !== undefined ? parseInt(match[3], 10) : 0;

    return {
      major,
      minor,
      patch,
      raw: match[0].trim(),
      versionStr: `${major}.${minor}.${patch}`
    };
  }

  function parsePhpVersion(str) {
    if (!str || typeof str !== 'string') return null;
    let match = str.match(/(?:^|[^a-zA-Z0-9])PHP[\/\s-]?v?(\d+)\.(\d+)(?:\.(\d+))?/i);
    if (!match) {
      match = str.match(/^v?(\d+)\.(\d+)(?:\.(\d+))?/);
    }
    if (!match) return null;

    const major = parseInt(match[1], 10);
    const minor = parseInt(match[2], 10);
    const patch = match[3] ? parseInt(match[3], 10) : 0;

    return {
      major,
      minor,
      patch,
      raw: match[0].trim(),
      versionStr: `${major}.${minor}.${patch}`
    };
  }

  function parseApacheVersion(str) {
    return parseGenericVersion(str, /Apache(?:\/|\s+v?)(\d+)\.(\d+)(?:\.(\d+))?/i);
  }

  function parseNginxVersion(str) {
    return parseGenericVersion(str, /nginx(?:\/|\s+v?)(\d+)\.(\d+)(?:\.(\d+))?/i);
  }

  function parseNodeVersion(str) {
    return parseGenericVersion(str, /(?:Node(?:\.js)?[\/\s-]?v?|Node[\s\/])(\d+)\.(\d+)(?:\.(\d+))?/i);
  }

  function parseTomcatVersion(str) {
    return parseGenericVersion(str, /(?:Apache\s+Tomcat|Apache-Coyote)[\/\s-]?v?(\d+)\.(\d+)(?:\.(\d+))?/i);
  }

  function parseIisVersion(str) {
    if (!str || typeof str !== 'string') return null;
    const match = str.match(/(?:Microsoft-IIS|Microsoft-HTTPAPI)[\/\s-]?v?(\d+)\.(\d+)?/i);
    if (!match) return null;
    const major = parseInt(match[1], 10);
    const minor = match[2] !== undefined ? parseInt(match[2], 10) : 0;
    return {
      major,
      minor,
      patch: 0,
      raw: match[0].trim(),
      versionStr: `${major}.${minor}`
    };
  }

  function compareVersions(v1, v2) {
    if (v1.major !== v2.major) return v1.major - v2.major;
    if (v1.minor !== v2.minor) return v1.minor - v2.minor;
    return v1.patch - v2.patch;
  }

  // --- Multi-Technology CVE Knowledge Base ---
  const CVE_DATABASE = [
    // === PHP CVEs ===
    {
      tech: 'PHP',
      id: "CVE-2024-4577",
      name: "PHP-CGI 參數注入與遠端程式碼執行 (RCE)",
      severity: "CRITICAL",
      cvss: 9.8,
      date: "2024-06",
      isVulnerable: (v) => {
        if (v.major === 8 && v.minor === 3 && v.patch < 8) return true;
        if (v.major === 8 && v.minor === 2 && v.patch < 20) return true;
        if (v.major === 8 && v.minor === 1 && v.patch < 29) return true;
        if (v.major < 8 || (v.major === 8 && v.minor === 0)) return true;
        return false;
      },
      affected: "PHP 8.3 < 8.3.8, PHP 8.2 < 8.2.20, PHP 8.1 < 8.1.29, 及所有 PHP <= 8.0 舊版本",
      fixed: "PHP 8.3.8+, 8.2.20+, 8.1.29+",
      summary: "Windows 環境下因 Best-Fit 字元轉碼漏洞，攻擊者可藉由 %ad 繞過引數保護，向 PHP-CGI 注入指令，造成未授權遠端代碼執行 (RCE)。",
      impact: "嚴重威脅（Critical / CVSS 9.8）。攻擊者可輕易取得主機控制權，已遭駭客集團廣泛武器化利用。",
      remediation: [
        "立即升級 PHP 至修復版本（8.3.8+、8.2.20+、8.1.29+）。",
        "停用 PHP-CGI 模式，改用更安全的 PHP-FPM / FastCGI 架構。",
        "若暫時無法升級且運行於 Apache，可在設定檔中加入 RewriteRule 規則阻擋包含 %ad 的 Query String。"
      ]
    },
    {
      tech: 'PHP',
      id: "CVE-2024-8926",
      name: "PHP-CGI 查詢字串解析與邊界引數注入",
      severity: "HIGH",
      cvss: 7.5,
      date: "2024-09",
      isVulnerable: (v) => {
        if (v.major === 8 && v.minor === 3 && v.patch < 12) return true;
        if (v.major === 8 && v.minor === 2 && v.patch < 24) return true;
        if (v.major === 8 && v.minor === 1 && v.patch < 30) return true;
        if (v.major < 8 || (v.major === 8 && v.minor === 0)) return true;
        return false;
      },
      affected: "PHP 8.3 < 8.3.12, 8.2 < 8.2.24, 8.1 < 8.1.30",
      fixed: "PHP 8.3.12+, 8.2.24+, 8.1.30+",
      summary: "PHP-CGI SAPI 模組在處理特殊查詢字串邊界時未妥善過濾，可能導致引數注入防護機制失效。",
      impact: "高風險（High / CVSS 7.5）。可能導致未預期的參數被傳遞至解譯器執行。",
      remediation: [
        "升級至 PHP 8.3.12+、8.2.24+、8.1.30+。",
        "停止將 PHP 直接作為 CGI 執行檔暴露給 Web 伺服器。"
      ]
    },
    {
      tech: 'PHP',
      id: "CVE-2024-8927",
      name: "Multipart 請求解析緩衝區溢位讀取 (DoS / 資訊洩露)",
      severity: "HIGH",
      cvss: 7.5,
      date: "2024-09",
      isVulnerable: (v) => {
        if (v.major === 8 && v.minor === 3 && v.patch < 12) return true;
        if (v.major === 8 && v.minor === 2 && v.patch < 24) return true;
        if (v.major === 8 && v.minor === 1 && v.patch < 30) return true;
        if (v.major < 8 || (v.major === 8 && v.minor === 0)) return true;
        return false;
      },
      affected: "PHP 8.3 < 8.3.12, 8.2 < 8.2.24, 8.1 < 8.1.30",
      fixed: "PHP 8.3.12+, 8.2.24+, 8.1.30+",
      summary: "PHP 在處理非標準 multipart/form-data 封包邊界時存在長度計算錯誤，可能引發緩衝區越界讀取。",
      impact: "高風險（High / CVSS 7.5）。攻擊者可構造畸形上傳封包導致工作行程崩潰 (DoS) 或洩漏部分記憶體內容。",
      remediation: [
        "升級 PHP 至 8.3.12+、8.2.24+ 或 8.1.30+。"
      ]
    },
    {
      tech: 'PHP',
      id: "CVE-2024-2756",
      name: "Windows 平台 proc_open 命令引數注入繞過",
      severity: "HIGH",
      cvss: 7.5,
      date: "2024-04",
      isVulnerable: (v) => {
        if (v.major === 8 && v.minor === 3 && v.patch < 6) return true;
        if (v.major === 8 && v.minor === 2 && v.patch < 18) return true;
        if (v.major === 8 && v.minor === 1 && v.patch < 28) return true;
        if (v.major < 8 || (v.major === 8 && v.minor === 0)) return true;
        return false;
      },
      affected: "PHP 8.3 < 8.3.6, 8.2 < 8.2.18, 8.1 < 8.1.28",
      fixed: "PHP 8.3.6+, 8.2.18+, 8.1.28+",
      summary: "Windows 環境中 proc_open 函式在跳脫引數特殊字符時存在瑕疵，使攻擊者能繞過防護注入額外命令引數。",
      impact: "高風險（High / CVSS 7.5）。依賴 proc_open 執行外部程式的應用可能被植入任意執行引數。",
      remediation: [
        "升級 PHP 至 8.3.6+、8.2.18+ 或 8.1.28+。"
      ]
    },
    {
      tech: 'PHP',
      id: "CVE-2023-3824",
      name: "Phar 檔案解析記憶體緩衝區溢位 (RCE)",
      severity: "CRITICAL",
      cvss: 9.8,
      date: "2023-08",
      isVulnerable: (v) => {
        if (v.major === 8 && v.minor === 2 && v.patch < 8) return true;
        if (v.major === 8 && v.minor === 1 && v.patch < 22) return true;
        if (v.major === 8 && v.minor === 0 && v.patch < 30) return true;
        if (v.major < 8) return true;
        return false;
      },
      affected: "PHP 8.2 < 8.2.8, 8.1 < 8.1.22, 8.0 < 8.0.30, 7.x 全部",
      fixed: "PHP 8.2.8+, 8.1.22+, 8.0.30+",
      summary: "PHP 在處理惡意構造的 Phar 壓縮封裝目錄時，phar_dir_read 函式存在緩衝區溢位，可導致任意程式碼執行。",
      impact: "嚴重威脅（Critical / CVSS 9.8）。",
      remediation: [
        "升級 PHP 至 8.2.8+ 或 8.1.22+。"
      ]
    },
    {
      tech: 'PHP',
      id: "PHP-EOL",
      name: "PHP 官方生命週期終止 (End-of-Life)",
      severity: "HIGH",
      cvss: 7.5,
      date: "2024-11",
      isVulnerable: (v) => {
        if (v.major < 8 || (v.major === 8 && v.minor <= 1)) return true;
        return false;
      },
      affected: "PHP <= 8.1 (包含 5.x, 7.x, 8.0, 8.1)",
      fixed: "遷移升級至 PHP 8.2 或 8.3+",
      summary: "PHP 官方已正式終止對該版本的安全性維護支援（PHP 8.1 安全支援於 2024-11-25 截止）。",
      impact: "高風險。該版本不再獲得官方安全修補，任何新發現漏洞都將持續暴露。",
      remediation: [
        "儘速安排將伺服器 PHP 執行環境遷移至仍在支援期內的 PHP 8.2+ 或 8.3+。"
      ]
    },

    // === Node.js CVEs ===
    {
      tech: 'NODEJS',
      id: "CVE-2024-27980",
      name: "Node.js HTTP/2 連續空資料幀 DoS 攻擊漏洞",
      severity: "HIGH",
      cvss: 7.5,
      date: "2024-04",
      isVulnerable: (v) => {
        if (v.major < 18) return true;
        if (v.major === 18 && (v.minor < 20 || (v.minor === 20 && v.patch < 2))) return true;
        if (v.major === 20 && (v.minor < 12 || (v.minor === 12 && v.patch < 2))) return true;
        if (v.major === 21 && (v.minor < 7 || (v.minor === 7 && v.patch < 2))) return true;
        return false;
      },
      affected: "Node.js 18 < 18.20.2, 20 < 20.12.2, 21 < 21.7.2, 以及舊版 Node < 18",
      fixed: "Node.js 18.20.2+, 20.12.2+, 21.7.2+",
      summary: "攻擊者可發送連續未結束的 HTTP/2 空資料封包，導致 Node.js 事件迴圈工作執行緒進入無效迴圈，造成 CPU 100% 耗盡與服務阻斷 (DoS)。",
      impact: "高風險（High / CVSS 7.5）。外部攻擊者無需身分驗證即可癱瘓伺服器程序。",
      remediation: [
        "升級至 Node.js 20.12.2+ (LTS) 或 18.20.2+。",
        "若暫時無法升級，可在前端反向代理 (Nginx/Cloudflare) 關閉 HTTP/2 直連後端或進行連線速率限制。"
      ]
    },
    {
      tech: 'NODEJS',
      id: "CVE-2024-21892",
      name: "Node.js 程式碼執行缺陷 (Windows OpenSSL 配置目錄搜尋)",
      severity: "HIGH",
      cvss: 8.3,
      date: "2024-02",
      isVulnerable: (v) => {
        if (v.major < 18) return true;
        if (v.major === 18 && v.minor < 20) return true;
        if (v.major === 20 && (v.minor < 11 || (v.minor === 11 && v.patch < 1))) return true;
        if (v.major === 21 && (v.minor < 6 || (v.minor === 6 && v.patch < 2))) return true;
        return false;
      },
      affected: "Node.js 18 < 18.20.0, 20 < 20.11.1, 21 < 21.6.2",
      fixed: "Node.js 18.20.0+, 20.11.1+, 21.6.2+",
      summary: "Windows 環境下，Node.js 內建的 OpenSSL 在尋找引擎與配置檔時未對當前路徑正確防護，可能導致加載非預期目錄中的惡意動態連結庫或配置，引發任意代碼執行。",
      impact: "高風險（High / CVSS 8.3）。",
      remediation: [
        "升級 Node.js 至 20.11.1+ 或 18.20.0+。"
      ]
    },
    {
      tech: 'NODEJS',
      id: "CVE-2024-22019",
      name: "Node.js http_parser 分塊傳輸擴充套件記憶體耗盡 (DoS)",
      severity: "HIGH",
      cvss: 7.5,
      date: "2024-02",
      isVulnerable: (v) => {
        if (v.major < 18) return true;
        if (v.major === 18 && (v.minor < 19 || (v.minor === 19 && v.patch < 1))) return true;
        if (v.major === 20 && (v.minor < 11 || (v.minor === 11 && v.patch < 1))) return true;
        return false;
      },
      affected: "Node.js 18 < 18.19.1, 20 < 20.11.1",
      fixed: "Node.js 18.19.1+, 20.11.1+",
      summary: "Node.js 內建 HTTP 伺服器在解析大量 Chunked Transfer Extension 時缺乏有效長度限制，可能導致記憶體耗盡阻斷服務。",
      impact: "高風險（High / CVSS 7.5）。",
      remediation: [
        "升級 Node.js 至修補版本。"
      ]
    },
    {
      tech: 'NODEJS',
      id: "NODE-EOL",
      name: "Node.js 官方生命週期終止 (End-of-Life)",
      severity: "HIGH",
      cvss: 7.5,
      date: "2023-09",
      isVulnerable: (v) => {
        // Node <= 16 is completely EOL
        if (v.major < 18) return true;
        return false;
      },
      affected: "Node.js <= 16 (包含 16.x, 14.x, 12.x 及更早舊版)",
      fixed: "遷移升級至 Node.js 20 LTS 或 22 LTS",
      summary: "該 Node.js 版本已到達生命週期終點（Node 16 於 2023 年 9 月終止），官方不再提供任何安全更新。",
      impact: "高風險。已知安全缺陷無法修補，生產環境曝露風險極高。",
      remediation: [
        "儘速遷移至目前維護中的 Node.js 20 或 22 LTS 分支。"
      ]
    },

    // === Apache HTTP Server CVEs ===
    {
      tech: 'APACHE',
      id: "CVE-2024-38472",
      name: "Apache HTTP Server mod_rewrite 混淆編碼與 SSRF / 命令執行缺陷",
      severity: "HIGH",
      cvss: 8.2,
      date: "2024-07",
      isVulnerable: (v) => {
        if (v.major === 2 && v.minor === 4 && v.patch < 60) return true;
        if (v.major < 2 || (v.major === 2 && v.minor < 4)) return true;
        return false;
      },
      affected: "Apache HTTP Server < 2.4.60",
      fixed: "Apache 2.4.60+",
      summary: "mod_rewrite 模組在處理不可信請求路徑與跳脫編碼時未適當驗證 Windows UNC 路徑或後端代理，攻擊者可藉此觸發伺服器端請求偽造 (SSRF) 或本地腳本執行。",
      impact: "高風險（High / CVSS 8.2）。",
      remediation: [
        "立即升級 Apache 至 2.4.60 或更高版本。",
        "檢視 httpd.conf 中的 RewriteRule 規則，避免將未經校驗的使用者輸入直接映射至檔案系統。"
      ]
    },
    {
      tech: 'APACHE',
      id: "CVE-2023-25690",
      name: "Apache HTTP Server HTTP Request Smuggling 請求走私漏洞",
      severity: "CRITICAL",
      cvss: 9.8,
      date: "2023-03",
      isVulnerable: (v) => {
        if (v.major === 2 && v.minor === 4 && v.patch < 56) return true;
        if (v.major < 2 || (v.major === 2 && v.minor < 4)) return true;
        return false;
      },
      affected: "Apache HTTP Server 2.4.0 至 2.4.55 (< 2.4.56)",
      fixed: "Apache 2.4.56+",
      summary: "當 Apache 使用 mod_proxy 與 RewriteRule 進行反向代理時，特殊格式的 CRLF 標頭可繞過轉發驗證，造成 HTTP 請求走私 (Request Smuggling)，攻擊者可藉此繞過前端存取控制或竊取他人會話憑證。",
      impact: "嚴重威脅（Critical / CVSS 9.8）。",
      remediation: [
        "升級 Apache 至 2.4.56 或更新版本。"
      ]
    },
    {
      tech: 'APACHE',
      id: "CVE-2021-41773",
      name: "Apache HTTP Server 目錄穿越與遠端程式碼執行 (Path Traversal / RCE)",
      severity: "CRITICAL",
      cvss: 9.8,
      date: "2021-10",
      isVulnerable: (v) => {
        if (v.major === 2 && v.minor === 4 && (v.patch === 49 || v.patch === 50)) return true;
        return false;
      },
      affected: "Apache HTTP Server 2.4.49, 2.4.50",
      fixed: "Apache 2.4.51+",
      summary: "Apache 2.4.49 與 2.4.50 中的路徑正規化缺陷，使攻擊者可透過 `.%2e` 等雙重 URL 編碼進行目錄穿越，若伺服器啟用了 cgi-bin 或 mod_cgi，可進一步執行任意系統命令。",
      impact: "嚴重威脅（Critical / CVSS 9.8）。網路上存在大量全自動利用腳本。",
      remediation: [
        "立即升級 Apache 至 2.4.51 或最新穩定版 (2.4.62+)。"
      ]
    },

    // === Nginx CVEs ===
    {
      tech: 'NGINX',
      id: "CVE-2024-7347",
      name: "Nginx ngx_http_mp4_module 緩衝區下溢與崩潰 (Buffer Underflow)",
      severity: "HIGH",
      cvss: 7.5,
      date: "2024-08",
      isVulnerable: (v) => {
        if (v.major === 1) {
          if (v.minor === 27 && v.patch < 1) return true;
          if (v.minor === 26 && v.patch < 2) return true;
          if (v.minor < 26 && v.minor >= 5) return true;
        }
        return false;
      },
      affected: "Nginx 1.5.13 至 1.27.0 (< 1.27.1 / < 1.26.2)",
      fixed: "Nginx 1.27.1+, 1.26.2+",
      summary: "啟用 ngx_http_mp4_module 時，特製的 MP4 串流請求可能導致工作行程記憶體緩衝區下溢，引發 Worker Process 終止或 DoS。",
      impact: "高風險（High / CVSS 7.5）。",
      remediation: [
        "升級至 Nginx 1.26.2+ (穩定版) 或 1.27.1+ (主線版)。",
        "若不需要 MP4 串流模組，建議在編譯或配置中移除。"
      ]
    },
    {
      tech: 'NGINX',
      id: "CVE-2021-23017",
      name: "Nginx 內建 DNS 解析器 1-byte 記憶體覆寫缺陷",
      severity: "HIGH",
      cvss: 8.1,
      date: "2021-05",
      isVulnerable: (v) => {
        if (v.major === 0) return true;
        if (v.major === 1 && (v.minor < 20 || (v.minor === 20 && v.patch === 0))) return true;
        return false;
      },
      affected: "Nginx 0.6.18 至 1.20.0",
      fixed: "Nginx 1.20.1+, 1.21.0+",
      summary: "在配置了 resolver 指令的環境下，偽造的惡意 DNS 回應封包可觸發 1 位元組記憶體覆寫，可能導致行程崩潰或潛在遠端代碼執行。",
      impact: "高風險（High / CVSS 8.1）。",
      remediation: [
        "升級 Nginx 至 1.20.1+ 或最新分支。"
      ]
    },

    // === Microsoft IIS CVEs ===
    {
      tech: 'IIS',
      id: "CVE-2022-21907",
      name: "Windows HTTP 協定堆疊 (http.sys) 遠端程式碼執行漏洞",
      severity: "CRITICAL",
      cvss: 9.8,
      date: "2022-01",
      isVulnerable: (v) => {
        // IIS 10.0 runs on Windows Server 2016/2019/2022
        if (v.major === 10) return true;
        return false;
      },
      affected: "Microsoft IIS 10.0 (Windows Server 2022 / 2019 / Windows 10/11)",
      fixed: "安裝微軟 2022 年 1 月安全累積修補程式 (KB5009557)",
      summary: "Windows 核心 http.sys 模組在處理特製 HTTP Accept-Encoding 封包時存在記憶體損毀漏洞，可遭遠端未認證攻擊者利用執行任意代碼 (可蠕蟲化 Wormable)。",
      impact: "嚴重威脅（Critical / CVSS 9.8）。",
      remediation: [
        "透過 Windows Update 安裝 2022 年 1 月或最新安全更新累積修補包。",
        "在登錄檔 HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\HTTP\\Parameters 暫時將 EnableHttp2Cleartext 設為 0 以減輕風險。"
      ]
    },

    // === Apache Tomcat CVEs ===
    {
      tech: 'TOMCAT',
      id: "CVE-2024-23672",
      name: "Apache Tomcat WebSocket 連線資源洩漏與 DoS",
      severity: "HIGH",
      cvss: 7.5,
      date: "2024-02",
      isVulnerable: (v) => {
        if (v.major === 11 && v.minor === 0 && v.patch < 17) return true;
        if (v.major === 10 && v.minor === 1 && v.patch < 19) return true;
        if (v.major === 9 && v.minor === 0 && v.patch < 86) return true;
        if (v.major < 9) return true;
        return false;
      },
      affected: "Tomcat 11 < 11.0.0-M17, 10.1 < 10.1.19, 9.0 < 9.0.86, 8.5 全部",
      fixed: "Tomcat 11.0.0-M17+, 10.1.19+, 9.0.86+",
      summary: "Tomcat 在處理 WebSocket 關閉握手時未正確釋放連線資源，可能引發連線洩漏與服務癱瘓。",
      impact: "高風險（High / CVSS 7.5）。",
      remediation: [
        "升級 Tomcat 至最新修復版（9.0.86+、10.1.19+ 或 11.0.0-M17+）。"
      ]
    },
    {
      tech: 'TOMCAT',
      id: "CVE-2020-1938",
      name: "Apache Tomcat Ghostcat AJP 協定檔案讀取與 RCE",
      severity: "CRITICAL",
      cvss: 9.8,
      date: "2020-02",
      isVulnerable: (v) => {
        if (v.major === 9 && v.minor === 0 && v.patch <= 30) return true;
        if (v.major === 8 && v.minor === 5 && v.patch <= 50) return true;
        if (v.major <= 7) return true;
        return false;
      },
      affected: "Tomcat 9.0.0.M1 - 9.0.30, 8.5.0 - 8.5.50, 7.x 全部",
      fixed: "Tomcat 9.0.31+, 8.5.51+, 7.0.100+",
      summary: "預設開啟且綁定 0.0.0.0 的 AJP 協定連接器 (Port 8009) 存在缺陷，攻擊者可讀取 webapp 目錄下任意靜態與 JSP 源碼檔案，並可能達成任意代碼執行。",
      impact: "嚴重威脅（Critical / CVSS 9.8）。",
      remediation: [
        "升級 Tomcat 至修復版，或在 server.xml 中停用 8009 AJP Connector，或設定 secret 認證密碼。"
      ]
    }
  ];

  /**
   * Evaluates security headers
   */
  function auditSecurityHeaders(headers) {
    const headerMap = {};
    if (Array.isArray(headers)) {
      for (const h of headers) {
        if (h && h.name) {
          headerMap[h.name.toLowerCase()] = h.value || "";
        }
      }
    } else if (headers && typeof headers === 'object') {
      for (const [k, v] of Object.entries(headers)) {
        headerMap[k.toLowerCase()] = v || "";
      }
    }

    const checks = [];

    // 1. X-Powered-By Check (PHP / Express / Next.js)
    const xPoweredBy = headerMap['x-powered-by'] || "";
    const hasPoweredBy = Boolean(xPoweredBy.trim());
    checks.push({
      key: 'expose_backend',
      name: 'X-Powered-By 框架資訊洩漏',
      status: hasPoweredBy ? 'WARN' : 'PASS',
      value: xPoweredBy || '(未洩漏 / 未配置)',
      message: hasPoweredBy
        ? `伺服器正透過 X-Powered-By 標頭洩漏技術細節 (${xPoweredBy})，降低攻擊者探測成本。`
        : '伺服器未回傳 X-Powered-By 標頭，符合隱蔽防禦實踐。',
      remediation: /express/i.test(xPoweredBy)
        ? "在 Express 中執行 app.disable('x-powered-by');"
        : /php/i.test(xPoweredBy)
        ? "在 php.ini 中設定 expose_php = Off"
        : "在後端設定中關閉 X-Powered-By 標頭或在反向代理中移除。"
    });

    // 2. Server Header Banner Disclosure
    const serverVal = headerMap['server'] || "";
    const leaksServerVer = /(?:\d+\.\d+)/.test(serverVal);
    checks.push({
      key: 'server_tokens',
      name: 'Server 標頭版本詳細度',
      status: leaksServerVer ? 'WARN' : 'PASS',
      value: serverVal || '(未洩漏)',
      message: leaksServerVer
        ? `Server 標頭暴露了精確版本號 (${serverVal})，有助於自動化掃描器鎖定特定 CVE。`
        : serverVal
        ? `Server 標頭僅暴露一般名稱 (${serverVal})，未洩漏精確小版本。`
        : '伺服器隱藏了 Server 標頭。',
      remediation: /nginx/i.test(serverVal)
        ? "在 nginx.conf 的 http 區塊中加入 server_tokens off;"
        : /apache/i.test(serverVal)
        ? "在 httpd.conf 中設定 ServerTokens Prod 與 ServerSignature Off"
        : "在反向代理中重寫或移除 Server 標頭。"
    });

    // 3. Strict-Transport-Security (HSTS)
    const hsts = headerMap['strict-transport-security'];
    checks.push({
      key: 'hsts',
      name: 'Strict-Transport-Security (HSTS)',
      status: hsts ? 'PASS' : 'WARN',
      value: hsts || '(未設定)',
      message: hsts
        ? '已啟用強制 HTTPS 連線防護。'
        : '缺少 HSTS 標頭，連線可能遭受 SSL 剝離或中間人降級攻擊。',
      remediation: '在伺服器標頭加入 Strict-Transport-Security: max-age=31536000; includeSubDomains'
    });

    // 4. Content-Security-Policy (CSP)
    const csp = headerMap['content-security-policy'];
    checks.push({
      key: 'csp',
      name: 'Content-Security-Policy (CSP)',
      status: csp ? 'PASS' : 'WARN',
      value: csp ? (csp.length > 50 ? csp.substring(0, 47) + '...' : csp) : '(未設定)',
      message: csp
        ? '已設定內容安全政策，能有效降低 XSS 與惡意腳本注入風險。'
        : '缺少 CSP 標頭，網頁若有 XSS 或第三方資源注入風險時缺乏防護罩。',
      remediation: '設定適合網站資源的 Content-Security-Policy 標頭。'
    });

    // 5. X-Content-Type-Options
    const xcto = headerMap['x-content-type-options'];
    const isNosniff = /nosniff/i.test(xcto || "");
    checks.push({
      key: 'xcto',
      name: 'X-Content-Type-Options',
      status: isNosniff ? 'PASS' : 'WARN',
      value: xcto || '(未設定)',
      message: isNosniff
        ? '已設定 nosniff，可防止瀏覽器進行 MIME 嗅探攻擊。'
        : '缺少 X-Content-Type-Options: nosniff，可能導致非可執行檔案被誤判解析執行。',
      remediation: '在伺服器標頭加入 X-Content-Type-Options: nosniff'
    });

    // 6. X-Frame-Options
    const xfo = headerMap['x-frame-options'];
    checks.push({
      key: 'xfo',
      name: 'X-Frame-Options (點擊劫持防護)',
      status: xfo ? 'PASS' : 'WARN',
      value: xfo || '(未設定)',
      message: xfo
        ? `已設定防護 (${xfo})，防止網站被內嵌於惡意 iframe 中。`
        : '缺少 X-Frame-Options，網站可能面臨 Clickjacking (點擊劫持) 風險。',
      remediation: '在伺服器標頭加入 X-Frame-Options: SAMEORIGIN 或 DENY'
    });

    return {
      headerMap,
      checks
    };
  }

  /**
   * Full Target Multi-Server Audit
   */
  function auditTarget({ url, headers, cookies, domEvidence }) {
    headers = headers || {};
    cookies = cookies || "";
    domEvidence = domEvidence || {};

    const { headerMap, checks } = auditSecurityHeaders(headers);

    const xPoweredBy = headerMap['x-powered-by'] || "";
    const serverHeader = headerMap['server'] || "";
    const setCookie = headerMap['set-cookie'] || "";

    const detectedTechs = [];
    const vulnerabilities = [];

    // --- 1. Detect PHP ---
    const phpSources = [];
    let phpVersion = null;
    if (/php/i.test(xPoweredBy)) {
      phpSources.push({ name: 'X-Powered-By', value: xPoweredBy });
      const p = parsePhpVersion(xPoweredBy);
      if (p) phpVersion = p;
    }
    if (/php/i.test(serverHeader)) {
      phpSources.push({ name: 'Server', value: serverHeader });
      if (!phpVersion) {
        const p = parsePhpVersion(serverHeader);
        if (p) phpVersion = p;
      }
    }
    if (/PHPSESSID/i.test(cookies) || /PHPSESSID/i.test(setCookie)) {
      phpSources.push({ name: 'Cookie', value: 'PHPSESSID' });
    }
    if (domEvidence.hasPhpLinks) {
      phpSources.push({ name: 'DOM', value: '頁面包含 .php 端點' });
    }
    if (domEvidence.generator && /wordpress|drupal|joomla/i.test(domEvidence.generator)) {
      phpSources.push({ name: 'Generator', value: domEvidence.generator });
    }

    if (phpSources.length > 0) {
      detectedTechs.push({
        tech: 'PHP',
        name: 'PHP',
        category: '語言執行環境',
        version: phpVersion ? phpVersion.versionStr : null,
        rawVersion: phpVersion ? phpVersion.raw : null,
        sources: phpSources
      });

      if (phpVersion) {
        for (const cve of CVE_DATABASE) {
          if (cve.tech === 'PHP' && cve.isVulnerable(phpVersion)) {
            vulnerabilities.push(cve);
          }
        }
      }
    }

    // --- 2. Detect Node.js / Express / Next.js ---
    const nodeSources = [];
    let nodeVersion = null;
    if (/express/i.test(xPoweredBy)) {
      nodeSources.push({ name: 'X-Powered-By', value: 'Express' });
    }
    if (/next\.js/i.test(xPoweredBy)) {
      nodeSources.push({ name: 'X-Powered-By', value: 'Next.js' });
    }
    if (/node(?:\.js)?/i.test(serverHeader) || /node(?:\.js)?/i.test(xPoweredBy)) {
      const p = parseNodeVersion(serverHeader) || parseNodeVersion(xPoweredBy);
      if (p) nodeVersion = p;
      nodeSources.push({ name: 'Header', value: serverHeader || xPoweredBy });
    }
    if (/connect\.sid|express:sess|next-auth/i.test(cookies) || /connect\.sid|express:sess|next-auth/i.test(setCookie)) {
      nodeSources.push({ name: 'Cookie', value: 'Node.js / Express Session Cookie' });
    }
    if (domEvidence.isNextJs) {
      nodeSources.push({ name: 'DOM', value: '__NEXT_DATA__ / Next.js 頁面特徵' });
    }

    if (nodeSources.length > 0) {
      detectedTechs.push({
        tech: 'NODEJS',
        name: 'Node.js / Express',
        category: '後端執行環境 / 框架',
        version: nodeVersion ? nodeVersion.versionStr : null,
        rawVersion: nodeVersion ? nodeVersion.raw : null,
        sources: nodeSources
      });

      if (nodeVersion) {
        for (const cve of CVE_DATABASE) {
          if (cve.tech === 'NODEJS' && cve.isVulnerable(nodeVersion)) {
            vulnerabilities.push(cve);
          }
        }
      }
    }

    // --- 3. Detect Apache HTTP Server ---
    const apacheVersion = parseApacheVersion(serverHeader);
    if (apacheVersion || /apache/i.test(serverHeader)) {
      const apacheSources = [{ name: 'Server', value: serverHeader }];
      detectedTechs.push({
        tech: 'APACHE',
        name: 'Apache HTTP Server',
        category: 'Web 伺服器',
        version: apacheVersion ? apacheVersion.versionStr : null,
        rawVersion: apacheVersion ? apacheVersion.raw : null,
        sources: apacheSources
      });

      if (apacheVersion) {
        for (const cve of CVE_DATABASE) {
          if (cve.tech === 'APACHE' && cve.isVulnerable(apacheVersion)) {
            vulnerabilities.push(cve);
          }
        }
      }
    }

    // --- 4. Detect Nginx ---
    const nginxVersion = parseNginxVersion(serverHeader);
    if (nginxVersion || /nginx/i.test(serverHeader)) {
      const nginxSources = [{ name: 'Server', value: serverHeader }];
      detectedTechs.push({
        tech: 'NGINX',
        name: 'Nginx',
        category: 'Web 伺服器 / 反向代理',
        version: nginxVersion ? nginxVersion.versionStr : null,
        rawVersion: nginxVersion ? nginxVersion.raw : null,
        sources: nginxSources
      });

      if (nginxVersion) {
        for (const cve of CVE_DATABASE) {
          if (cve.tech === 'NGINX' && cve.isVulnerable(nginxVersion)) {
            vulnerabilities.push(cve);
          }
        }
      }
    }

    // --- 5. Detect Microsoft IIS ---
    const iisVersion = parseIisVersion(serverHeader);
    if (iisVersion || /microsoft-iis|microsoft-httpapi/i.test(serverHeader)) {
      const iisSources = [{ name: 'Server', value: serverHeader }];
      detectedTechs.push({
        tech: 'IIS',
        name: 'Microsoft IIS',
        category: 'Web 伺服器 (Windows)',
        version: iisVersion ? iisVersion.versionStr : null,
        rawVersion: iisVersion ? iisVersion.raw : null,
        sources: iisSources
      });

      if (iisVersion) {
        for (const cve of CVE_DATABASE) {
          if (cve.tech === 'IIS' && cve.isVulnerable(iisVersion)) {
            vulnerabilities.push(cve);
          }
        }
      }
    }

    // --- 6. Detect Apache Tomcat ---
    const tomcatVersion = parseTomcatVersion(serverHeader);
    const hasJsessionid = /JSESSIONID/i.test(cookies) || /JSESSIONID/i.test(setCookie);
    if (tomcatVersion || /tomcat|coyote/i.test(serverHeader) || hasJsessionid) {
      const tomcatSources = [];
      if (serverHeader) tomcatSources.push({ name: 'Server', value: serverHeader });
      if (hasJsessionid) tomcatSources.push({ name: 'Cookie', value: 'JSESSIONID (Java/Tomcat)' });

      detectedTechs.push({
        tech: 'TOMCAT',
        name: 'Apache Tomcat / Java',
        category: '應用伺服器 (Java)',
        version: tomcatVersion ? tomcatVersion.versionStr : null,
        rawVersion: tomcatVersion ? tomcatVersion.raw : null,
        sources: tomcatSources
      });

      if (tomcatVersion) {
        for (const cve of CVE_DATABASE) {
          if (cve.tech === 'TOMCAT' && cve.isVulnerable(tomcatVersion)) {
            vulnerabilities.push(cve);
          }
        }
      }
    }

    // --- Determine overall risk level ---
    let riskLevel = 'SAFE';
    let badgeText = '';
    let badgeColor = '#38A169';

    if (vulnerabilities.some(v => v.severity === 'CRITICAL')) {
      riskLevel = 'CRITICAL';
      badgeText = '!';
      badgeColor = '#E53E3E'; // Red
    } else if (vulnerabilities.some(v => v.severity === 'HIGH')) {
      riskLevel = 'HIGH';
      badgeText = '!';
      badgeColor = '#DD6B20'; // Orange
    } else if (vulnerabilities.some(v => v.severity === 'MEDIUM') || checks.some(c => c.status === 'WARN')) {
      riskLevel = 'WARNING';
      badgeText = '▲';
      badgeColor = '#D69E2E'; // Yellow
    } else if (detectedTechs.length > 0) {
      riskLevel = 'INFO';
      badgeText = 'OK';
      badgeColor = '#3182CE'; // Blue
    } else {
      riskLevel = 'SAFE';
      badgeText = '';
      badgeColor = '#38A169'; // Green
    }

    // Legacy compatibility fields for PHP
    const phpTech = detectedTechs.find(t => t.tech === 'PHP');

    return {
      url: url || "",
      timestamp: Date.now(),
      detectedTechs,
      phpDetected: Boolean(phpTech),
      version: phpTech ? phpTech.version : null,
      rawVersion: phpTech ? phpTech.rawVersion : null,
      sources: phpTech ? phpTech.sources : [],
      vulnerabilities,
      checks,
      riskLevel,
      badgeText,
      badgeColor
    };
  }

  return {
    parsePhpVersion,
    parseApacheVersion,
    parseNginxVersion,
    parseNodeVersion,
    parseTomcatVersion,
    parseIisVersion,
    compareVersions,
    CVE_DATABASE,
    auditSecurityHeaders,
    auditTarget
  };
});
