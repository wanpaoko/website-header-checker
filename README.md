# 伺服器與後端漏洞安全檢測器 (Web Server & Backend Security Auditor)

這是一個基於 **Chrome Extension (Manifest V3)** 的網站安全檢測工具，專門用來在瀏覽網頁時**即時偵測目標網站使用的伺服器與後端環境（PHP、Node.js / Express / Next.js、Apache、Nginx、Microsoft IIS、Apache Tomcat）**，自動辨別暴露的版本標頭，並精準比對近年重大 CVE 漏洞與生命週期終止 (EOL) 狀況，提醒網站管理者與使用者即時防範與修復。

---

## 🌟 主要功能

1. **多架構被動指紋檢測**:
   - 監聽 HTTP 回應標頭（`X-Powered-By`、`Server`）。
   - 辨識後端語言與框架：**PHP**、**Node.js**、**Express**、**Next.js**。
   - 辨識主流 Web 伺服器：**Apache HTTP Server**、**Nginx**、**Microsoft IIS**、**Apache Tomcat**。
   - 偵測 Session Cookie（`PHPSESSID`、`connect.sid`、`express:sess`、`JSESSIONID`）。
   - 分析 DOM 特徵（`__NEXT_DATA__`、WordPress / Drupal 產生器標籤、`.php` 端點）。
2. **主流伺服器與後端重大 CVE 漏洞比對**:
   - 內建精準語意版本比對引擎，涵蓋近期重磅漏洞：
     - **PHP**: CVE-2024-4577 (PHP-CGI RCE)、CVE-2024-8926、CVE-2024-8927、CVE-2023-3824 (Phar RCE)、PHP EOL。
     - **Node.js**: CVE-2024-27980 (HTTP/2 DoS)、CVE-2024-21892 (Windows 代碼執行)、CVE-2024-22019、Node EOL。
     - **Apache**: CVE-2024-38472 (mod_rewrite SSRF/執行)、CVE-2023-25690 (請求走私)、CVE-2021-41773 (目錄穿越 RCE)。
     - **Nginx**: CVE-2024-7347 (MP4 模組緩衝區下溢 DoS)、CVE-2021-23017 (DNS 解析器 1-byte 溢位)。
     - **Microsoft IIS**: CVE-2022-21907 (http.sys 內核 RCE)。
     - **Apache Tomcat**: CVE-2024-23672 (WebSocket DoS)、CVE-2020-1938 (Ghostcat AJP 檔案讀取/RCE)。
3. **資訊洩漏與防禦標頭審查**:
   - 檢測 `X-Powered-By` 標頭洩漏（PHP / Express / Next.js）。
   - 檢測 `Server` 標頭版本詳細度（Nginx / Apache 是否關閉版本展示）。
   - 檢查 `Strict-Transport-Security` (HSTS)、`Content-Security-Policy` (CSP)、`X-Content-Type-Options`、`X-Frame-Options` 是否已配置。
4. **視覺化狀態警示**:
   - 🚨 **紅色圖示 / "!" Badge**：偵測到存在重大 CVE 高危漏洞或 EOL 風險。
   - ⚠️ **黃色圖示 / "▲" Badge**：伺服器暴露精確版本標頭或缺少關鍵安全防禦標頭。
   - 🛡️ **綠色圖示**：伺服器防禦良好，未發現已知漏洞與版本洩漏。
   - ⚪ **灰色圖示**：未在此網站偵測到已知後端特徵。
5. **快速行動工具**:
   - **手動檢測任意 URL**: 支援在 Popup 輸入任意網址，快速發送探測請求進行標頭與漏洞分析。
   - **一鍵複製 Markdown 檢測報告**: 點擊「複製安全審查報告」，可直接將包含漏洞詳情、CVSS 與修復建議的專業報告貼至資安工單、Slack 或 GitHub Issue。

---

## 📦 安裝步驟 (Installation)

支援 Chrome、Edge、Brave 等所有基於 Chromium 的瀏覽器：

1.  **開啟擴充功能管理頁面**:
    *   Chrome: 網址列輸入 `chrome://extensions/` 並按 Enter。
    *   Edge: 網址列輸入 `edge://extensions/` 並按 Enter。
2.  **開啟開發者模式**:
    *   在頁面右上角切換開啟「**開發者模式** (Developer mode)」。
3.  **載入擴充功能**:
    *   點擊「**載入未封裝項目** (Load unpacked)」。
    *   選擇本專案目錄（選擇專案根目錄或 `src` 資料夾皆可）。
4.  **安裝完成**:
    *   擴充功能將出現在瀏覽器工具列中。
    *   造訪任意網站，即可自動分析並點擊圖示查看安全報告。

---

## 🧪 本地單元測試驗證

本專案提供自動化測試腳本，驗證所有伺服器與後端的指紋解析、版本比對與 CVE 規則：

```bash
node test_audit.js
```

---

## 🔒 資安與合規性說明

*   本工具採用**完全被動的標頭分析與指紋審查 (Passive Security Assessment)**。
*   **絕不向目標網站發送任何惡意攻擊載荷 (No Exploit Payloads)**，確保遵守網路資安規範與服務條款，適合日常安全審查與網站自我健檢。
