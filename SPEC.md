# 伺服器與後端漏洞安全檢測器 (Web Server & Backend Security Auditor) - 規格書

本擴充功能（Chrome Extension Manifest V3）旨在協助資安工程師、網站維運者與使用者，在瀏覽網頁時即時檢測目標網站的**伺服器與後端技術棧（PHP、Node.js / Express / Next.js、Apache、Nginx、IIS、Tomcat）**，自動辨識暴露的版本標頭，並精準比對近期重大 CVE 漏洞與生命週期終止 (EOL) 狀況，提供防禦修復建議。

---

## 核心設計原則

1. **被動式檢測 (Passive Auditing)**：
   - 透過瀏覽器網路回應標頭 (`webRequest.onHeadersReceived`)、Cookie 標記與 DOM 特徵進行指紋識別。
   - **絕不向目標網站發送任何攻擊載荷 (No Exploit Payloads)**，確保檢測過程合規、安全、不干擾線上服務運作。
2. **多架構全方位檢測**：
   - 同時支援常見 Web 伺服器 (Apache, Nginx, IIS) 與後端應用執行環境 (PHP, Node.js / Express / Next.js, Tomcat / Java)。
3. **明確修復與防禦指引**：
   - 提供各漏洞與資訊洩漏項目的處置步驟（包含配置設定檔指令、版本升級建議與反向代理規則）。

---

## 支援檢測之伺服器與後端重大 CVE 資料庫

### 1. PHP 漏洞
| 漏洞編號 | CVSS / 等級 | 影響版本範圍 | 漏洞摘要與危害 | 修復版本 |
| :--- | :--- | :--- | :--- | :--- |
| **CVE-2024-4577** | **9.8 (CRITICAL)** | 8.3 < 8.3.8<br>8.2 < 8.2.20<br>8.1 < 8.1.29<br>PHP <= 8.0 (所有舊版) | **PHP-CGI 參數注入遠端程式碼執行 (RCE)**<br>Windows 環境下因 Best-Fit 字元轉碼漏洞，攻擊者可藉由 `%ad` 繞過引數保護，向 PHP-CGI 注入指令執行任意代碼。 | 8.3.8+<br>8.2.20+<br>8.1.29+ |
| **CVE-2024-8926** | **7.5 (HIGH)** | 8.3 < 8.3.12<br>8.2 < 8.2.24<br>8.1 < 8.1.30 | **PHP-CGI 查詢字串解析邊界引數注入** | 8.3.12+<br>8.2.24+<br>8.1.30+ |
| **CVE-2024-8927** | **7.5 (HIGH)** | 8.3 < 8.3.12<br>8.2 < 8.2.24<br>8.1 < 8.1.30 | **Multipart 請求解析緩衝區溢位讀取 (DoS / 記憶體洩漏)** | 8.3.12+<br>8.2.24+<br>8.1.30+ |
| **CVE-2024-2756** | **7.5 (HIGH)** | 8.3 < 8.3.6<br>8.2 < 8.2.18<br>8.1 < 8.1.28 | **Windows proc_open 引數跳脫繞過命令注入** | 8.3.6+<br>8.2.18+<br>8.1.28+ |
| **CVE-2023-3824** | **9.8 (CRITICAL)** | 8.2 < 8.2.8<br>8.1 < 8.1.22<br>8.0 < 8.0.30<br>7.x 全部 | **Phar 檔案解析記憶體緩衝區溢位 (RCE)** | 8.2.8+<br>8.1.22+<br>8.0.30+ |
| **PHP-EOL** | **7.5 (HIGH)** | PHP <= 8.1 (含 5.x, 7.x, 8.0, 8.1) | **PHP 官方生命週期終止**（PHP 8.1 安全支援於 2024-11-25 截止） | 遷移至 8.2+ / 8.3+ |

### 2. Node.js / Express / Next.js 漏洞
| 漏洞編號 | CVSS / 等級 | 影響版本範圍 | 漏洞摘要與危害 | 修復版本 |
| :--- | :--- | :--- | :--- | :--- |
| **CVE-2024-27980** | **7.5 (HIGH)** | 18 < 18.20.2<br>20 < 20.12.2<br>21 < 21.7.2 | **Node.js HTTP/2 連續空資料幀 DoS 攻擊漏洞**<br>攻擊者可發送連續空資料封包，導致事件迴圈進入無效迴圈，造成 CPU 100% 耗盡與服務中斷。 | 18.20.2+<br>20.12.2+<br>21.7.2+ |
| **CVE-2024-21892** | **8.3 (HIGH)** | 18 < 18.20.0<br>20 < 20.11.1<br>21 < 21.6.2 | **Windows OpenSSL 模組目錄搜尋代碼執行**<br>載入路徑缺陷可能導致加載未授權動態連結庫引發任意程式碼執行。 | 18.20.0+<br>20.11.1+<br>21.6.2+ |
| **CVE-2024-22019** | **7.5 (HIGH)** | 18 < 18.19.1<br>20 < 20.11.1 | **http_parser 分塊傳輸擴充套件記憶體耗盡 (DoS)** | 18.19.1+<br>20.11.1+ |
| **NODE-EOL** | **7.5 (HIGH)** | Node.js <= 16 (含 16.x, 14.x, 12.x) | **Node.js 官方生命週期終止**（Node 16 於 2023-09 截止） | 遷移至 20 LTS 或 22 LTS |

### 3. Apache HTTP Server 漏洞
| 漏洞編號 | CVSS / 等級 | 影響版本範圍 | 漏洞摘要與危害 | 修復版本 |
| :--- | :--- | :--- | :--- | :--- |
| **CVE-2024-38472** | **8.2 (HIGH)** | Apache < 2.4.60 | **mod_rewrite 混淆編碼與 SSRF / 指令執行缺陷**<br>未正確防護 Windows UNC 或反向代理路徑，可造成內部 SSRF 或非預期腳本執行。 | Apache 2.4.60+ |
| **CVE-2023-25690** | **9.8 (CRITICAL)** | 2.4.0 至 2.4.55 (< 2.4.56) | **Apache HTTP Request Smuggling 請求走私漏洞 (mod_proxy)**<br>反向代理配置下，CRLF 格式缺陷可被用於走私請求並繞過存取控制或竊取他人會話。 | Apache 2.4.56+ |
| **CVE-2021-41773** | **9.8 (CRITICAL)** | Apache 2.4.49, 2.4.50 | **Apache 目錄穿越與遠端程式碼執行 (Path Traversal / RCE)**<br>雙重編碼 `.%2e` 穿越目錄，若啟用 cgi-bin 可直接執行系統命令。 | Apache 2.4.51+ |

### 4. Nginx 漏洞
| 漏洞編號 | CVSS / 等級 | 影響版本範圍 | 漏洞摘要與危害 | 修復版本 |
| :--- | :--- | :--- | :--- | :--- |
| **CVE-2024-7347** | **7.5 (HIGH)** | 1.5.13 - 1.27.0 (< 1.27.1 / < 1.26.2) | **ngx_http_mp4_module 緩衝區下溢與 Worker 崩潰 (DoS)** | 1.27.1+ / 1.26.2+ |
| **CVE-2021-23017** | **8.1 (HIGH)** | 0.6.18 至 1.20.0 | **內建 DNS 解析器 1-byte 記憶體覆寫缺陷**<br>偽造 DNS 回應可造成行程終止或潛在代碼執行。 | 1.20.1+ / 1.21.0+ |

### 5. Microsoft IIS 漏洞
| 漏洞編號 | CVSS / 等級 | 影響版本範圍 | 漏洞摘要與危害 | 修復版本 |
| :--- | :--- | :--- | :--- | :--- |
| **CVE-2022-21907** | **9.8 (CRITICAL)** | IIS 10.0 (Windows Server 2022/2019/Win10) | **Windows 核心 HTTP 堆疊 (http.sys) 遠端程式碼執行漏洞**<br>惡意 Accept-Encoding 標頭觸發內核級 RCE，具蠕蟲化傳播風險。 | KB5009557 累積更新 |

### 6. Apache Tomcat 漏洞
| 漏洞編號 | CVSS / 等級 | 影響版本範圍 | 漏洞摘要與危害 | 修復版本 |
| :--- | :--- | :--- | :--- | :--- |
| **CVE-2024-23672** | **7.5 (HIGH)** | Tomcat 11 < 11.0.0-M17<br>10.1 < 10.1.19<br>9.0 < 9.0.86 | **WebSocket 連線握手資源洩漏與 DoS** | 11.0.0-M17+<br>10.1.19+<br>9.0.86+ |
| **CVE-2020-1938** | **9.8 (CRITICAL)** | 9.0.0.M1 - 9.0.30<br>8.5.0 - 8.5.50<br>7.x 全部 | **Ghostcat AJP 協定任意檔案讀取與 RCE**<br>預設開放 8009 AJP 缺陷，攻擊者可讀取 webapp 任意源碼並結合檔案上傳實現 RCE。 | 9.0.31+<br>8.5.51+<br>7.0.100+ |

---

## 防禦標頭與資訊洩漏審查

1. **`X-Powered-By` 洩漏**：
   - 檢查是否回傳 `PHP`、`Express`、`Next.js` 等框架資訊。
   - 修復：Express 執行 `app.disable('x-powered-by')`；PHP 設定 `expose_php = Off`。
2. **`Server` 標頭版本詳細度**：
   - 檢查是否暴露精確版本號（如 `nginx/1.24.0` 或 `Apache/2.4.52`）。
   - 修復：Nginx 設定 `server_tokens off;`；Apache 設定 `ServerTokens Prod`。
3. **`Strict-Transport-Security` (HSTS)**：強制 HTTPS 連線防護。
4. **`Content-Security-Policy` (CSP)**：防禦 XSS 與未授權腳本注入。
5. **`X-Content-Type-Options: nosniff`**：防禦 MIME 類型嗅探攻擊。
6. **`X-Frame-Options`**：防禦點擊劫持 (Clickjacking)。

---

## 模組架構

```
src/
├── cve_database.js     # 多伺服器與後端 CVE 漏洞知識庫、語意版本解析器與審查引擎
├── service_worker.js   # 監聽 HTTP 回應標頭 (webRequest.onHeadersReceived) 與分頁狀態管理
├── content.js          # DOM 指紋（Next.js / Nuxt / WordPress）與 Session Cookie 擷取
├── popup.html / .js    # 多架構技術棧標籤、CVE 漏洞卡片、防禦標頭檢驗與 Markdown 報告
└── manifest.json       # Manifest V3 設定 (webRequest, storage, activeTab, <all_urls>)
```
