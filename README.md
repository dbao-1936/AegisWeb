# AegisWeb v1.2 - Web Security Scanner & Subdomain Intelligence

Ứng dụng Python All-in-One chạy Web UI cục bộ (Local Web App) phục vụ **quét, đánh giá độ an toàn của website (Defensive Security Audit)**, **thu thập & kiểm tra Subdomain thụ động (Subdomain Intelligence)** và **tự động đề xuất các module Metasploit tương ứng** để đội ngũ kiểm thử bảo mật (Pentester / SecOps) có căn cứ xác minh an toàn một cách có kiểm soát.

> [!NOTE]
> **Triết lý thiết kế an toàn:** Ứng dụng tập trung vào các kỹ thuật quét an toàn (non-destructive passive & safe reconnaissance), không phát động tấn công hay khai thác tự động. Hệ thống đề xuất các module `auxiliary/scanner`, `gather` của Metasploit cùng câu lệnh `msfconsole` chuẩn hóa để chuyên gia kiểm thử thủ công khi có thẩm quyền.

---

## 1. Kiến trúc hệ thống (System Architecture)

```
Scanning_App/
│
├── backend/                         # Backend Python (FastAPI + Asynchronous Engine)
│   ├── models.py                    # Khung Pydantic Models (Findings, Metasploit, SSL, Tech, Diff)
│   ├── main.py                      # FastAPI App, REST APIs (/api/scan, /api/recon, /api/history)
│   ├── database.py                  # Lưu trữ SQLite & Công cụ so sánh biến động (Change Tracking Diff)
│   │
│   └── scanner/                     # Bộ khung các module quét an toàn
│       ├── engine.py                # Bộ điều phối quét đa luồng (Async Coordinator)
│       ├── headers.py               # Phân tích HTTP Security Headers & Cookie Flags
│       ├── ssl_checker.py           # Thẩm định chứng chỉ SSL/TLS, ngày hết hạn & giao thức
│       ├── tech_detector.py         # Nhận diện Server, CMS, Framework, DevOps (Jenkins, Grafana, Kibana)
│       ├── recon.py                 # Thăm dò an toàn (robots.txt, .git detached HEAD, .env rộng)
│       ├── passive_audit.py         # Kiểm tra CORS, HTTP OPTIONS, Mixed Content & SRI
│       ├── subdomain_recon.py       # Thu thập Subdomain (crt.sh), Takeover check, Wildcard DNS, Email Security
│       └── metasploit_db.py         # Cơ sở tri thức đề xuất module Metasploit theo bối cảnh
│
├── frontend/                        # Giao diện Web Cyber Dashboard (HTML5 + TailwindCSS)
│   ├── index.html                   # Giao diện trực quan Dashboard (Dark Mode Cyber)
│   ├── app.js                       # Logic tương tác chính, Chart.js, bộ lọc & sao chép lệnh an toàn
│   └── recon.js                     # Bảng điều khiển Subdomain, Scope Gate, Takeover, DNS & Batch Scan
│
├── data/                            # Thư mục cơ sở dữ liệu SQLite
│   └── aegisweb.db                  # CSDL lưu trữ lịch sử quét và kết quả recon bền vững
│
├── run.py                           # File chạy chính (Tự sửa lỗi môi trường & tự mở trình duyệt)
├── run.bat                          # File kích hoạt 1-click cho Windows
└── requirements.txt                 # Danh sách thư viện Python cần thiết (fastapi, uvicorn, httpx, dnspython, aiohttp)
```

---

## 2. Các tính năng cốt lõi mới trong v1.2

### A. Subdomain Intelligence & Scope Gate (Kiểm tra Subdomain thụ động)
1. **Scope Gate xác nhận quyền kiểm thử & Audit Log**: Bắt buộc người dùng tích chọn và xác nhận tên domain mục tiêu trước khi chạy recon. Hệ thống ghi nhận vào nhật ký kiểm toán `consent_logs` kèm IP, User-Agent và timestamp. *Lưu ý quan trọng: Đây là cơ chế ghi nhận cam kết trách nhiệm kiểm toán (acknowledgement audit log), không thay thế cho hợp đồng ủy quyền hoặc văn bản phê duyệt phạm vi kiểm thử chính thức.*
2. **Thu thập thụ động qua Certificate Transparency (crt.sh)**: Không gửi gói tin quét nào đến máy chủ mục tiêu.
3. **Phát hiện Wildcard DNS**: Tự động gửi probe nhãn ngẫu nhiên để xác định domain có bật Wildcard DNS không, tự động gắn cờ và loại trừ các subdomain có IP trùng Wildcard để chống nhiễu (anti-false positive).
4. **Phát hiện Subdomain Takeover (13 nhà cung cấp dịch vụ)**: So sánh bản ghi CNAME và chữ ký lỗi HTTP đặc trưng của GitHub Pages, Amazon S3, CloudFront, Heroku, Netlify, Vercel, Fastly, Shopify, Azure, Ghost, Tumblr, Zendesk, HubSpot. Chế độ chỉ đọc kiểm tra, không khai thác.
5. **Kiểm tra an toàn cấu hình DNS & Email**:
   - **SPF**: Phát hiện thiếu SPF, SPF `+all` (nguy cơ mạo danh cao), SPF `?all`.
   - **DMARC**: Phát hiện thiếu DMARC, chính sách yếu `p=none` (không thực thi ngăn chặn spoofing).
   - **CAA**: Kiểm tra bản ghi giới hạn Certificate Authority được cấp chứng chỉ cho tên miền.
   - **DNSSEC**: Kiểm tra cờ xác thực Authentic Data (AD) chống giả mạo DNS Cache Poisoning.
6. **Quét hàng loạt có kiểm soát tốc độ (Rate-limited Batch Scan)**:
   - Cho phép chọn nhiều subdomain đang hoạt động từ danh sách.
   - Thực thi với độ trễ an toàn giữa các request và thanh tiến trình trực quan, chống nghẽn mạng và chống bị chặn IP.

### B. Theo dõi biến động theo thời gian (Change Tracking & Diff over SQLite)
- Dữ liệu lịch sử quét web và recon subdomain được lưu trữ bền vững vào cơ sở dữ liệu SQLite cục bộ (`data/aegisweb.db`), không bị mất khi tắt máy chủ.
- **Tự động đối chiếu (Diff Engine)**: Khi quét lại một mục tiêu đã từng kiểm tra trước đây, hệ thống tự động tính toán:
  - Biến động điểm số (`score_delta`: tăng/giảm bao nhiêu điểm).
  - Lỗ hổng mới phát sinh (`new_findings`).
  - Lỗ hổng đã được khắc phục (`resolved_findings`).
  - Thay đổi cấu hình Security Headers (tiêu đề vừa được thêm hoặc vừa bị gỡ).
  - Biến động subdomain (subdomain mới xuất hiện, subdomain đã gỡ, nguy cơ takeover mới).

### C. Nhận diện hạ tầng DevOps & Giám sát (Jenkins, Grafana, Kibana)
- Bổ sung nhận diện dịch vụ đặc thù: **Jenkins CI/CD**, **Grafana Dashboard**, **Kibana Log Analytics**.
- Đề xuất module Metasploit Auxiliary chuẩn xác tương ứng:
  - Jenkins: `auxiliary/scanner/http/jenkins_enum`
  - Grafana: `auxiliary/scanner/http/grafana_cve_2021_43798` (kiểm tra Directory Traversal)
  - Kibana: `auxiliary/scanner/http/kibana_cve_2019_7609` (kiểm tra Prototype Pollution)

---

## 3. Hướng dẫn khởi chạy

### Cách 1: Chạy 1-Click (Khuyến nghị trên Windows)
Nhấp đúp chuột vào tệp:
```text
run.bat
```

### Cách 2: Chạy dòng lệnh
```powershell
python run.py
```

Truy cập giao diện Web: 👉 **`http://127.0.0.1:8000`**

---

## 4. Lưu ý bảo mật & quyền riêng tư

- **DNSSEC:** Bước kiểm tra DNSSEC gửi truy vấn tới các resolver công cộng `1.1.1.1` và `8.8.8.8` (kèm fallback bản ghi DS). Tên miền được tra cứu sẽ hiển thị với các nhà cung cấp resolver này; không dùng resolver nội bộ.
- **Chứng chỉ TLS của mục tiêu không được xác thực (theo thiết kế):** scanner chấp nhận cả chứng chỉ self-signed/không hợp lệ để vẫn thu thập được headers và nội dung phục vụ đánh giá (`httpx` dùng `verify=False`, `aiohttp` dùng `ssl=False`). Kết quả chỉ dùng cho mục đích audit, không dùng để xác nhận độ tin cậy của kênh truyền.
