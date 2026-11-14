[README.md](https://github.com/user-attachments/files/34850436/README.md)
# AegisWeb v1.2 - Công cụ quét bảo mật web và thu thập subdomain

AegisWeb là ứng dụng Python chạy cục bộ (Web UI trên `http://127.0.0.1:8000`), dùng để **kiểm tra cấu hình bảo mật của website** (defensive security audit), **thu thập và kiểm tra subdomain theo cách thụ động**, và **gợi ý module Metasploit tương ứng** để chuyên gia kiểm thử xác minh thủ công.

> [!WARNING]
> **Chỉ quét hệ thống mà bạn có quyền kiểm thử bằng văn bản** (hợp đồng, phạm vi kiểm thử, hoặc chính hệ thống của bạn). Việc quét hệ thống không được cho phép có thể vi phạm pháp luật. Tác giả không chịu trách nhiệm cho việc sử dụng sai mục đích.

---

## 1. Công cụ này làm gì và không làm gì

**Làm:**
- Kiểm tra HTTP Security Headers, cờ bảo mật của Cookie, cấu hình TLS/SSL (ngày hết hạn, giao thức).
- Nhận diện công nghệ (Server, CMS, framework, công cụ DevOps như Jenkins, Grafana, Tomcat).
- Kiểm tra một số file và đường dẫn công khai an toàn: `robots.txt`, `sitemap.xml`, `.well-known/security.txt`, `.git/HEAD`, `.env` (nội dung `.env` chỉ hiển thị dạng đã che giá trị).
- Kiểm tra CORS, phương thức HTTP OPTIONS, Mixed Content, SRI.
- Thu thập subdomain qua Certificate Transparency (crt.sh), kiểm tra wildcard DNS, nguy cơ subdomain takeover, cấu hình DNS/email (SPF, DMARC, CAA, DNSSEC).
- Đề xuất lệnh Metasploit dạng **chỉ để sao chép** (copy-only), không tự chạy.
- Lưu lịch sử quét vào SQLite và so sánh thay đổi giữa các lần quét.

**Không làm:**
- Không gửi payload tấn công, không khai thác lỗ hổng, không thử đăng nhập, không brute-force đường dẫn hay mật khẩu.
- Không tự thực thi module Metasploit. Các module được đề xuất đều cần người dùng tự chạy trong `msfconsole`.
- Không tự gọi sqlmap hay công cụ tấn công khác.
- Không có cơ chế "chống bị chặn IP". Công cụ chỉ giới hạn số luồng đồng thời (xem mục 6).

---

## 2. Cấu trúc thư mục

```
Scanning_App/
├── backend/                      # FastAPI + engine bất đồng bộ
│   ├── main.py                   # App FastAPI, các API (/api/scan, /api/recon, /api/history)
│   ├── models.py                 # Pydantic models (Finding, Metasploit, SSL, Tech, Diff)
│   ├── database.py               # SQLite, lưu lịch sử và so sánh thay đổi (diff)
│   ├── normalize.py              # Chuẩn hóa tên miền/URL đầu vào (bỏ scheme, path, "www.")
│   └── scanner/
│       ├── engine.py             # Điều phối quét (async)
│       ├── headers.py            # Security Headers và cờ Cookie
│       ├── ssl_checker.py        # Chứng chỉ SSL/TLS
│       ├── tech_detector.py      # Nhận diện công nghệ và hạ tầng DevOps
│       ├── recon.py              # Kiểm tra file/đường dẫn công khai an toàn
│       ├── passive_audit.py      # CORS, OPTIONS, Mixed Content, SRI
│       ├── subdomain_recon.py    # crt.sh, takeover, wildcard DNS, DNS/email
│       └── metasploit_db.py      # Bảng gợi ý module Metasploit (copy-only)
│
├── frontend/                     # Giao diện (HTML + Tailwind CSS + JavaScript)
│   ├── index.html
│   ├── app.js                    # Quét web, biểu đồ, lọc findings, lịch sử
│   └── recon.js                  # Subdomain, Scope Gate, takeover, DNS, quét hàng loạt
│
├── data/
│   └── aegisweb.db               # CSDL SQLite (tự tạo khi chạy)
│
├── test_*.py                     # Bộ kiểm thử (unittest)
├── run.py                        # Điểm khởi chạy (kiểm tra môi trường, mở trình duyệt)
├── run.bat                       # Khởi chạy 1 chạm trên Windows
└── requirements.txt              # fastapi, uvicorn, httpx, dnspython, aiohttp, ...
```

---

## 3. Cài đặt và chạy (Windows)

Yêu cầu: **Python 3.11** (đã kiểm thử với 3.11).

Mở Command Prompt tại thư mục dự án:

```bat
cd /d C:\đường\dẫn\tới\Scanning_App
py -3.11 -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Chạy ứng dụng:

```bat
python run.py
```

Hoặc nhấp đúp `run.bat`. Sau đó mở trình duyệt tại **`http://127.0.0.1:8000`**.

Dữ liệu được lưu trong `data\aegisweb.db`. Xóa file này nếu muốn reset lịch sử.

---

## 4. Chạy kiểm thử

```bat
venv\Scripts\python.exe test_v12_full.py
```

Bộ test dùng CSDL tạm (biến môi trường `AEGISWEB_DB`) và không tạo truy vấn tới mục tiêu thật, nên an toàn để chạy lại nhiều lần.

---

## 5. Các tính năng chính

### A. Scope Gate và Thu thập subdomain
1. **Scope Gate:** bạn phải tích chọn xác nhận và nhập lại đúng tên domain trước khi chạy. Hệ thống ghi vào bảng `consent_logs` gồm IP, User-Agent và thời điểm.
   *Lưu ý: đây chỉ là nhật ký ghi nhận cam kết, không thay thế hợp đồng hay văn bản phê duyệt phạm vi kiểm thử.*
2. **Thu thập qua crt.sh:** truy vấn cơ sở dữ liệu Certificate Transparency công khai. Bước này không gửi gói tin nào tới máy chủ mục tiêu.
3. **Phát hiện Wildcard DNS:** gửi truy vấn DNS với nhãn ngẫu nhiên để xem domain có trả lời mọi subdomain không. Subdomain có IP trùng với wildcard bị gắn cờ để tránh báo sai.
4. **Subdomain takeover (13 nhà cung cấp):** kiểm tra CNAME trỏ tới dịch vụ đã bị gỡ (NXDOMAIN) và chữ ký lỗi HTTP đặc trưng của GitHub Pages, Amazon S3, CloudFront, Heroku, Netlify, Vercel, Fastly, Shopify, Azure, Ghost, Tumblr, Zendesk, HubSpot. Bước này có gửi HTTP GET tới subdomain và đọc phản hồi. Không gửi dữ liệu nào khác.
5. **Kiểm tra DNS và email:**
   - **SPF:** thiếu SPF, `+all` (rủi ro mạo danh cao), `?all`.
   - **DMARC:** thiếu DMARC hoặc `p=none` (không chặn giả mạo).
   - **DKIM:** kiểm tra có `v=DKIM1` (hoặc `k=rsa` kèm `p=`).
   - **CAA:** kiểm tra giới hạn CA được cấp chứng chỉ.
   - **DNSSEC:** kiểm tra cờ AD qua resolver `1.1.1.1` và `8.8.8.8`, có dự phòng bằng bản ghi DS.
6. **Quét hàng loạt có giới hạn:** chọn nhiều subdomain đang hoạt động để quét các kiểm tra web. Tối đa **50 mục tiêu** mỗi lần, mặc định 5 luồng song song (tối đa 10). Yêu cầu xác nhận phạm vi (`confirm_scope`) trước khi chạy.

### B. Theo dõi thay đổi
- Mỗi lần quét được lưu vào SQLite. Khi quét lại cùng một mục tiêu, hệ thống so sánh với lần quét hoàn thành gần nhất và báo:
  - Chênh lệch điểm (`score_delta`).
  - Lỗ hổng mới và lỗ hổng đã khắc phục.
  - Security Headers được thêm hoặc bị gỡ.
  - Subdomain mới, subdomain đã gỡ, nguy cơ takeover mới.
- Lần quét bị lỗi không được dùng làm mốc so sánh.

### C. Gợi ý module Metasploit (copy-only)
- Các gợi ý được hiển thị theo bối cảnh phát hiện, ví dụ:
  - Jenkins: `auxiliary/scanner/http/jenkins_enum`
  - Grafana: `auxiliary/scanner/http/grafana_plugin_traversal`
  - Tomcat: `auxiliary/scanner/http/tomcat_mgr_login` (kiểm tra theo bảng trong `metasploit_db.py`)
- Các module được đánh dấu **intrusive** bị ẩn mặc định trên giao diện.
- Giá trị được đưa vào lệnh `msfconsole` đều được kiểm tra và escape.
- *Lưu ý:* tên module được đối chiếu với mã nguồn Metasploit. Hãy chạy `search <tên>` trong `msfconsole` để xác nhận trước khi dùng.

---

## 6. Giới hạn đã biết

- **Chỉ quét theo lượng kiểm soát:** không có độ trễ giữa các request. Công cụ chỉ giới hạn số luồng đồng thời. Nếu mục tiêu nhạy cảm với tải, hãy tự giảm số luồng.
- **Thu thập subdomain:** crt.sh chỉ thấy chứng chỉ đã được ghi log công khai. Các entry wildcard (`*.example.com`) hiện bị bỏ qua khi lấy tên, nên có thể sót subdomain.
- **Phạm vi truy vấn crt.sh:** hiện truy vấn dựa trên host bạn nhập vào. Nếu nhập `www.example.com`, kết quả có thể không đủ đầy đủ so với `example.com`. Đây là lỗi đã biết và sẽ được sửa.
- **Đường dẫn file công khai:** chỉ kiểm tra một danh sách cố định, không dò thư mục ẩn.
- **Chứng chỉ TLS không được xác thực (theo thiết kế):** scanner chấp nhận chứng chỉ tự ký hoặc không hợp lệ để vẫn lấy được headers và nội dung. `httpx` dùng `verify=False`, `aiohttp` dùng `ssl=False`. Kết quả này phục vụ audit, không dùng để xác nhận kênh truyền an toàn.
- **Quyền riêng tư DNS:** bước kiểm tra DNSSEC gửi truy vấn tới `1.1.1.1` và `8.8.8.8`. Hai nhà cung cấp này sẽ thấy tên miền bạn tra cứu. Không dùng resolver nội bộ.
- **Chỉ chạy cục bộ:** giao diện chỉ lắng nghe trên `127.0.0.1`. Đây là công cụ cá nhân, không phải dịch vụ web.

---

## 7. Giấy phép

[Chưa chọn giấy phép. Điền tên giấy phép (ví dụ MIT) và thêm file `LICENSE` vào thư mục gốc.]
