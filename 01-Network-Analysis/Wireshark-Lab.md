# Phân Tích Giao Thức Mạng & Lưu Lượng Baseline (Wireshark)

* **Đối tượng phân tích:** Lưu lượng HTTP/DNS từ truy vấn web thực tế
* **Môi trường:** Windows 10, Wireshark, CLI (`curl`)
* **Thời gian thực hiện:** Tháng 09/2026
* **Phân tích viên:** Ngô Trấn Vũ

---

## 1. Tóm tắt sự việc (Executive Summary)
Bài lab thực hiện giám sát, bắt gói tin và phân tích toàn bộ vòng đời của một phiên kết nối mạng thông thường khi client truy cập dịch vụ web qua giao thức không mã hóa (HTTP). 

Mục tiêu chính:
* Bóc tách tiến trình phân giải tên miền qua DNS (IPv4 song song IPv6).
* Kiểm chứng cơ chế bắt tay 3 bước của giao thức TCP (3-Way Handshake).
* Đánh giá rủi ro an toàn thông tin khi dữ liệu và header HTTP được truyền tải dạng văn bản rõ (cleartext).

---

## 2. Phương pháp luận & Bộ lọc sử dụng (Filters)
Các bộ lọc hiển thị (Display Filters) được áp dụng trên Wireshark để cô lập luồng dữ liệu cần điều tra:
* `dns`: Lọc toàn bộ các gói tin truy vấn và phản hồi phân giải tên miền.
* `tcp.port == 80`: Lọc lưu lượng TCP liên quan đến cổng dịch vụ web HTTP tiêu chuẩn.
* `http`: Lọc riêng các bản tin tầng ứng dụng HTTP (Request/Response).

---

## 3. Quá trình phân tích chi tiết (Detailed Investigation)

### Bước 1: Phân giải tên miền (DNS Resolution)
* **Thao tác kích hoạt:** Xóa cache DNS cục bộ bằng lệnh `ipconfig /flushdns` và gửi yêu cầu tới `example.com`.
* **Bộ lọc:** `dns`
<img width="1724" height="236" alt="image" src="https://github.com/user-attachments/assets/db529af3-9096-4620-8c6f-486e490b71fd" />
* **Hiện tượng & Phân tích:**
  * Client (`fd00:db80::1527:...`) gửi 2 truy vấn song song đến Local DNS Server (`fd00:db80::1`):
    * Record Type `A` (yêu cầu địa chỉ IPv4).
    * Record Type `AAAA` (yêu cầu địa chỉ IPv6).
  * Server phản hồi bản ghi AAAA chứa địa chỉ IPv6: `2606:4700:10::ac42:93f3` (hạ tầng CDN Cloudflare). 
  * Do hệ thống ưu tiên kết nối IPv6 (Dual-Stack), toàn bộ phiên truyền tải sau đó tự động định tuyến qua IPv6.

---

### Bước 2: Thiết lập kết nối (TCP 3-Way Handshake)
* **Bộ lọc:** `tcp.port == 80`
<img width="1504" height="362" alt="image" src="https://github.com/user-attachments/assets/e892a4f4-f552-4fba-978f-127a7a673400" />
* **Hiện tượng & Phân tích:**
  *Quá trình bắt tay 3 bước diễn ra tin cậy giữa Client (port ngẫu nhiên `62437`) và Server (port `80`):
  *1. **Packet #19 [SYN]:** Client gửi cờ `SYN`, khởi tạo phiên và thống nhất số thứ tự tuần tự ban đầu (`Seq = 0`).
  *2. **Packet #20 [SYN, ACK]:** Server chấp thuận kết nối, gửi lại cờ `SYN-ACK`, xác nhận Sequence number tiếp theo (`Ack = 1`).
  *3. **Packet #21 [ACK]:** Client gửi gói `ACK` chốt hoàn tất bắt tay. Kênh truyền TCP hai chiều được thiết lập thành công.

---

### Bước 3: Kiểm tra dữ liệu HTTP (HTTP Inspection)
* **Bộ lọc:** `http`
<img width="1920" height="1010" alt="image" src="https://github.com/user-attachments/assets/fbe17e81-29a8-4f2b-b04e-c90a91ee472c" />

* **Hiện tượng & Phân tích:**
  * **Packet #22 (HTTP Request):** Client gửi yêu cầu `HEAD / HTTP/1.1` để lấy thông tin header mà không cần tải nội dung trang (payload tối giản).
  * **Packet #24 (HTTP Response):** Server trả về mã phản hồi `HTTP/1.1 200 OK`.
  * **Các trường thông tin thu thập được dạng Cleartext:**
    * `Status Code:` 200 OK
    * `Server:` cloudflare
    * `Content-Type:` text/html
    * `CF-RAY:` a4030c263a8485c7-HKG

---

## 4. Đánh giá rủi ro & Khuyến nghị phòng thủ (Security Recommendations)

### Rủi ro an ninh mạng (Findings):
1. **Lộ lọt thông tin nhận diện hệ thống (Fingerprinting):** Do HTTP chạy không mã hóa, trường `Server: cloudflare` và các định danh proxy bị lộ hoàn toàn, giúp kẻ tấn công dễ dàng lập bản đồ công nghệ của mục tiêu.
2. **Nguy cơ nghe lén & can thiệp (MitM Risk):** Toàn bộ dữ liệu truyền qua cổng 80 không có cơ chế xác thực danh tính server lẫn tính toàn vẹn dữ liệu, mở đường cho các cuộc tấn công giả mạo hoặc chèn mã độc vào gói tin.

### Khuyến nghị phòng thủ (Remediation):
* **Bắt buộc dùng HTTPS:** Chuyển toàn bộ dịch vụ web sang chạy giao thức HTTPS (TLS 1.3) trên port 443.
* **Cấu hình HSTS (HTTP Strict Transport Security):** Bật header `Strict-Transport-Security` để buộc trình duyệt luôn sử dụng kết nối mã hóa, loại bỏ hoàn toàn nguy cơ tấn công hạ cấp giao thức (SSL Stripping).
