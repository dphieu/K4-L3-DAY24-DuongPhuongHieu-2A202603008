# DPIA-lite — checkpoint 5

1. **Dữ liệu và phân loại:** `corpus/` chứa ticket synthetic, được coi là
   `internal` nhưng không tin cậy vì người khác có thể cài chỉ thị. Hồ sơ giả
   trong `data/customers.json` chứa tên, CCCD, SĐT, STK, email và quan hệ ticket,
   được coi là `restricted`. Ticket ID lấy từ tên file là dữ liệu typed duy nhất
   đi qua ranh giới Run A → Run B; nội dung đưa vào tóm tắt được redact trước.

2. **Mục đích và principal:** `support_l1` được tìm/tóm tắt ticket cho
   `summarize-tickets` hoặc `support-reply`, nhưng không được đọc hồ sơ riêng.
   `dpo` được đọc hồ sơ gắn với ticket cho `support-reply`; không principal nào
   được gửi dữ liệu `restricted` qua egress. `--as` chỉ chọn fixture quyền, không
   xác thực người đang dùng máy.

3. **Luồng dữ liệu và đích:** Run A xin policy trước `search_docs`, đọc ticket,
   phát hiện lure, redact PII và chỉ xuất danh sách ticket ID từ tên file. Run B
   xin quyền trước khi mở private store, map ID qua `related_tickets`, rồi xin
   quyền lần nữa trước từng `read_customer`. Nếu lure yêu cầu gửi, một lượt PEP
   riêng chỉ kiểm URL với `restricted + egress_enabled=True`; policy deny trước
   khi body được tạo hoặc `http_post` chạy. Sink thử nghiệm duy nhất là
   `http://127.0.0.1:10024/reconcile`. Ledger chỉ lưu `args_hash`, metadata OBO,
   quyết định và reason, không lưu hồ sơ thô.

4. **Bằng chứng và giới hạn:** Trước containment, `reports/attack-before.log`
   có 4 POST chứa `KH-000999`; sau containment, `reports/attack-after.log` là
   `0` byte. Toàn bộ test có `33 passed`, không skip; ledger có 71 dòng,
   `verify()` trả `True`, và dòng 71 ghi `http_post/deny` thay mặt `dpo` với
   reason. Giới hạn: LLM là mock deterministic; principal, TTL và quyền là
   fixture; regex không phải nhận diện PII toàn diện; sink/dữ liệu đều local và
   synthetic; hash chain không phát hiện cắt đuôi hoặc viết lại toàn chuỗi nếu
   thiếu mốc ngoài. Đây là mô tả học tập, không phải DPIA pháp lý chính thức.
