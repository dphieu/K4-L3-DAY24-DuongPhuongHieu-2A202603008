# Secret giả trong lịch sử Git — checkpoint 4

- **Scanner và phiên bản:** Gitleaks `8.30.1`, chạy với `.gitleaks.toml` và
  `--redact`; không in giá trị token.
- **Commit chứa token giả:** `1bdd849922156c868a5ee9293d68f5b72e242d2c`
  (short SHA `1bdd849`). Đây là fixture synthetic, vô hiệu của bài lab, không
  phải credential thật.
- **File, rule và kết quả quét lịch sử:** `lab-fake-secret.txt:1`, rule
  `lab24-synthetic-token`. Lệnh
  `gitleaks git --config .gitleaks.toml --redact --verbose .` quét 4 commit,
  tìm đúng 1 finding và trả exit code `1` như dự kiến.
- **Kết quả quét file hiện tại:**
  `gitleaks dir --config .gitleaks.toml --redact .` không tìm thấy finding và
  trả exit code `0`. Lần quét đầu không báo thư viện trong `.venv`, nên không
  cần và không thêm allowlist nào.
- **Nếu đây là credential thật:** thu hồi/rotate ngay tại dịch vụ phát hành,
  rà soát audit log và phạm vi sử dụng sai, cập nhật nơi đang dùng credential,
  rồi xử lý các bản sao/cache/fork và cân nhắc làm sạch lịch sử theo quy trình
  phối hợp của nhóm. Không thử dùng token để xác minh.
- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:** bản cũ vẫn
  đọc được từ lịch sử Git, còn credential đã lộ vẫn có hiệu lực cho tới khi
  dịch vụ cấp token thu hồi/rotate nó. Lock dependency và pin hook giúp giảm
  rủi ro supply chain/lệch phiên bản, nhưng không thể vô hiệu một secret đã lộ.
