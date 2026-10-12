# Baseline — checkpoint 1

1. **Identity theo từng run:** Chưa có `agent_id`, `run_id` hay danh tính người dùng đi vào luồng baseline: `_naive_loop()` chỉ nhận `message` và `llm` (`agent/loop.py:27`), còn nhánh fallback gọi nó mà không truyền `principal_id` (`agent/loop.py:67-74`). Vì vậy baseline không có ngữ cảnh danh tính để kiểm quyền cho từng lần chạy.

2. **Quyết định gửi:** Trước `http_post` không có policy kiểm mục đích, quyền hoặc loại dữ liệu; `_naive_loop()` lấy chỉ thị do mock nhận ra từ toàn văn ticket rồi trực tiếp gọi `read_customer()` và `http_post()` (`agent/loop.py:31-44`). Chính chỉ thị nằm trong ticket, qua quyết định của LLM, thực tế quyết định việc gửi; `http_post()` chỉ kiểm scheme/host/port localhost (`agent/tools.py:68-84`), không kiểm body hay quyền truy cập.

3. **Body và bằng chứng ở sink:** Body POST được tạo tại `agent/loop.py:44` dưới dạng `{"records": collected}` từ các hồ sơ vừa đọc. Sink ghi mỗi body nhận được vào `reports/sink.log` qua `LOG_PATH` và handler (`sink/sink.py:36-47`); bản bằng chứng cần giữ trước containment là `reports/attack-before.log` sao chép từ file này.

Nói cách khác, ticket vốn là dữ liệu không tin cậy nhưng baseline lại xử lý chỉ thị bên trong như lệnh và gọi thẳng `read_customer()`/`http_post()` mà không có cổng kiểm quyền.
