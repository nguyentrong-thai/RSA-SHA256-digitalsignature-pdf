# Hệ thống Ký số PDF — PAdES / RSA-PSS + SHA-256

Web app ký số PDF chuẩn PAdES/ISO 32000-1, chuyển đổi từ Tkinter Desktop App sang Flask Web App.

## Chức năng

- **Tạo chứng thư**: Sinh cặp khóa RSA (2048/4096-bit) và chứng thư X.509 tự ký
- **Ký PDF**: Nhúng chữ ký PAdES theo cơ chế Byte-Range, có thể hiển thị khung trực quan
- **Xác thực**: Kiểm tra tính toàn vẹn và hợp lệ của chữ ký RSA-PSS

## Chạy local

```bash
pip install -r requirements.txt
python app.py
```

Mở trình duyệt: http://localhost:5000

## Deploy lên Render (miễn phí)

1. Push code lên GitHub
2. Vào https://render.com → New Web Service
3. Kết nối repo GitHub
4. Cấu hình:
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
5. Deploy → nhận link `https://ten-project.onrender.com`

## Cấu trúc project

```
pdf_signer/
├── app.py              # Flask Web Server
├── signer.py           # Logic ký số (RSA + SHA256 + pyHanko)
├── requirements.txt
├── Procfile            # Cấu hình Gunicorn cho Render
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── keygen.html
│   ├── sign.html
│   └── verify.html
├── uploads/            # File upload tạm thời
├── signed/             # PDF đã ký
└── certs/              # Khóa và chứng thư sinh ra
```

## Công nghệ

| Thành phần | Thư viện |
|---|---|
| Backend | Flask + Gunicorn |
| Ký số PDF | pyHanko (PAdES Byte-Range) |
| Mật mã | cryptography (RSA-PSS + SHA-256) |
| Visual stamp | reportlab + pypdf |
| Chứng thư | X.509 v3 Self-Signed |
