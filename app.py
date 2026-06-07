"""
app.py — Flask Web Server cho Hệ thống Ký số PDF PAdES
Chuyển đổi từ Tkinter Desktop App sang Web App
"""

import os
import io
import uuid
import datetime
from flask import (
    Flask, request, render_template,
    send_file, jsonify, redirect, url_for
)

# ── Import các hàm lõi từ signer.py (giữ nguyên 100% logic) ─────────────────
from signer import (
    generate_identity_and_cert,
    sign_pdf_file,
    verify_pdf_file,
    remove_vietnamese_accents,
)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB tối đa

# ── Thư mục lưu trữ tạm thời ─────────────────────────────────────────────────
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
SIGNED_DIR = os.path.join(os.path.dirname(__file__), "signed")
CERTS_DIR  = os.path.join(os.path.dirname(__file__), "certs")

for d in [UPLOAD_DIR, SIGNED_DIR, CERTS_DIR]:
    os.makedirs(d, exist_ok=True)


def _save_upload(file_obj, folder: str, prefix: str = "") -> str:
    """Lưu file upload vào folder, trả về đường dẫn tuyệt đối."""
    uid = uuid.uuid4().hex[:8]
    filename = f"{prefix}{uid}_{file_obj.filename}"
    path = os.path.join(folder, filename)
    file_obj.save(path)
    return path


# =============================================================================
# ROUTE: TRANG CHỦ
# =============================================================================

@app.route("/")
def index():
    return render_template("index.html")


# =============================================================================
# ROUTE: TẠO CHỨNG THƯ (KEYGEN)
# =============================================================================

@app.route("/keygen", methods=["GET", "POST"])
def keygen():
    if request.method == "GET":
        return render_template("keygen.html")

    # ── Nhận dữ liệu form ────────────────────────────────────────────────────
    common_name  = request.form.get("common_name",  "Nguyen Van A").strip()
    organization = request.form.get("organization", "Cong ty ABC").strip()
    country      = request.form.get("country",      "VN").strip()
    valid_days   = int(request.form.get("valid_days", "730"))
    key_size     = int(request.form.get("key_size",   "2048"))
    passphrase   = request.form.get("passphrase",   "").strip()

    # ── Tạo thư mục riêng cho lần sinh khóa này ──────────────────────────────
    session_id = uuid.uuid4().hex[:8]
    save_dir   = os.path.join(CERTS_DIR, session_id)
    os.makedirs(save_dir, exist_ok=True)

    try:
        priv_path, cert_path = generate_identity_and_cert(
            key_size=key_size,
            common_name=common_name,
            organization=organization,
            country=country,
            valid_days=valid_days,
            passphrase=passphrase,
            save_dir=save_dir,
        )
        return jsonify({
            "success": True,
            "session_id": session_id,
            "message": f"Đã tạo khóa RSA-{key_size} và chứng thư X.509 thành công!",
            "cn": remove_vietnamese_accents(common_name),
            "org": remove_vietnamese_accents(organization),
            "country": country[:2].upper(),
            "valid_days": valid_days,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/keygen/download/<session_id>/<file_type>")
def keygen_download(session_id, file_type):
    """Tải về private key hoặc certificate sau khi sinh."""
    # Bảo vệ path traversal
    if ".." in session_id or "/" in session_id:
        return "Invalid session", 400

    if file_type == "key":
        path = os.path.join(CERTS_DIR, session_id, "private_key.pem")
        download_name = "private_key.pem"
        mimetype = "application/x-pem-file"
    elif file_type == "cert":
        path = os.path.join(CERTS_DIR, session_id, "certificate.crt")
        download_name = "certificate.crt"
        mimetype = "application/x-x509-ca-cert"
    else:
        return "Not found", 404

    if not os.path.exists(path):
        return "File không tồn tại hoặc đã hết hạn", 404

    return send_file(path, as_attachment=True, download_name=download_name, mimetype=mimetype)


# =============================================================================
# ROUTE: KÝ PDF
# =============================================================================

@app.route("/sign", methods=["GET", "POST"])
def sign():
    if request.method == "GET":
        return render_template("sign.html")

    # ── Kiểm tra file upload ──────────────────────────────────────────────────
    if "pdf" not in request.files or "key" not in request.files or "cert" not in request.files:
        return jsonify({"success": False, "error": "Thiếu file PDF, Private Key hoặc Certificate!"}), 400

    pdf_file  = request.files["pdf"]
    key_file  = request.files["key"]
    cert_file = request.files["cert"]

    if not pdf_file.filename.lower().endswith(".pdf"):
        return jsonify({"success": False, "error": "File phải là PDF (.pdf)!"}), 400

    # ── Lưu file upload tạm thời ─────────────────────────────────────────────
    session_id = uuid.uuid4().hex[:8]
    tmp_dir    = os.path.join(UPLOAD_DIR, session_id)
    os.makedirs(tmp_dir, exist_ok=True)

    pdf_path  = _save_upload(pdf_file,  tmp_dir, "pdf_")
    key_path  = _save_upload(key_file,  tmp_dir, "key_")
    cert_path = _save_upload(cert_file, tmp_dir, "cert_")

    # ── Nhận tham số ký ──────────────────────────────────────────────────────
    passphrase   = request.form.get("passphrase",   "").strip()
    signer_name  = request.form.get("signer_name",  "Nguyen Van A").strip()
    reason       = request.form.get("reason",       "Ky duyet tai lieu").strip()
    visible      = request.form.get("visible",      "true").lower() == "true"
    page_str     = request.form.get("page",         "last").strip()
    pos_preset   = request.form.get("pos_preset",   "Bottom-Right").strip()
    width        = float(request.form.get("width",  "170"))
    height       = float(request.form.get("height", "65"))

    # ── Chuẩn bị text_lines cho visual stamp ─────────────────────────────────
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    text_lines = [
        "CHU KY SO PADES HOP LE",
        f"Nguoi ky: {remove_vietnamese_accents(signer_name)}",
        f"Ly do: {remove_vietnamese_accents(reason)}",
        f"Ngay ky: {now_str}",
        "RSA-PSS + SHA-256 (PAdES)",
    ] if visible else []

    # ── Đường dẫn file đầu ra ────────────────────────────────────────────────
    base_name  = os.path.splitext(pdf_file.filename)[0]
    out_name   = f"{base_name}_signed_{session_id}.pdf"
    out_path   = os.path.join(SIGNED_DIR, out_name)

    try:
        info = sign_pdf_file(
            pdf_path=pdf_path,
            key_path=key_path,
            cert_path=cert_path,
            passphrase=passphrase,
            out_path=out_path,
            visible=visible,
            page_str=page_str,
            pos_preset=pos_preset,
            custom_x=0.0,
            custom_y=0.0,
            width=width,
            height=height,
            text_lines=text_lines,
            signer_name=signer_name,
            reason=reason,
        )
        return jsonify({
            "success":      True,
            "download_id":  session_id,
            "file_name":    out_name,
            "sign_time":    info["sign_time"],
            "signer_name":  info["signer_name"],
            "file_size_kb": info["file_size_kb"],
            "message":      "Ký số PAdES thành công!",
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/sign/download/<download_id>")
def sign_download(download_id):
    """Tải về file PDF đã ký."""
    if ".." in download_id or "/" in download_id:
        return "Invalid", 400

    # Tìm file có download_id trong tên
    for fn in os.listdir(SIGNED_DIR):
        if download_id in fn:
            return send_file(
                os.path.join(SIGNED_DIR, fn),
                as_attachment=True,
                download_name=fn,
                mimetype="application/pdf",
            )
    return "File không tồn tại hoặc đã hết hạn", 404


# =============================================================================
# ROUTE: XÁC THỰC CHỮ KÝ
# =============================================================================

@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "GET":
        return render_template("verify.html")

    if "pdf" not in request.files:
        return jsonify({"success": False, "error": "Chưa chọn file PDF!"}), 400

    pdf_file = request.files["pdf"]
    if not pdf_file.filename.lower().endswith(".pdf"):
        return jsonify({"success": False, "error": "File phải là PDF (.pdf)!"}), 400

    # Lưu tạm để xác thực
    session_id = uuid.uuid4().hex[:8]
    tmp_path   = os.path.join(UPLOAD_DIR, f"verify_{session_id}.pdf")
    pdf_file.save(tmp_path)

    try:
        ok, title, details = verify_pdf_file(tmp_path)
        return jsonify({
            "success": True,
            "valid":   ok,
            "title":   title,
            "details": details,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        # Xóa file tạm sau khi xác thực
        try:
            os.remove(tmp_path)
        except Exception:
            pass


# =============================================================================
# ENTRYPOINT
# =============================================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
