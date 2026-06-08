# ── Encoding UTF-8 ──────────────────────────────────────────────────────────
import os
import sys
import io
import datetime


os.environ["PYTHONUTF8"] = "1"
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# ── Kiểm tra thư viện bắt buộc ──────────────────────────────────────────────
_MISSING = []
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
    from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
except ModuleNotFoundError:
    _MISSING.append("cryptography")

try:
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import fields as sig_fields
    from pyhanko.sign.fields import SigFieldSpec
    from pyhanko.sign.signers import (
        SimpleSigner,
        PdfSignatureMetadata,
        sign_pdf,
    )
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko.stamp import TextStampStyle
    from pyhanko.pdf_utils.text import TextBoxStyle
except ModuleNotFoundError:
    _MISSING.append("pyhanko / pyhanko-certvalidator")

try:
    from reportlab.pdfgen import canvas as rl_canvas
    from reportlab.lib.colors import HexColor
    from pypdf import PdfReader as PypdfReader, PdfWriter as PypdfWriter
except ModuleNotFoundError:
    _MISSING.append("reportlab / pypdf")

if _MISSING:
    print("\n" + "=" * 80)
    print("  ❌ LỖI: THIẾU THƯ VIỆN PHỤ THUỘC")
    print("=" * 80)
    print(f"Các gói còn thiếu: {', '.join(_MISSING)}")
    print("\nCài đặt bằng lệnh:")
    print("  pip install pyhanko pyhanko-certvalidator cryptography reportlab pypdf")
    print("=" * 80)
    sys.exit(1)

# ── Tkinter (tùy chọn — fallback CLI nếu không có GUI) ────────────────────
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    _HAS_TK = True
except ImportError:
    tk = None
    _HAS_TK = False


# =============================================================================
# PHẦN 1: HÀM BỔ TRỢ TIẾNG VIỆT
# =============================================================================

def remove_vietnamese_accents(text: str) -> str:
    """
    Chuyển tiếng Việt có dấu → không dấu để tránh lỗi font khi vẽ
    trên PDF bằng font Helvetica (font chuẩn Latin, không hỗ trợ Unicode mở rộng).
    """
    _MAP = {
        'á':'a','à':'a','ả':'a','ã':'a','ạ':'a',
        'ă':'a','ắ':'a','ằ':'a','ẳ':'a','ẵ':'a','ặ':'a',
        'â':'a','ấ':'a','ầ':'a','ẩ':'a','ẫ':'a','ậ':'a',
        'é':'e','è':'e','ẻ':'e','ẽ':'e','ẹ':'e',
        'ê':'e','ế':'e','ề':'e','ể':'e','ễ':'e','ệ':'e',
        'í':'i','ì':'i','ỉ':'i','ĩ':'i','ị':'i',
        'ó':'o','ò':'o','ỏ':'o','õ':'o','ọ':'o',
        'ô':'o','ố':'o','ồ':'o','ổ':'o','ỗ':'o','ộ':'o',
        'ơ':'o','ớ':'o','ờ':'o','ở':'o','ỡ':'o','ợ':'o',
        'ú':'u','ù':'u','ủ':'u','ũ':'u','ụ':'u',
        'ư':'u','ứ':'u','ừ':'u','ử':'u','ữ':'u','ự':'u',
        'ý':'y','ỳ':'y','ỷ':'y','ỹ':'y','ỵ':'y','đ':'d',
        'Á':'A','À':'A','Ả':'A','Ã':'A','Ạ':'A',
        'Ă':'A','Ắ':'A','Ằ':'A','Ẳ':'A','Ẵ':'A','Ặ':'A',
        'Â':'A','Ấ':'A','Ầ':'A','Ẩ':'A','Ẫ':'A','Ậ':'A',
        'É':'E','È':'E','Ẻ':'E','Ẽ':'E','Ẹ':'E',
        'Ê':'E','Ế':'E','Ề':'E','Ể':'E','Ễ':'E','Ệ':'E',
        'Í':'I','Ì':'I','Ỉ':'I','Ĩ':'I','Ị':'I',
        'Ó':'O','Ò':'O','Ỏ':'O','Õ':'O','Ọ':'O',
        'Ô':'O','Ố':'O','Ồ':'O','Ổ':'O','Ỗ':'O','Ộ':'O',
        'Ơ':'O','Ớ':'O','Ờ':'O','Ở':'O','Ỡ':'O','Ợ':'O',
        'Ú':'U','Ù':'U','Ủ':'U','Ũ':'U','Ụ':'U',
        'Ư':'U','Ứ':'U','Ừ':'U','Ử':'U','Ữ':'U','Ự':'U',
        'Ý':'Y','Ỳ':'Y','Ỷ':'Y','Ỹ':'Y','Ỵ':'Y','Đ':'D',
    }
    return "".join(_MAP.get(c, c) for c in text)


# =============================================================================
# PHẦN 2: SINH KHÓA RSA + CHỨNG THƯ X.509 TỰ KÝ (SELF-SIGNED CERTIFICATE)
# =============================================================================

def generate_identity_and_cert(
    key_size: int,
    common_name: str,
    organization: str,
    country: str,
    valid_days: int,
    passphrase: str,
    save_dir: str,
) -> tuple[str, str]:
    """
    Sinh khóa RSA và chứng thư số X.509 tự ký (Self-Signed Certificate).

    Tại sao cần X.509 thay vì chỉ cặp khóa PEM thô?
    ────────────────────────────────────────────────
    - Chuẩn PAdES / ISO 32000-1 yêu cầu chữ ký phải được gói trong
      cấu trúc CMS (Cryptographic Message Syntax / PKCS#7).
    - Bên trong CMS, bắt buộc phải có Certificate (chứng thư X.509) đính kèm
      để Adobe Reader có thể trích xuất thông tin định danh (CN, O, C, ...).
    - Nếu dùng khóa thô (.pem) không có cert, pyHanko không thể tạo
      cấu trúc /Contents hợp lệ theo chuẩn ISO.

    Trả về: (đường dẫn private key .pem, đường dẫn certificate .crt)
    """
    # ── Bước 1: Sinh khóa RSA ─────────────────────────────────────────────
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
        )

    # ── Bước 2: Xây dựng Subject / Issuer DN (Distinguished Name) ─────────
    # Đây là thông tin định danh sẽ hiển thị trong Signature Panel của Adobe
    safe_cn  = remove_vietnamese_accents(common_name)   # tên người ký
    safe_org = remove_vietnamese_accents(organization)  # tổ chức
    safe_c   = country[:2].upper() if country else "VN"

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,             safe_c),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,        safe_org),
        x509.NameAttribute(NameOID.COMMON_NAME,              safe_cn),
    ])

    # ── Bước 3: Xây dựng cấu trúc chứng thư X.509 v3 ─────────────────────
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)                           # tự ký → issuer = subject
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        # Extension: Basic Constraints — đánh dấu đây là CA (cần cho cert tự ký)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        # Extension: Key Usage — chỉ định mục đích sử dụng khóa
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,   # non-repudiation
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,        # cần vì CA=True
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # Ký chứng thư bằng chính private key (self-signed)
        .sign(private_key, hashes.SHA256(), backend=default_backend())
    )

    # ── Bước 4: Xuất file ──────────────────────────────────────────────────
    enc_algo = (
        serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
        if passphrase
        else serialization.NoEncryption()
    )

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_algo,
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    os.makedirs(save_dir, exist_ok=True)
    priv_path = os.path.join(save_dir, "private_key.pem")
    cert_path = os.path.join(save_dir, "certificate.crt")

    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    with open(cert_path, "wb") as f:
        f.write(cert_pem)

    return priv_path, cert_path


# =============================================================================
# PHẦN 3: THÊM LỚP CHỮ KÝ TRỰC QUAN (VISUAL STAMP) VÀO PDF — dùng reportlab
# =============================================================================

def _compute_stamp_box(
    page_width: float, page_height: float,
    pos_preset: str,
    custom_x: float, custom_y: float,
    width: float, height: float,
) -> tuple[float, float, float, float]:
    """
    Tính tọa độ (x0, y0, x1, y1) của khung chữ ký dạng PDF points.
    Hệ tọa độ PDF: góc dưới-trái là (0,0).
    Trả về tuple (x0, y0, x1, y1) — bottom-left và top-right corner.
    """
    margin = 20.0
    if pos_preset == "Bottom-Right":
        x0 = page_width  - width  - margin
        y0 = margin
    elif pos_preset == "Bottom-Left":
        x0 = margin
        y0 = margin
    elif pos_preset == "Top-Right":
        x0 = page_width  - width  - margin
        y0 = page_height - height - margin
    elif pos_preset == "Top-Left":
        x0 = margin
        y0 = page_height - height - margin
    else:  # Custom
        x0 = float(custom_x)
        y0 = float(custom_y)

    # Clamp vào trong trang
    x0 = max(0.0, min(x0, page_width  - width))
    y0 = max(0.0, min(y0, page_height - height))

    return x0, y0, x0 + width, y0 + height


def draw_visual_stamp_on_pdf(
    pdf_bytes: bytes,
    page_str: str,
    pos_preset: str,
    custom_x: float,
    custom_y: float,
    width: float,
    height: float,
    text_lines: list[str],
) -> bytes:
    """
    Vẽ con dấu chữ ký trực quan (visible stamp) lên trang PDF chỉ định.

    Luồng xử lý:
      1. Dùng reportlab tạo một trang overlay chứa khung + text chữ ký.
      2. Dùng pypdf hợp nhất (merge) overlay vào đúng trang cần ký.
      3. Trả về bytes PDF mới (chỉ có visual stamp, chưa có chữ ký mật mã).

    Lưu ý: bước này chỉ tạo "hình ảnh" con dấu. Chữ ký mật mã thực sự
    (PKCS#7/CMS + ByteRange) sẽ được pyHanko nhúng ở bước tiếp theo.
    """
    reader  = PypdfReader(io.BytesIO(pdf_bytes))
    n_pages = len(reader.pages)

    # Xác định số trang (1-based)
    if page_str.strip().lower() == "last":
        page_num = n_pages
    else:
        try:
            page_num = max(1, min(int(page_str), n_pages))
        except ValueError:
            page_num = n_pages

    target_page = reader.pages[page_num - 1]
    pw = float(target_page.mediabox.width)
    ph = float(target_page.mediabox.height)

    x0, y0, x1, y1 = _compute_stamp_box(pw, ph, pos_preset, custom_x, custom_y, width, height)

    # ── Vẽ overlay bằng reportlab ──────────────────────────────────────────
    # ReportLab và PDF đều dùng hệ tọa độ bottom-left = (0,0).
    # KHÔNG dùng translate/scale để tránh tính sai vị trí.
    buf = io.BytesIO()
    c   = rl_canvas.Canvas(buf, pagesize=(pw, ph))

    # Khung viền kép màu đỏ — vẽ trực tiếp tại (x0, y0) trong hệ PDF
    c.setStrokeColor(HexColor("#CC0000"))
    c.setLineWidth(1.5)
    c.rect(x0, y0, width, height, stroke=1, fill=0)
    c.setStrokeColor(HexColor("#FF6666"))
    c.setLineWidth(0.5)
    c.rect(x0 + 2, y0 + 2, width - 4, height - 4, stroke=1, fill=0)

    # Nội dung text — bắt đầu từ phía trên của khung (y0 + height - 12)
    c.setFillColor(HexColor("#B71C1C"))
    text_y = y0 + height - 12
    for i, line in enumerate(text_lines):
        c.setFont("Helvetica-Bold" if i == 0 else "Helvetica", 8)
        c.drawString(x0 + 6, text_y, line)
        text_y -= 10.5

    c.save()
    buf.seek(0)

    # ── Hợp nhất overlay vào PDF gốc bằng pypdf ───────────────────────────
    overlay_page = PypdfReader(buf).pages[0]
    writer = PypdfWriter()
    for idx, page in enumerate(reader.pages):
        if idx == page_num - 1:
            page.merge_page(overlay_page, expand=True)
        writer.add_page(page)

    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


# =============================================================================
# PHẦN 4: KÝ SỐ PDF CHUẨN PAdES — CƠ CHẾ BYTE-RANGE (pyHanko)
# =============================================================================

def sign_pdf_file(
    pdf_path:   str,
    key_path:   str,
    cert_path:  str,
    passphrase: str,
    out_path:   str,
    # tham số chữ ký trực quan
    visible:    bool  = False,
    page_str:   str   = "last",
    pos_preset: str   = "Bottom-Right",
    custom_x:   float = 0.0,
    custom_y:   float = 0.0,
    width:      float = 160.0,
    height:     float = 100.0,
    text_lines: list[str] | None = None,
    # metadata chữ ký
    signer_name: str  = "",
    reason:      str  = "",
    location:    str  = "Viet Nam",
) -> dict:
    """
    Ký số PDF theo chuẩn PAdES / ISO 32000-1 sử dụng cơ chế Byte-Range.

    ════════════════════════════════════════════════════════════════════
    Giải thích cơ chế Byte-Range (quan trọng cho báo cáo):
    ════════════════════════════════════════════════════════════════════
    Chuẩn PDF cho phép nhúng chữ ký số trực tiếp vào thân file PDF thông
    qua entry /ByteRange trong Signature Dictionary:

        /ByteRange [A B C D]

    Trong đó:
      A = offset bắt đầu tính từ byte 0 của file (thường = 0)
      B = số byte từ A đến TRƯỚC ký tự mở ngoặc '<' của /Contents
      C = offset của ký tự sau ngoặc đóng '>' của /Contents
      D = số byte từ C đến cuối file

    Vùng được băm (hash) = bytes[A .. A+B] + bytes[C .. C+D]
    → Không bao gồm /Contents chính nó, vì /Contents chứa chữ ký
      cần được đặt TRƯỚC khi băm nên không thể tự băm chính nó.

    pyHanko thực hiện toàn bộ quy trình này:
      1. Tạo IncrementalPdfFileWriter (chỉ thêm revision, không sửa file gốc)
      2. Gọi sign_pdf() → pyHanko đặt placeholder /Contents với hex zeros
      3. Tính toán /ByteRange chính xác
      4. Băm SHA-256 trên hai vùng ByteRange
      5. Ký bằng RSA-PSS, đóng gói vào CMS/PKCS#7 cùng Certificate X.509
      6. Ghi lại chữ ký HEX vào đúng vị trí /Contents placeholder
    ════════════════════════════════════════════════════════════════════

    Trả về dict chứa thông tin chữ ký để hiển thị lên GUI/CLI.
    """
    # ── Đọc và kiểm tra PDF đầu vào ───────────────────────────────────────
    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()
    if b"%PDF" not in pdf_bytes[:1024]:
        raise ValueError("File không đúng định dạng PDF tiêu chuẩn!")

    # ── Bước 1: Vẽ visual stamp lên PDF (nếu được yêu cầu) ───────────────
    # Thực hiện TRƯỚC bước ký mật mã để con dấu trực quan được bảo vệ bởi chữ ký
    if visible and text_lines:
        pdf_bytes = draw_visual_stamp_on_pdf(
            pdf_bytes, page_str, pos_preset, custom_x, custom_y,
            width, height, text_lines,
        )

    # ── Bước 2: Nạp khóa bí mật và chứng thư X.509 vào pyHanko ──────────
    # SimpleSigner là lớp signer chuẩn của pyHanko, nó tự động:
    #   - Đóng gói cert vào CMS SignedData structure
    #   - Thực hiện RSA-PSS signing (khi prefer_pss=True)
    #   - Gắn cert vào /Contents theo chuẩn PAdES-B-B (Basic)
    pass_bytes = passphrase.encode("utf-8") if passphrase else None
    try:
        signer = SimpleSigner.load(
            key_file=key_path,
            cert_file=cert_path,
            key_passphrase=pass_bytes,
            prefer_pss=True,   # ← dùng RSA-PSS thay vì PKCS#1 v1.5
        )
    except Exception as e:
        raise ValueError(f"Không thể nạp khóa/chứng thư: {e}") from e

    # ── Bước 3: Tính tọa độ trường chữ ký (Signature Field) ─────────────
    # pyHanko cần biết vị trí trường chữ ký (box) và trang để:
    #   a) Tạo AcroForm field /Sig trong PDF structure (được Adobe nhận diện)
    #   b) Hiển thị visual stamp (nếu có) đúng vị trí
    reader_tmp  = PypdfReader(io.BytesIO(pdf_bytes))
    n_pages_tmp = len(reader_tmp.pages)
    if page_str.strip().lower() == "last":
        sig_page = n_pages_tmp - 1  # 0-based
    else:
        try:
            sig_page = max(0, min(int(page_str) - 1, n_pages_tmp - 1))
        except ValueError:
            sig_page = n_pages_tmp - 1

    target_page = reader_tmp.pages[sig_page]
    pw = float(target_page.mediabox.width)
    ph = float(target_page.mediabox.height)

    x0, y0, x1, y1 = _compute_stamp_box(
        pw, ph, pos_preset, custom_x, custom_y, width, height
    )
    # pyHanko dùng hệ tọa độ PDF (bottom-left origin), tuple = (x0, y0, x1, y1)
    sig_box = (x0, y0, x1, y1) if visible else None

    # ── Bước 4: Tạo SigFieldSpec — khai báo trường chữ ký ────────────────
    # SigFieldSpec định nghĩa:
    #   - Tên trường (field_name): duy nhất trong file PDF
    #   - Trang (on_page): trang chứa trường, 0-based
    #   - Vị trí (box): tọa độ (x0, y0, x1, y1) — nếu None → invisible
    field_name = "Sig1"
    new_field_spec = SigFieldSpec(
        sig_field_name=field_name,
        on_page=sig_page,
        box=sig_box,            # None = chữ ký ẩn (chỉ metadata, không hiển thị khung)
    )

    # ── Bước 5: Cấu hình metadata chữ ký ─────────────────────────────────
    # PdfSignatureMetadata chứa các thông tin được nhúng vào Signature Dictionary:
    #   /Name    → tên người ký (hiển thị trong Signature Panel Adobe)
    #   /Reason  → lý do ký (hiển thị trong Signature Properties)
    #   /Location → địa điểm ký
    #   /M       → thời điểm ký (auto từ đồng hồ hệ thống)
    sig_meta = PdfSignatureMetadata(
        field_name=field_name,
        md_algorithm="sha256",          # băm SHA-256
        name=remove_vietnamese_accents(signer_name) if signer_name else None,
        reason=remove_vietnamese_accents(reason)    if reason      else "Ky duyet tai lieu",
        location=remove_vietnamese_accents(location),
    )

    # ── Bước 6: NHÚNG CHỮ KÝ VÀO PDF — cơ chế IncrementalWriter ─────────
    # IncrementalPdfFileWriter là cơ chế cốt lõi của chuẩn ISO 32000:
    #   - Không sửa đổi bytes của file gốc
    #   - Chỉ APPEND một revision mới vào cuối file (cấu trúc PDF Cross-Reference)
    #   - Byte-Range sẽ trỏ đúng vào các vùng bytes này
    # → Đây là lý do tại sao Adobe Reader nhận diện được chữ ký
    pdf_stream   = io.BytesIO(pdf_bytes)
    pdf_writer   = IncrementalPdfFileWriter(pdf_stream)
    output_buf   = io.BytesIO()

    # sign_pdf() thực hiện toàn bộ quy trình PAdES Byte-Range:
    #   1. Tạo trường chữ ký (append_signature_field)
    #   2. Giữ chỗ /Contents với hex zeros
    #   3. Tính /ByteRange
    #   4. Hash ByteRange với SHA-256
    #   5. Ký RSA-PSS, đóng gói CMS + Certificate
    #   6. Ghi hex chữ ký vào /Contents placeholder
    sign_pdf(
        pdf_out=pdf_writer,
        signature_meta=sig_meta,
        signer=signer,
        new_field_spec=new_field_spec,
        output=output_buf,
        in_place=False,
    )

    # ── Bước 7: Lưu file ký ───────────────────────────────────────────────
    signed_bytes = output_buf.getvalue()
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(signed_bytes)

    # ── Trả về thông tin tóm tắt ──────────────────────────────────────────
    sign_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return {
        "output_path": os.path.abspath(out_path),
        "sign_time":   sign_time,
        "field_name":  field_name,
        "signer_name": signer_name or "(không cung cấp)",
        "reason":      reason     or "Ky duyet tai lieu",
        "file_size_kb": len(signed_bytes) // 1024,
    }


# =============================================================================
# PHẦN 5: XÁC THỰC CHỮ KÝ PDF CHUẨN PAdES (pyHanko Validation)
# =============================================================================

def verify_pdf_file(pdf_path: str) -> tuple[bool, str, str]:
    """
    Xác thực chữ ký số PAdES nhúng trong file PDF.

    ════════════════════════════════════════════════════════════════════
    Quy trình xác thực Byte-Range (pyHanko tự động thực hiện):
    ════════════════════════════════════════════════════════════════════
    1. Đọc /ByteRange từ Signature Dictionary trong file PDF
    2. Đọc đúng hai vùng bytes được chỉ định bởi /ByteRange
    3. Băm SHA-256 trên hai vùng đó
    4. Đọc /Contents → giải mã CMS/PKCS#7 → trích xuất:
         - Chữ ký RSA-PSS (raw signature bytes)
         - Certificate X.509 của người ký
    5. Dùng Public Key trong Certificate xác thực chữ ký trên hash
    6. Kiểm tra Certificate (còn hạn, đúng key usage, ...)
    7. Trả về kết quả + thông tin người ký từ Certificate
    ════════════════════════════════════════════════════════════════════

    Tham số:
        pdf_path: đường dẫn file PDF đã ký

    Trả về:
        (success: bool, title: str, details: str)
    """
    with open(pdf_path, "rb") as f:
        reader = PdfFileReader(f, strict=False)

        # Lấy danh sách chữ ký nhúng trong file PDF
        # embedded_regular_signatures trả về Iterator[EmbeddedPdfSignature]
        sigs = list(reader.embedded_regular_signatures)

        if not sigs:
            return (
                False,
                "Không tìm thấy chữ ký số",
                "File PDF này chưa được ký số theo chuẩn PAdES/ISO 32000-1.\n"
                "Hệ thống không tìm thấy Signature Field nào trong AcroForm.",
            )

        # Xác thực chữ ký đầu tiên (mở rộng sau để xử lý nhiều chữ ký)
        sig = sigs[0]

        # Xác thực tính toàn vẹn Byte-Range và chữ ký CMS
        # validate_pdf_signature() tự động:
        #   - Kiểm tra coverage (ByteRange có bao phủ toàn bộ file không?)
        #   - Giải mã CMS, xác thực hash + chữ ký RSA
        #   - Kiểm tra Certificate validity (thời hạn, key usage)
        status = validate_pdf_signature(sig)

        # ── Trích xuất thông tin Certificate để hiển thị ──────────────────
        cert_info = _extract_cert_info(sig)

        # ── Đánh giá kết quả ──────────────────────────────────────────────
        # intact: ByteRange coverage hợp lệ, hash khớp
        # valid:  chữ ký RSA xác thực thành công
        # trusted: cert do CA tin cậy cấp (sẽ là False với self-signed cert)
        intact  = status.intact
        valid   = status.valid

        if intact and valid:
            title = "CHU KY HOP LE — Byte-Range & CMS da duoc xac thuc"
            details = (
                f"Ket qua: Chu ky so PAdES hop le!\n"
                f"  • Toan ven du lieu (ByteRange): Co\n"
                f"  • Chu ky RSA-PSS hop le: Co\n"
                f"  • Chung thu tin cay (Trusted): "
                f"{'Co' if status.trusted else 'Khong (Self-Signed Cert)'}\n\n"
                + cert_info
            )
            return (True, title, details)
        else:
            reason_list = []
            if not intact:
                reason_list.append("Du lieu bi chinh sua sau khi ky (ByteRange sai)")
            if not valid:
                reason_list.append("Chu ky RSA khong khop voi noi dung file")
            title   = "CANH BAO: CHU KY KHONG HOP LE"
            details = (
                f"Ket qua: Chu ky so PAdES KHONG hop le!\n"
                f"  • Ly do: {'; '.join(reason_list)}\n\n"
                + cert_info
            )
            return (False, title, details)


def _extract_cert_info(sig) -> str:
    """
    Trích xuất thông tin từ Certificate X.509 nhúng trong chữ ký CMS.
    Hiển thị: Tên người ký (CN), Tổ chức (O), Quốc gia (C), thời hạn cert.
    """
    try:
        cert = sig.signer_cert   # đối tượng asn1crypto.x509.Certificate
        if cert is None:
            return "Khong tim thay chung thu so trong chu ky."

        subject = cert.subject
        # human_friendly = "Common Name: ..., Organization: ..., Country: ..."
        cn = org = country = "N/A"
        try:
            for part in subject.human_friendly.split(","):
                part = part.strip()
                if part.startswith("Common Name:"):
                    cn = part.split(":", 1)[-1].strip()
                elif part.startswith("Organization:"):
                    org = part.split(":", 1)[-1].strip()
                elif part.startswith("Country:"):
                    country = part.split(":", 1)[-1].strip()
        except Exception:
            cn = org = country = "N/A"

        not_before = cert["tbs_certificate"]["validity"]["not_before"].native
        not_after  = cert["tbs_certificate"]["validity"]["not_after"].native

        self_signed_note = ""
        try:
            if cert.issuer == cert.subject:
                self_signed_note = " (Self-Signed — Chu ky tu ky)"
        except Exception:
            pass

        return (
            f"Thong tin chung thu so X.509:\n"
            f"  • Nguoi ky (CN) : {cn}\n"
            f"  • To chuc  (O)  : {org}\n"
            f"  • Quoc gia (C)  : {country}\n"
            f"  • Hieu luc tu   : {not_before.strftime('%Y-%m-%d')}\n"
            f"  • Hieu luc den  : {not_after.strftime('%Y-%m-%d')}{self_signed_note}\n"
            f"  • Serial Number : {cert.serial_number}\n"
        )
    except Exception as ex:
        return f"Khong the doc thong tin chung thu: {ex}"


# =============================================================================
# PHẦN 6: GIAO DIỆN ĐỒ HỌA TKINTER (GUI)
# =============================================================================

class PDFSignerApp:
    """
    Giao diện đồ họa Tkinter với 3 tab chức năng:
      Tab 1 — Tạo Cặp Khóa & Chứng Thư X.509
      Tab 2 — Ký Số PDF (PAdES Byte-Range)
      Tab 3 — Xác Thực Chữ Ký
    """

    def __init__(self, root: "tk.Tk"):
        self.root = root
        self.root.title("Hệ thống Ký số PDF chuẩn PAdES (RSA-PSS + X.509)")
        self.root.geometry("800x700")
        self.root.resizable(False, False)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", font=("Helvetica", 10))
        style.configure("TLabel", foreground="#333333")
        style.configure("TButton", font=("Helvetica", 10, "bold"), padding=6)
        style.configure("Action.TButton", background="#17b978", foreground="white")
        style.map("Action.TButton", background=[("active", "#118f5c")])
        style.configure("Danger.TButton", background="#c62828", foreground="white")
        style.map("Danger.TButton", background=[("active", "#b71c1c")])

        ttk.Label(
            root,
            text="HỆ THỐNG KÝ SỐ PDF — CHUẨN PAdES / ISO 32000-1",
            font=("Helvetica", 13, "bold"),
            foreground="#1a237e",
        ).pack(pady=12)

        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=10, pady=5)

        self.tab_key    = ttk.Frame(nb)
        self.tab_sign   = ttk.Frame(nb)
        self.tab_verify = ttk.Frame(nb)
        nb.add(self.tab_key,    text="  🔑 Tạo Khóa & Chứng Thư X.509  ")
        nb.add(self.tab_sign,   text="  ✍️ Ký Số PDF (PAdES)  ")
        nb.add(self.tab_verify, text="  🔍 Xác Thực Chữ Ký  ")

        self._build_key_tab()
        self._build_sign_tab()
        self._build_verify_tab()

        self.status_var = tk.StringVar(value="Sẵn sàng.")
        ttk.Label(root, textvariable=self.status_var,
                  relief=tk.SUNKEN, anchor="w",
                  font=("Helvetica", 9)).pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)

    # ──────────────────────────────────────────────────────────────────────
    # TAB 1: TẠO CẶP KHÓA & CHỨNG THƯ X.509
    # ──────────────────────────────────────────────────────────────────────
    def _build_key_tab(self):
        f = ttk.LabelFrame(self.tab_key, text=" Thông tin chứng thư X.509 & tham số khóa RSA ", padding=18)
        f.pack(fill="both", expand=True, padx=15, pady=15)

        def row(label, widget_factory, r, **kw):
            ttk.Label(f, text=label, font=("Helvetica", 10, "bold")).grid(
                row=r, column=0, sticky="w", pady=6)
            w = widget_factory(f, **kw)
            w.grid(row=r, column=1, sticky="w", padx=10, pady=6)
            return w

        self.k_cn   = tk.StringVar(value="Nguyen Van A")
        self.k_org  = tk.StringVar(value="Cong ty ABC")
        self.k_c    = tk.StringVar(value="VN")
        self.k_days = tk.StringVar(value="730")
        self.k_size = tk.StringVar(value="2048")
        self.k_pass = tk.StringVar()

        ttk.Entry(f, textvariable=self.k_cn,   width=35).grid(row=0, column=1, sticky="w", padx=10, pady=6)
        ttk.Label(f, text="Họ tên người ký (CN):", font=("Helvetica", 10, "bold")).grid(row=0, column=0, sticky="w", pady=6)

        ttk.Entry(f, textvariable=self.k_org,  width=35).grid(row=1, column=1, sticky="w", padx=10, pady=6)
        ttk.Label(f, text="Tên tổ chức (O):", font=("Helvetica", 10, "bold")).grid(row=1, column=0, sticky="w", pady=6)

        ttk.Entry(f, textvariable=self.k_c,    width=5).grid(row=2, column=1, sticky="w", padx=10, pady=6)
        ttk.Label(f, text="Mã quốc gia (C, 2 ký tự):", font=("Helvetica", 10, "bold")).grid(row=2, column=0, sticky="w", pady=6)

        ttk.Entry(f, textvariable=self.k_days, width=8).grid(row=3, column=1, sticky="w", padx=10, pady=6)
        ttk.Label(f, text="Thời hạn chứng thư (ngày):", font=("Helvetica", 10, "bold")).grid(row=3, column=0, sticky="w", pady=6)

        ttk.Combobox(f, textvariable=self.k_size, values=["2048", "4096"],
                     width=8, state="readonly").grid(row=4, column=1, sticky="w", padx=10, pady=6)
        ttk.Label(f, text="Độ dài khóa RSA (bit):", font=("Helvetica", 10, "bold")).grid(row=4, column=0, sticky="w", pady=6)

        self.k_pass_entry = ttk.Entry(f, textvariable=self.k_pass, show="*", width=25)
        self.k_pass_entry.grid(row=5, column=1, sticky="w", padx=10, pady=6)
        ttk.Label(f, text="Mật khẩu bảo vệ Private Key:", font=("Helvetica", 10, "bold")).grid(row=5, column=0, sticky="w", pady=6)

        ttk.Label(f, text=(
            "⚠  Kết quả: private_key.pem (khóa riêng) + certificate.crt (chứng thư X.509 tự ký)\n"
            "    → Dùng certificate.crt để Adobe Reader nhận diện chứng thư trong Signature Panel."
        ), foreground="#555", font=("Helvetica", 9, "italic"), wraplength=560).grid(
            row=6, column=0, columnspan=2, sticky="w", pady=8)

        ttk.Button(f, text="⚡ Sinh Khóa & Chứng Thư X.509",
                   style="Action.TButton",
                   command=self._do_keygen).grid(row=7, column=0, columnspan=2, pady=12)

    def _do_keygen(self):
        save_dir = filedialog.askdirectory(title="Chọn thư mục lưu khóa và chứng thư")
        if not save_dir:
            return
        try:
            self.status_var.set("Đang sinh khóa RSA và chứng thư X.509...")
            self.root.update_idletasks()
            priv, cert = generate_identity_and_cert(
                key_size=int(self.k_size.get()),
                common_name=self.k_cn.get().strip()   or "Nguyen Van A",
                organization=self.k_org.get().strip() or "Cong ty ABC",
                country=self.k_c.get().strip()[:2]    or "VN",
                valid_days=int(self.k_days.get().strip() or "730"),
                passphrase=self.k_pass.get().strip(),
                save_dir=save_dir,
            )
            self.status_var.set("Sinh khóa thành công!")
            messagebox.showinfo("Thành công",
                f"Đã sinh cặp khóa RSA + Chứng thư X.509:\n\n"
                f"  Khóa bí mật : {priv}\n"
                f"  Chứng thư   : {cert}\n\n"
                f"Dùng certificate.crt và private_key.pem để ký số PDF.")
        except Exception as e:
            self.status_var.set("Sinh khóa thất bại!")
            messagebox.showerror("Lỗi", str(e))

    # ──────────────────────────────────────────────────────────────────────
    # TAB 2: KÝ SỐ PDF
    # ──────────────────────────────────────────────────────────────────────
    def _build_sign_tab(self):
        f = ttk.LabelFrame(self.tab_sign, text=" Cấu hình ký số PDF chuẩn PAdES Byte-Range ", padding=14)
        f.pack(fill="both", expand=True, padx=15, pady=10)

        def pick_file(var, filetypes):
            p = filedialog.askopenfilename(filetypes=filetypes)
            if p:
                var.set(p)

        # PDF gốc
        self.s_pdf  = tk.StringVar()
        self.s_key  = tk.StringVar()
        self.s_cert = tk.StringVar()
        self.s_pass = tk.StringVar()
        self.s_name = tk.StringVar(value="Nguyen Van A")
        self.s_reason = tk.StringVar(value="Ky duyet tai lieu")

        ttk.Label(f, text="File PDF cần ký:", font=("Helvetica", 10, "bold")).grid(row=0, column=0, sticky="w", pady=5)
        ttk.Entry(f, textvariable=self.s_pdf, width=44, state="readonly").grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(f, text="Mở...", command=lambda: pick_file(self.s_pdf, [("PDF","*.pdf")])).grid(row=0, column=2)

        ttk.Label(f, text="Private Key (.pem):", font=("Helvetica", 10, "bold")).grid(row=1, column=0, sticky="w", pady=5)
        ttk.Entry(f, textvariable=self.s_key, width=44, state="readonly").grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(f, text="Mở...", command=lambda: pick_file(self.s_key, [("PEM","*.pem"),("All","*.*")])).grid(row=1, column=2)

        ttk.Label(f, text="Certificate (.crt/.pem):", font=("Helvetica", 10, "bold")).grid(row=2, column=0, sticky="w", pady=5)
        ttk.Entry(f, textvariable=self.s_cert, width=44, state="readonly").grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(f, text="Mở...", command=lambda: pick_file(self.s_cert, [("CRT","*.crt"),("PEM","*.pem"),("All","*.*")])).grid(row=2, column=2)

        ttk.Label(f, text="Mật khẩu Private Key:", font=("Helvetica", 10, "bold")).grid(row=3, column=0, sticky="w", pady=5)
        ttk.Entry(f, textvariable=self.s_pass, show="*", width=25).grid(row=3, column=1, sticky="w", padx=5, pady=5)

        ttk.Label(f, text="Tên người ký:", font=("Helvetica", 10, "bold")).grid(row=4, column=0, sticky="w", pady=5)
        ttk.Entry(f, textvariable=self.s_name, width=25).grid(row=4, column=1, sticky="w", padx=5, pady=5)

        ttk.Label(f, text="Lý do ký:", font=("Helvetica", 10, "bold")).grid(row=5, column=0, sticky="w", pady=5)
        ttk.Entry(f, textvariable=self.s_reason, width=35).grid(row=5, column=1, sticky="w", padx=5, pady=5)

        # Khung visual stamp
        vf = ttk.LabelFrame(f, text=" Chữ ký trực quan (Visible Stamp) ", padding=10)
        vf.grid(row=6, column=0, columnspan=3, sticky="nsew", pady=10)

        self.s_visible = tk.BooleanVar(value=True)
        ttk.Checkbutton(vf, text="Hiển thị khung chữ ký trực quan trên trang PDF",
                        variable=self.s_visible).grid(row=0, column=0, columnspan=4, sticky="w")

        self.s_page = tk.StringVar(value="last")
        self.s_pos  = tk.StringVar(value="Bottom-Right")
        self.s_w    = tk.StringVar(value="170")
        self.s_h    = tk.StringVar(value="100")
        self.s_cx   = tk.StringVar(value="100")
        self.s_cy   = tk.StringVar(value="100")

        ttk.Label(vf, text="Trang ký:").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(vf, textvariable=self.s_page, width=8).grid(row=1, column=1, sticky="w", padx=5)
        ttk.Label(vf, text="Vị trí:").grid(row=1, column=2, sticky="w")
        self.s_pos_combo = ttk.Combobox(
            vf, textvariable=self.s_pos, width=13, state="readonly",
            values=["Bottom-Right","Bottom-Left","Top-Right","Top-Left","Custom"])
        self.s_pos_combo.grid(row=1, column=3, sticky="w", padx=5)
        self.s_pos_combo.bind("<<ComboboxSelected>>", self._on_pos_change)

        ttk.Label(vf, text="Rộng:").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(vf, textvariable=self.s_w, width=7).grid(row=2, column=1, sticky="w", padx=5)
        ttk.Label(vf, text="Cao:").grid(row=2, column=2, sticky="w")
        ttk.Entry(vf, textvariable=self.s_h, width=7).grid(row=2, column=3, sticky="w", padx=5)

        ttk.Label(vf, text="Custom X:").grid(row=3, column=0, sticky="w", pady=4)
        self.s_cx_entry = ttk.Entry(vf, textvariable=self.s_cx, width=7, state="disabled")
        self.s_cx_entry.grid(row=3, column=1, sticky="w", padx=5)
        ttk.Label(vf, text="Custom Y:").grid(row=3, column=2, sticky="w")
        self.s_cy_entry = ttk.Entry(vf, textvariable=self.s_cy, width=7, state="disabled")
        self.s_cy_entry.grid(row=3, column=3, sticky="w", padx=5)

        ttk.Button(f, text="✍️  Tiến Hành Ký Số PAdES",
                   style="Action.TButton",
                   command=self._do_sign).grid(row=7, column=0, columnspan=3, pady=10)

    def _on_pos_change(self, _=None):
        state = "normal" if self.s_pos.get() == "Custom" else "disabled"
        self.s_cx_entry.config(state=state)
        self.s_cy_entry.config(state=state)

    def _do_sign(self):
        pdf   = self.s_pdf.get()
        key   = self.s_key.get()
        cert  = self.s_cert.get()
        passw = self.s_pass.get().strip()

        if not pdf or not key or not cert:
            messagebox.showwarning("Thiếu thông tin",
                "Vui lòng chọn đầy đủ:\n  • File PDF\n  • Private Key\n  • Certificate (.crt)")
            return

        dir_n, file_n = os.path.split(pdf)
        name_n, ext_n = os.path.splitext(file_n)
        out_path = filedialog.asksaveasfilename(
            initialdir=dir_n,
            initialfile=f"{name_n}_signed_pades{ext_n}",
            filetypes=[("PDF","*.pdf")], defaultextension=".pdf")
        if not out_path:
            return

        try:
            self.status_var.set("Đang thực hiện ký số PAdES Byte-Range...")
            self.root.update_idletasks()

            visible = self.s_visible.get()
            sig_name = self.s_name.get().strip()
            reason   = self.s_reason.get().strip()
            now_str  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            text_lines = [
                "CHU KY SO PADES HOP LE",
                f"Nguoi ky: {remove_vietnamese_accents(sig_name)}",
                f"Ly do: {remove_vietnamese_accents(reason)}",
                f"Ngay ky: {now_str}",
                "RSA-PSS + SHA-256 (PAdES)",
            ] if visible else []

            info = sign_pdf_file(
                pdf_path=pdf, key_path=key, cert_path=cert,
                passphrase=passw, out_path=out_path,
                visible=visible,
                page_str=self.s_page.get(),
                pos_preset=self.s_pos.get(),
                custom_x=float(self.s_cx.get() or 100),
                custom_y=float(self.s_cy.get() or 100),
                width=float(self.s_w.get() or 170),
                height=float(self.s_h.get() or 100),
                text_lines=text_lines,
                signer_name=sig_name,
                reason=reason,
            )
            self.status_var.set("Ký số PAdES thành công!")
            messagebox.showinfo("Ký số thành công",
                f"PDF đã được ký theo chuẩn PAdES / ISO 32000-1!\n\n"
                f"File đã ký: {info['output_path']}\n"
                f"Kích thước: {info['file_size_kb']} KB\n"
                f"Thời gian ký: {info['sign_time']}\n\n"
                f"Mở file bằng Adobe Acrobat Reader để kiểm tra\n"
                f"'Signature Panel' → thấy chứng thư X.509.")
        except Exception as e:
            self.status_var.set("Ký số thất bại!")
            messagebox.showerror("Lỗi ký số", str(e))

    # ──────────────────────────────────────────────────────────────────────
    # TAB 3: XÁC THỰC
    # ──────────────────────────────────────────────────────────────────────
    def _build_verify_tab(self):
        f = ttk.LabelFrame(self.tab_verify, text=" Xác thực chữ ký PAdES nhúng trong PDF ", padding=15)
        f.pack(fill="both", expand=True, padx=15, pady=15)

        self.v_pdf = tk.StringVar()
        ttk.Label(f, text="File PDF đã ký:", font=("Helvetica", 10, "bold")).grid(row=0, column=0, sticky="w", pady=8)
        ttk.Entry(f, textvariable=self.v_pdf, width=48, state="readonly").grid(row=0, column=1, padx=5, pady=8)
        ttk.Button(f, text="Mở...",
                   command=lambda: (
                       p := filedialog.askopenfilename(filetypes=[("PDF","*.pdf")]),
                       self.v_pdf.set(p) if p else None)
                   ).grid(row=0, column=2)

        ttk.Label(f, text=(
            "ℹ️  Không cần Public Key riêng — chứng thư X.509 đã được nhúng\n"
            "    trực tiếp vào file PDF theo chuẩn CMS/PKCS#7 của PAdES."
        ), foreground="#15100c0", font=("Helvetica", 9, "italic"),
           wraplength=570).grid(row=1, column=0, columnspan=3, sticky="w", pady=8)

        self.v_result = ttk.Label(f,
            text="Vui lòng chọn file PDF đã ký để bắt đầu xác thực.",
            foreground="#555", justify="left", wraplength=580,
            font=("Helvetica", 10, "italic"))
        self.v_result.grid(row=2, column=0, columnspan=3, sticky="nsew", pady=15)

        ttk.Button(f, text="🔍  Xác Thực Chữ Ký Số PAdES",
                   style="Action.TButton",
                   command=self._do_verify).grid(row=3, column=0, columnspan=3, pady=5)

    def _do_verify(self):
        pdf = self.v_pdf.get()
        if not pdf:
            messagebox.showwarning("Thiếu thông tin", "Vui lòng chọn file PDF cần xác thực!")
            return
        try:
            self.status_var.set("Đang xác thực Byte-Range và CMS...")
            self.root.update_idletasks()
            ok, title, details = verify_pdf_file(pdf)
            color = "#1b5e20" if ok else "#b71c1c"
            self.v_result.config(
                text=f"{title}\n\n{details}",
                foreground=color,
                font=("Helvetica", 10, "normal"),
            )
            self.status_var.set("Xác thực hoàn tất: " + ("HỢP LỆ ✅" if ok else "KHÔNG HỢP LỆ ❌"))
        except Exception as e:
            self.v_result.config(text=f"Lỗi xác thực: {e}", foreground="#b71c1c")
            self.status_var.set("Xác thực thất bại do lỗi!")


# =============================================================================
# PHẦN 7: GIAO DIỆN DÒNG LỆNH TƯƠNG TÁC (Interactive CLI)
# =============================================================================

def interactive_cli():
    """
    Giao diện CLI tương tác — dự phòng khi Tkinter không khả dụng
    (môi trường server, Docker, SSH không có X11...).
    """
    print("\n" + "=" * 72)
    print("  HỆ THỐNG KÝ SỐ PDF CHUẨN PAdES — CHẾ ĐỘ DÒNG LỆNH TƯƠNG TÁC")
    print("=" * 72)
    print("[!] Tkinter GUI không khả dụng — chuyển sang chế độ CLI.")

    while True:
        print("\n" + "-" * 50)
        print("CHỨC NĂNG:")
        print("  1. 🔑  Tạo Khóa RSA + Chứng Thư X.509")
        print("  2. ✍️   Ký Số PDF (PAdES Byte-Range)")
        print("  3. 🔍  Xác Thực Chữ Ký Số PAdES")
        print("  4. 🚪  Thoát")
        print("-" * 50)

        choice = input("Nhập lựa chọn (1-4): ").strip()

        if choice == "1":
            print("\n── TẠO KHÓA & CHỨNG THƯ X.509 ──")
            cn       = input("Họ tên (Common Name) [Nguyen Van A]: ").strip() or "Nguyen Van A"
            org      = input("Tổ chức (Organization) [Cong ty ABC]: ").strip() or "Cong ty ABC"
            country  = (input("Mã quốc gia (2 ký tự) [VN]: ").strip() or "VN")[:2].upper()
            days_str = input("Thời hạn chứng thư (ngày) [730]: ").strip() or "730"
            size_str = input("Độ dài khóa RSA: 2048 / 4096 [2048]: ").strip() or "2048"
            passw    = input("Mật khẩu bảo vệ Private Key (Enter = không có): ").strip()
            save_dir = input("Thư mục lưu file [.]: ").strip() or "."
            try:
                priv, cert = generate_identity_and_cert(
                    key_size=int(size_str) if size_str in ("2048","4096") else 2048,
                    common_name=cn, organization=org, country=country,
                    valid_days=int(days_str), passphrase=passw, save_dir=save_dir,
                )
                print(f"\n✅ Thành công!")
                print(f"   Private Key  : {os.path.abspath(priv)}")
                print(f"   Certificate  : {os.path.abspath(cert)}")
            except Exception as e:
                print(f"❌ Lỗi: {e}")

        elif choice == "2":
            print("\n── KÝ SỐ PDF (PAdES) ──")
            pdf  = input("Đường dẫn file PDF gốc: ").strip().strip("'\"")
            if not os.path.exists(pdf):
                print("❌ File PDF không tồn tại!"); continue
            key  = input("Đường dẫn Private Key (.pem): ").strip().strip("'\"")
            if not os.path.exists(key):
                print("❌ File Private Key không tồn tại!"); continue
            cert = input("Đường dẫn Certificate (.crt/.pem): ").strip().strip("'\"")
            if not os.path.exists(cert):
                print("❌ File Certificate không tồn tại!"); continue
            passw = input("Mật khẩu Private Key (Enter = không có): ").strip()

            dn, fn = os.path.split(pdf); nm, ex = os.path.splitext(fn)
            default_out = os.path.join(dn, f"{nm}_signed_pades{ex}")
            out = input(f"File đầu ra [{default_out}]: ").strip().strip("'\"") or default_out

            vis = (input("Chữ ký trực quan? (y/n) [y]: ").strip().lower() or "y") == "y"
            page_str = pos_preset = "last"
            cx = cy = 0.0; w = 170.0; h = 100.0
            sig_name = reason = ""
            text_lines = []
            if vis:
                page_str = input("Trang ký ('last' hoặc số) [last]: ").strip() or "last"
                print("Vị trí: 1=Bottom-Right  2=Bottom-Left  3=Top-Right  4=Top-Left  5=Custom")
                pm = {"1":"Bottom-Right","2":"Bottom-Left","3":"Top-Right","4":"Top-Left","5":"Custom"}
                pos_preset = pm.get(input("Chọn (1-5) [1]: ").strip(), "Bottom-Right")
                if pos_preset == "Custom":
                    cx = float(input("Tọa độ X: ").strip() or "100")
                    cy = float(input("Tọa độ Y: ").strip() or "100")
                w = float(input("Chiều rộng khung [170]: ").strip() or "170")
                h = float(input("Chiều cao khung [100]: ").strip() or "100")
            sig_name = input("Tên người ký [Nguyen Van A]: ").strip() or "Nguyen Van A"
            reason   = input("Lý do ký [Ky duyet tai lieu]: ").strip() or "Ky duyet tai lieu"
            now_str  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if vis:
                text_lines = [
                    "CHU KY SO PADES HOP LE",
                    f"Nguoi ky: {remove_vietnamese_accents(sig_name)}",
                    f"Ly do: {remove_vietnamese_accents(reason)}",
                    f"Ngay ky: {now_str}",
                    "RSA-PSS + SHA-256 (PAdES)",
                ]
            try:
                info = sign_pdf_file(
                    pdf_path=pdf, key_path=key, cert_path=cert,
                    passphrase=passw, out_path=out,
                    visible=vis, page_str=page_str, pos_preset=pos_preset,
                    custom_x=cx, custom_y=cy, width=w, height=h,
                    text_lines=text_lines, signer_name=sig_name, reason=reason,
                )
                print(f"\n✅ Ký số PAdES thành công!")
                print(f"   File đầu ra : {info['output_path']}")
                print(f"   Thời gian   : {info['sign_time']}")
                print(f"   Kích thước  : {info['file_size_kb']} KB")
            except Exception as e:
                print(f"❌ Lỗi ký số: {e}")

        elif choice == "3":
            print("\n── XÁC THỰC CHỮ KÝ PAdES ──")
            pdf = input("Đường dẫn file PDF đã ký: ").strip().strip("'\"")
            if not os.path.exists(pdf):
                print("❌ File không tồn tại!"); continue
            try:
                ok, title, details = verify_pdf_file(pdf)
                sym = "✅" if ok else "❌"
                print(f"\n{sym * 30}")
                print(f"  {title}")
                print(f"\n{details}")
                print(f"{sym * 30}")
            except Exception as e:
                print(f"❌ Lỗi xác thực: {e}")

        elif choice == "4":
            print("Tạm biệt!")
            break
        else:
            print("❌ Lựa chọn không hợp lệ!")


# =============================================================================
# PHẦN 8: GIAO DIỆN DÒNG LỆNH ARGPARSE (Non-Interactive CLI)
# =============================================================================

def main_cli():
    """
    CLI phi tương tác với argparse — dùng cho tự động hóa / scripting.
    Ví dụ:
        python pdf_signer_pades.py keygen --cn "Nguyen Van A" --org "ABC" --outdir ./keys
        python pdf_signer_pades.py sign --pdf doc.pdf --key ./keys/private_key.pem \\
                                        --cert ./keys/certificate.crt --visible --out signed.pdf
        python pdf_signer_pades.py verify --pdf signed.pdf
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="Ký số PDF chuẩn PAdES / ISO 32000-1 (RSA-PSS + X.509)")
    sub = parser.add_subparsers(dest="cmd")

    # ── keygen ──
    kg = sub.add_parser("keygen", help="Sinh khóa RSA + chứng thư X.509 tự ký")
    kg.add_argument("--cn",         default="Nguyen Van A",    help="Common Name (tên người ký)")
    kg.add_argument("--org",        default="Cong ty ABC",     help="Organization")
    kg.add_argument("--country",    default="VN",              help="Mã quốc gia (2 ký tự)")
    kg.add_argument("--days",       type=int, default=730,     help="Thời hạn chứng thư (ngày)")
    kg.add_argument("--size",       type=int, choices=[2048,4096], default=2048)
    kg.add_argument("--passphrase", default="",                help="Mật khẩu bảo vệ Private Key")
    kg.add_argument("--outdir",     default=".",               help="Thư mục lưu kết quả")

    # ── sign ──
    sg = sub.add_parser("sign", help="Ký số PDF theo chuẩn PAdES Byte-Range")
    sg.add_argument("--pdf",        required=True,             help="File PDF gốc")
    sg.add_argument("--key",        required=True,             help="Private Key (.pem)")
    sg.add_argument("--cert",       required=True,             help="Certificate (.crt/.pem)")
    sg.add_argument("--passphrase", default="",                help="Mật khẩu Private Key")
    sg.add_argument("--out",        default=None,              help="File PDF đầu ra")
    sg.add_argument("--visible",    action="store_true",       help="Vẽ khung chữ ký trực quan")
    sg.add_argument("--page",       default="last",            help="Trang ký ('last' hoặc số)")
    sg.add_argument("--pos",        default="Bottom-Right",
                    choices=["Bottom-Right","Bottom-Left","Top-Right","Top-Left","Custom"])
    sg.add_argument("--cx",         type=float, default=100.0)
    sg.add_argument("--cy",         type=float, default=100.0)
    sg.add_argument("--width",      type=float, default=170.0)
    sg.add_argument("--height",     type=float, default=100.0)
    sg.add_argument("--name",       default="Nguyen Van A",    help="Tên người ký")
    sg.add_argument("--reason",     default="Ky duyet tai lieu")

    # ── verify ──
    vf = sub.add_parser("verify", help="Xác thực chữ ký PAdES trong PDF")
    vf.add_argument("--pdf", required=True)

    args = parser.parse_args()

    if args.cmd == "keygen":
        try:
            priv, cert = generate_identity_and_cert(
                key_size=args.size, common_name=args.cn, organization=args.org,
                country=args.country, valid_days=args.days,
                passphrase=args.passphrase, save_dir=args.outdir,
            )
            print(f"SUCCESS: Keys generated.")
            print(f"  Private key : {os.path.abspath(priv)}")
            print(f"  Certificate : {os.path.abspath(cert)}")
        except Exception as e:
            print(f"ERROR: {e}"); sys.exit(1)

    elif args.cmd == "sign":
        out = args.out
        if not out:
            d, fn = os.path.split(args.pdf); nm, ex = os.path.splitext(fn)
            out = os.path.join(d, f"{nm}_signed_pades{ex}")
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        tl = [
            "CHU KY SO PADES HOP LE",
            f"Nguoi ky: {remove_vietnamese_accents(args.name)}",
            f"Ly do: {remove_vietnamese_accents(args.reason)}",
            f"Ngay ky: {now_str}",
            "RSA-PSS + SHA-256 (PAdES)",
        ] if args.visible else []
        try:
            info = sign_pdf_file(
                pdf_path=args.pdf, key_path=args.key, cert_path=args.cert,
                passphrase=args.passphrase, out_path=out,
                visible=args.visible, page_str=args.page, pos_preset=args.pos,
                custom_x=args.cx, custom_y=args.cy, width=args.width, height=args.height,
                text_lines=tl, signer_name=args.name, reason=args.reason,
            )
            print(f"SUCCESS: PDF signed (PAdES).")
            print(f"  Output    : {info['output_path']}")
            print(f"  Sign time : {info['sign_time']}")
            print(f"  Size      : {info['file_size_kb']} KB")
        except Exception as e:
            print(f"ERROR: {e}"); sys.exit(1)

    elif args.cmd == "verify":
        try:
            ok, title, details = verify_pdf_file(args.pdf)
            status = "VALID" if ok else "INVALID"
            print(f"VERIFICATION: {status}")
            print(f"  {title}")
            print(f"\n{details}")
            if not ok:
                sys.exit(2)
        except Exception as e:
            print(f"ERROR: {e}"); sys.exit(1)

    else:
        parser.print_help()


# =============================================================================
# ENTRYPOINT
# =============================================================================

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Chế độ CLI phi tương tác (argparse)
        main_cli()
    else:
        if _HAS_TK:
            try:
                root = tk.Tk()
                app  = PDFSignerApp(root)
                root.mainloop()
            except Exception:
                interactive_cli()
        else:
            interactive_cli()
