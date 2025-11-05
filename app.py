import os, base64, uuid, mimetypes, pathlib, secrets, smtplib
from datetime import datetime, timezone, timedelta
from functools import wraps
from email.message import EmailMessage
from sqlalchemy import or_, asc, desc
import re
from markupsafe import Markup, escape
from urllib.parse import urlencode, quote
import json
from flask import current_app
from jinja2 import TemplateNotFound
from sqlalchemy.orm import joinedload

from io import BytesIO
from reportlab.lib.units import inch

# ===== Azure Blob (preferencial) =====
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient, BlobSasPermissions, generate_blob_sas

from flask import (
    Flask, request, render_template, render_template_string,
    jsonify, send_from_directory, send_file, redirect, url_for,
    flash, abort, make_response
)
from dotenv import load_dotenv
from werkzeug.utils import secure_filename, safe_join

# DB / Models
from extensions import db
from models import Client, Contract, AccessRequest, User, Asset, ContractTemplate, ClientContractPref, AssetReview

# Auth
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)

# PDF (ReportLab)
try:
    from reportlab.lib.pagesizes import LETTER
    from reportlab.pdfgen import canvas as rl_canvas
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.utils import ImageReader
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

# Thumbnails
try:
    from PIL import Image
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

# Tokens (onboarding e set-password)
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# -------------------------------------------------
# Azure Blob – configuração (opcional, com fallback local)
# -------------------------------------------------
ACCOUNT = os.environ.get("AZURE_STORAGE_ACCOUNT")  # ex.: "strgportal4uitmkt"
CONTAINER = os.environ.get("AZURE_BLOB_CONTAINER", "uploads")

blob_service = None
container_client = None

if ACCOUNT:
    try:
        cred = DefaultAzureCredential(exclude_shared_token_cache_credential=True)
        blob_service = BlobServiceClient(
            f"https://{ACCOUNT}.blob.core.windows.net", credential=cred
        )
        container_client = blob_service.get_container_client(CONTAINER)
        try:
            container_client.create_container()  # idempotente
        except Exception:
            pass
    except Exception:
        # Não falhar o app; seguimos com armazenamento local
        blob_service = None
        container_client = None


# --------- HÍBRIDO: salvar arquivo local OU no Azure e gerar URL pública ---------
USE_BLOB = bool(blob_service and container_client)

def _store_file(bytes_data: bytes, rel_path: str, content_type: str | None = None) -> str:
    """
    Salva o arquivo:
      - Se Azure Blob ativo: sobe em <CONTAINER>/<rel_path> e retorna 'blob:<rel_path>'
      - Senão: salva em UPLOAD_ROOT/<rel_path> e retorna 'uploads/<rel_path>'
    rel_path deve ser relativo à raiz lógica de uploads (ex.: 'assets/abc.jpg', 'assets/thumbs/abc.jpg').
    """
    rel = rel_path.lstrip("/").replace("\\", "/")
    if USE_BLOB:
        try:
            bc = container_client.get_blob_client(rel)
            bc.upload_blob(bytes_data, overwrite=True, content_type=content_type or "application/octet-stream")
            return f"blob:{rel}"
        except Exception as e:
            # fallback local se der ruim no blob
            pass

    # LOCAL
    abs_path = os.path.join(UPLOAD_ROOT, rel)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    with open(abs_path, "wb") as f:
        f.write(bytes_data)
    return f"uploads/{rel}"


def _public_url(ref: str | None, minutes: int = 30) -> str | None:
    """
    Converte o valor armazenado no modelo (ex.: 'blob:assets/xyz.jpg' ou 'uploads/assets/xyz.jpg')
    em uma URL pública consumível no front.

    - 'blob:...' -> gera SAS temporário
    - 'uploads/...' -> retorna '/uploads/...'
    - qualquer outro valor -> tenta inferir
    """
    if not ref:
        return None
    ref = ref.replace("\\", "/").lstrip("/")
    if ref.startswith("blob:"):
        if not USE_BLOB:
            return None
        blob_name = ref.split("blob:", 1)[1]
        try:
            # Reaproveita seu gerador SAS
            return make_sas_url(blob_name, minutes=minutes)
        except Exception:
            return None
    if ref.startswith("uploads/"):
        return "/" + ref
    # Fallback: caso já venha só 'assets/...'
    if ref.startswith("assets/"):
        return "/uploads/" + ref
    return "/" + ref


def _guess_mime(filename: str, fallback: str = "application/octet-stream") -> str:
    ctype, _ = mimetypes.guess_type(filename)
    return ctype or fallback


def _portal_find_client_for_user():
    if not current_user.is_authenticated:
        return None
    user_email = (current_user.email or "").strip().lower()

    # 1) Client.contact_email === user.email
    c = Client.query.filter(db.func.lower(Client.contact_email) == user_email).first()
    if c:
        return c

    # 2) Client via Contract.signer_email === user.email
    ct = (Contract.query
          .options(joinedload(Contract.client))
          .filter(db.func.lower(Contract.signer_email) == user_email)
          .order_by(Contract.signed_at.desc())
          .first())
    if ct and ct.client:
        return ct.client

    # 3) Client via AccessRequest.signer_email === user.email (caso ainda não tenha contrato)
    ar = (AccessRequest.query
          .options(joinedload(AccessRequest.client))
          .filter(db.func.lower(AccessRequest.signer_email) == user_email)
          .order_by(AccessRequest.submitted_at.desc())
          .first())
    if ar and ar.client:
        return ar.client

    return None

def save_dataurl_png_to_blob(data_url: str, folder="signatures") -> str:
    """
    Salva dataURL PNG no Azure Blob (se configurado).
    Retorna o blob_name (ex.: 'signatures/abc.png').
    Lança exceção se blob não estiver disponível.
    """
    if not (blob_service and container_client):
        raise RuntimeError("Azure Blob não configurado.")
    if not data_url.startswith("data:image/png;base64,"):
        raise ValueError("Assinatura inválida: formato não suportado")
    b64 = data_url.split(",", 1)[1]
    raw = base64.b64decode(b64)
    blob_name = f"{folder}/{uuid.uuid4().hex}.png"
    blob = container_client.get_blob_client(blob_name)
    blob.upload_blob(raw, overwrite=True, content_type="image/png")
    return blob_name


def make_sas_url(blob_name: str, minutes: int = 15) -> str:
    """
    Gera SAS temporário (User Delegation SAS) para leitura.
    Requer blob_service configurado com identidade gerenciada.
    """
    if not blob_service:
        raise RuntimeError("Azure Blob não configurado para SAS.")
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=5)
    expiry = now + timedelta(minutes=minutes)
    udk = blob_service.get_user_delegation_key(start, expiry)
    sas = generate_blob_sas(
        account_name=ACCOUNT,
        container_name=CONTAINER,
        blob_name=blob_name,
        user_delegation_key=udk,
        permission=BlobSasPermissions(read=True),
        expiry=expiry,
        start=start,
    )
    return f"https://{ACCOUNT}.blob.core.windows.net/{CONTAINER}/{blob_name}?{sas}"

def _draw_kv(c, y, k, v):
    c.setFont("Helvetica-Bold", 10)
    c.drawString(72, y, f"{k}:")
    c.setFont("Helvetica", 10)
    c.drawString(72 + 140, y, (v or "-"))

def generate_accessrequest_pdf(access: AccessRequest) -> bytes:
    buf = BytesIO()
    c = rl_canvas.Canvas(buf, pagesize=LETTER)
    width, height = LETTER

    y = height - 72
    c.setFont("Helvetica-Bold", 14)
    c.drawString(72, y, "Access Information (Ads / Analytics / Domain / Hosting)")
    y -= 18
    c.setFont("Helvetica", 10)
    c.drawString(72, y, f"Client: {access.client.company_name if access.client else '-'}")
    y -= 24

    fields = [
        ("Instagram", access.instagram_user),
        ("Facebook Page", access.facebook_page),
        ("Meta BM ID", access.meta_bm_id),
        ("Meta Ads Account", access.meta_ads_account_id),
        ("Google Ads ID", access.google_ads_id),
        ("Analytics", "Yes" if access.analytics else "No"),
        ("Tag Manager", "Yes" if access.tag_manager else "No"),
        ("Search Console", "Yes" if access.search_console else "No"),
        ("Website", access.website_url),
        ("Hosting", access.hosting),
        ("Hosting Login", access.hosting_login),
        ("Hosting Password", access.hosting_password),
        ("Domain Registrar", access.domain_registrar),
        ("Domain Login", access.domain_login),
        ("Domain Password", access.domain_password),
        ("Brand Notes", (access.brand_notes or "")[:500]),
        ("Submitted at (UTC)", str(access.submitted_at) if access.submitted_at else "-"),
        ("Signer", f"{access.signer_name or '-'} <{access.signer_email or '-'}>"),
        ("IP", access.signer_ip),
        ("User-Agent", (access.user_agent or "")[:250]),
    ]

    for k, v in fields:
        if y < 96:
            c.showPage()
            y = height - 72
        _draw_kv(c, y, k, v)
        y -= 16

    c.showPage()
    c.save()
    buf.seek(0)
    return buf.read()


# -------------------------------------------------
# App & Config
# -------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

app = Flask(
    __name__,
    static_folder="static",
    template_folder="templates",
    instance_path=os.path.join(BASE_DIR, "instance"),
)
os.makedirs(app.instance_path, exist_ok=True)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev")
# DATABASE — prioriza Postgres do .env; se não houver, cai no SQLite em instance/
db_url = (os.getenv("DATABASE_URL") or "").strip()

# Corrige URLs antigas "postgres://..." para o driver atual "postgresql+psycopg://"
if db_url.startswith("postgres://"):
    db_url = "postgresql+psycopg://" + db_url[len("postgres://"):]

if db_url:
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(app.instance_path, "app.db")

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Log simples pra confirmar no console o que entrou
try:
    print("[DB] SQLALCHEMY_DATABASE_URI ->", app.config["SQLALCHEMY_DATABASE_URI"])
except Exception:
    pass


app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100MB

from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config["PREFERRED_URL_SCHEME"] = "https"

# --- Upload roots (persist on Azure App Service) ---
UPLOAD_ROOT = os.environ.get("UPLOAD_ROOT", os.path.join(BASE_DIR, "uploads"))
os.makedirs(UPLOAD_ROOT, exist_ok=True)

UPLOAD_SIGS_DIR = os.path.join(UPLOAD_ROOT, "signatures")
UPLOAD_ASSETS_DIR = os.path.join(UPLOAD_ROOT, "assets")
UPLOAD_ASSETS_THUMBS_DIR = os.path.join(UPLOAD_ASSETS_DIR, "thumbs")
UPLOAD_CONTRACTS_DIR = os.path.join(UPLOAD_ROOT, "contracts")
ACCESS_SIGS_DIR = os.path.join(UPLOAD_ROOT, "access_signatures")
TMP_DIR = os.path.join(UPLOAD_ROOT, "tmp")

for p in (UPLOAD_SIGS_DIR, UPLOAD_ASSETS_DIR, UPLOAD_ASSETS_THUMBS_DIR, UPLOAD_CONTRACTS_DIR, ACCESS_SIGS_DIR, TMP_DIR):
    os.makedirs(p, exist_ok=True)

ASSETS_DIR = UPLOAD_ASSETS_DIR  # alias

# DB
db.init_app(app)

# Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id: str):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None


def seed_admin():
    email = os.getenv("ADMIN_EMAIL")
    pwd = os.getenv("ADMIN_PASSWORD")
    name = os.getenv("ADMIN_NAME", "4UIT Admin")
    if not email or not pwd:
        return
    if not User.query.filter_by(email=email).first():
        u = User(name=name, email=email, role="admin")
        u.set_password(pwd)
        db.session.add(u)
        db.session.commit()


def seed_default_contract_template():
    if ContractTemplate.query.count() == 0:
        default_body = """4UIT SOLUTIONS LLC — MASTER SERVICES AGREEMENT (MSA)
Effective on the date of e-signature below (“Effective Date”).

1) Parties.
This Agreement is between 4UIT Solutions LLC (“Provider”, “4UIT”) and the client identified in the signature block (“Client”).

2) Services & Deliverables.
Provider will perform professional services that may include: marketing strategy, creative/content production, paid media (Google/Meta/TikTok/etc.), landing pages, websites and web/mobile app development, analytics/BI, and related growth services (the “Services”). Specific deliverables, timelines, KPIs and add-ons will be detailed in a Statement of Work (“SOW”).

3) Term.
Month-to-month unless stated otherwise in SOW, auto-renewing monthly.

4) Fees & Invoicing.
As per SOW. Invoices monthly in advance, NET 7. Out-of-pocket above US$100 with prior approval.

5) Client Responsibilities.
Provide timely access to accounts/materials and comply with platform policies.

6) Approvals & Posting.
Approvals via e-mail, portal, or review link authorize posting/scheduling.

7) IP.
Client owns paid-for work product; 4UIT retains pre-existing tools/libraries with license to Client as embedded.

8) Confidentiality & Data.
2-year confidentiality (trade secrets while secret). 4UIT aplica práticas razoáveis de segurança.

9) Disclaimers.
Services “AS IS”; mídia paga depende de terceiros/mercado.

10) Liability Cap.
Até os fees pagos nos 2 meses anteriores ao claim.

11) Termination.
30 dias por conveniência; 10 dias para cura em caso de breach.

12) Non-Solicitation.
12 meses após o término.

13) Compliance.
Cliente responsável por regulamentações e políticas de anúncios.

14) Governing Law.
Florida; Orange County.

15) Entire Agreement.
MSA + SOW.
"""
        t = ContractTemplate(name="Default MSA (EN/PT mix)", body=default_body, is_default=True)
        db.session.add(t)
        db.session.commit()


with app.app_context():
    db.create_all()
    seed_admin()
    seed_default_contract_template()


# === Azure base opcional para blobs públicos ===============================
AZURE_BLOB_PUBLIC_BASE = (os.environ.get("AZURE_BLOB_PUBLIC_BASE") or "").strip()

# === Helper de URL pública para assets =====================================


def asset_public_url(a):
    """
    Retorna URL pública do asset:
    - external_url (se existir)
    - Azure Blob (se AZURE_BLOB_PUBLIC_BASE estiver setado)
    - Rotas locais /uploads/assets/... (file/thumb)
    - Fallback para sua rota genérica serve_uploads
    """
    if not a:
        return None

    ext_url = getattr(a, "external_url", None)
    if ext_url:
        return ext_url

    rel = (getattr(a, "storage_path", "") or "").replace("\\", "/")
    if not rel:
        return None

    # Normaliza chave removendo o prefixo 'uploads/'
    key = rel[8:] if rel.startswith("uploads/") else rel  # ex.: 'assets/xxx.mp4'

    # Azure público
    if AZURE_BLOB_PUBLIC_BASE:
        return f"{AZURE_BLOB_PUBLIC_BASE.rstrip('/')}/{key.lstrip('/')}"

    # Local — preferir rotas específicas
    if key.startswith("assets/thumbs/"):
        fname = key.split("/", 2)[-1]
        return url_for("serve_asset_thumb", filename=fname)

    if key.startswith("assets/"):
        fname = key.split("/", 1)[-1]
        return url_for("serve_asset_file", filename=fname)

    # Fallback: usa sua rota genérica existente
    return url_for("serve_uploads", filename=rel)

# Registra nos globais do Jinja (garante disponibilidade)
app.add_template_global(asset_public_url, name="asset_public_url")

# E como context_processor (redundante de propósito — evita ordem de import)
@app.context_processor
def _inject_asset_helpers():
    return dict(asset_public_url=asset_public_url)

# ------------------ Email ------------------
SMTP_HOST = os.getenv("SMTP_HOST", os.getenv("SMTP_SERVER", "smtp.office365.com"))
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_TLS = (os.getenv("SMTP_TLS", "true").lower() != "false")
SMTP_FROM = os.getenv("SMTP_FROM") or SMTP_USER or "no-reply@4uit.us"
EMAIL_BCC = os.getenv("EMAIL_BCC")  # optional


def _split_emails(s: str | None):
    if not s:
        return []
    return [x.strip() for x in s.split(",") if x.strip()]


def _env(key, default=None):
    return os.environ.get(key, default)


def _send_email_fallback(subject: str, html: str, to: list[str] | str,
                         bcc: list[str] | str | None = None,
                         text: str | None = None):
    if isinstance(to, str):
        to = [to]
    if bcc and isinstance(bcc, str):
        bcc = [bcc]

    msg = EmailMessage()
    msg["From"] = _env("SMTP_FROM", _env("SMTP_USER", ""))
    msg["To"]   = ", ".join([t for t in to if t])
    if bcc:
        msg["Bcc"] = ", ".join([b for b in bcc if b])
    msg["Subject"] = subject

    if not text:
        text = (html.replace("<br>", "\n")
                   .replace("<br/>", "\n")
                   .replace("<br />", "\n")
                   .replace("&nbsp;", " "))

    msg.set_content(text)
    msg.add_alternative(html, subtype="html")

    host = _env("SMTP_HOST", "smtp.gmail.com")
    port = int(_env("SMTP_PORT", "587"))
    user = _env("SMTP_USER", "")
    pwd  = _env("SMTP_PASSWORD", "")

    with smtplib.SMTP(host, port) as s:
        s.set_debuglevel(0)
        s.starttls()
        if user:
            s.login(user, pwd)
        s.send_message(msg)


def _html_to_text(html: str) -> str:
    return (html or "").replace("<br>", "\n").replace("<br/>", "\n").replace("<br />", "\n").replace("&nbsp;", " ")


def send_email(subject: str, text_body: str, html_body: str,
               to_addrs: list[str], cc_addrs: list[str] | None = None,
               attachments: list[tuple[str, str]] | None = None):
    if not (SMTP_HOST and SMTP_USER and SMTP_PASSWORD):
        raise RuntimeError("SMTP not configured (.env).")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(to_addrs)
    if cc_addrs:
        msg["Cc"] = ", ".join(cc_addrs)
    bcc_list = _split_emails(EMAIL_BCC)
    all_rcpts = list(to_addrs) + (cc_addrs or []) + bcc_list

    msg.set_content(text_body or "")
    if html_body:
        msg.add_alternative(html_body, subtype="html")

    for abs_path, filename in (attachments or []):
        ctype, _ = mimetypes.guess_type(abs_path)
        maintype, subtype = (ctype.split("/", 1) if ctype else ("application", "octet-stream"))
        with open(abs_path, "rb") as f:
            msg.add_attachment(f.read(), maintype=maintype, subtype=subtype, filename=filename)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
        s.ehlo()
        if SMTP_TLS:
            s.starttls()
        s.login(SMTP_USER, SMTP_PASSWORD)
        s.send_message(msg, from_addr=SMTP_FROM, to_addrs=all_rcpts)


# -------------------------------------------------
# Helpers
# -------------------------------------------------
def utcnow():
    return datetime.now(timezone.utc)


def get_request_ip():
    forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    return forwarded or request.remote_addr or "0.0.0.0"


# ======= Assinatura: fallback local legado =======
def save_signature_data_url(data_url: str) -> str:
    """
    Salva o dataURL da assinatura em uploads/signatures/<uuid>.png
    e já NORMALIZA para traço preto + fundo transparente.
    Retorna o caminho relativo público (uploads/signatures/arquivo.png).
    """
    if not data_url.startswith("data:image"):
        raise ValueError("Invalid signature data URL")

    header, b64data = data_url.split(",", 1)
    # sempre salva como PNG (independente do header)
    filename = f"{uuid.uuid4().hex}.png"
    rel_path = os.path.join("uploads", "signatures", filename)
    abs_path = os.path.join(UPLOAD_SIGS_DIR, filename)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)

    with open(abs_path, "wb") as f:
        f.write(base64.b64decode(b64data))

    # normaliza pra preto e fundo transparente
    try:
        norm_path = normalize_signature_png(abs_path)
        if norm_path and os.path.abspath(norm_path) != os.path.abspath(abs_path):
            try:
                os.replace(norm_path, abs_path)
            except Exception:
                pass
    except Exception:
        pass

    return rel_path


def save_signature_unified(data_url: str) -> dict:
    """
    Tenta salvar no Azure Blob. Se indisponível, salva local.
    Retorna dict:
      { "blob_name": str|None, "local_relpath": str|None }
    """
    # Preferencial: Blob
    if blob_service and container_client:
        try:
            blob_name = save_dataurl_png_to_blob(data_url, folder="signatures")
            return {"blob_name": blob_name, "local_relpath": None}
        except Exception:
            pass
    # Fallback: local
    rel = save_signature_data_url(data_url)
    return {"blob_name": None, "local_relpath": rel}


def _normalize_signature_image(abs_path: str) -> None:
    try:
        from PIL import Image, ImageOps, ImageStat
        g = Image.open(abs_path).convert("L")
        mean = ImageStat.Stat(g).mean[0]
        if mean < 128:
            g = ImageOps.invert(g)
        alpha = ImageOps.invert(g)
        alpha = alpha.point(lambda p: 0 if p < 16 else (255 if p > 220 else p))
        from PIL import Image as _PIL
        rgba = _PIL.new("RGBA", g.size, (0, 0, 0, 0))
        black = _PIL.new("RGBA", g.size, (0, 0, 0, 255))
        rgba.paste(black, (0, 0), mask=alpha)
        rgba.save(abs_path, "PNG")
    except Exception:
        pass


def is_safe_next(next_url: str) -> bool:
    return bool(next_url and next_url.startswith("/"))


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapper(*args, **kwargs):
        if getattr(current_user, "role", None) != "admin":
            flash("You must be admin to access this area.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def _allowed_ext(name: str) -> bool:
    ext = (name.rsplit(".", 1)[-1] or "").lower()
    return ext in {"png", "jpg", "jpeg", "gif", "webp", "mp4", "mov", "webm", "pdf", "mkv"}


def _is_image(mime: str, ext: str) -> bool:
    return (mime or "").startswith("image/") or ext in {"png", "jpg", "jpeg", "gif", "webp"}


def _gen_thumb(src_path: str, thumb_path: str, max_size=(480, 480)):
    if not PIL_AVAILABLE:
        return
    try:
        with Image.open(src_path) as im:
            if im.mode == "P":
                try:
                    im = im.convert("RGBA")
                except Exception:
                    im = im.convert("RGB")
            elif im.mode not in ("RGB", "RGBA"):
                im = im.convert("RGBA" if "A" in im.getbands() else "RGB")

            im.thumbnail(max_size)
            if im.mode == "RGBA":
                from PIL import Image as _PILImage
                bg = _PILImage.new("RGB", im.size, (255, 255, 255))
                bg.paste(im, mask=im.split()[3])
                im = bg

            im.save(thumb_path, "JPEG", quality=82)
    except Exception as e:
        app.logger.warning("thumbnail generation failed: %s", e)


def ensure_public_token(asset: Asset):
    if not asset.public_token:
        asset.public_token = secrets.token_urlsafe(24)
        db.session.add(asset)


def _serializer(salt: str):
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt=salt)

def make_onboarding_token(client_id: int) -> str:
    return _serializer("4uit-onb").dumps({"cid": client_id})

def decode_onboarding_token(token: str, max_age_seconds: int = 60*60*24*14) -> dict:
    return _serializer("4uit-onb").loads(token, max_age=max_age_seconds)

def make_setpwd_token(email: str) -> str:
    return _serializer("4uit-setpwd").dumps({"email": email})

def decode_setpwd_token(token: str, max_age_seconds: int = 60*60*24*7) -> dict:
    return _serializer("4uit-setpwd").loads(token, max_age=max_age_seconds)


def normalize_signature_png(src_path: str) -> str:
    if not PIL_AVAILABLE:
        return src_path
    try:
        im = Image.open(src_path).convert("RGBA")
        px = im.load()
        w, h = im.size
        for y in range(h):
            for x in range(w):
                r, g, b, a = px[x, y]
                if a > 16:
                    px[x, y] = (0, 0, 0, 255)
                else:
                    px[x, y] = (255, 255, 255, 0)
        out_path = os.path.join(UPLOAD_SIGS_DIR, f"norm_{uuid.uuid4().hex}.png")
        im.save(out_path, "PNG")
        return out_path
    except Exception:
        return src_path


#=========Helpers assets del/edit======

# === Storage helpers: local e Azure Blob ===============================
def _storage_is_azure() -> bool:
    return bool(os.environ.get("AZURE_STORAGE_CONNECTION_STRING") and os.environ.get("AZURE_STORAGE_CONTAINER"))

def _azure_blob_client():
    from azure.storage.blob import BlobServiceClient  # pip install azure-storage-blob
    conn_str = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
    return BlobServiceClient.from_connection_string(conn_str)

def _blob_container_name() -> str:
    return os.environ.get("AZURE_STORAGE_CONTAINER")

def _blob_name_from_rel(rel_path: str) -> str:
    # Mantém a mesma estrutura de caminho (ex.: 'uploads/assets/abc.png')
    return rel_path.replace("\\", "/").lstrip("/")

def _delete_storage_file(rel_path: str) -> None:
    """Remove um arquivo do storage (local ou Azure). Ignora silenciosamente se não existir."""
    if not rel_path:
        return
    try:
        if _storage_is_azure():
            try:
                bsc = _azure_blob_client()
                container = _blob_container_name()
                blob_name = _blob_name_from_rel(rel_path)
                bsc.get_container_client(container).delete_blob(blob_name)
            except Exception:
                # Se der 'BlobNotFound' ou similar, apenas ignoramos
                pass
        else:
            abs_path = os.path.join(BASE_DIR, rel_path)
            if os.path.exists(abs_path):
                os.remove(abs_path)
    except Exception:
        app.logger.exception("Falha ao remover arquivo do storage: %s", rel_path)



# ===== Helpers para PDF com Blob =====
def blob_to_temp_png(blob_name: str) -> str:
    tmp_path = os.path.join(TMP_DIR, f"{uuid.uuid4().hex}.png")
    bc = container_client.get_blob_client(blob_name)
    with open(tmp_path, "wb") as f:
        f.write(bc.download_blob().readall())
    return tmp_path


def contract_signature_abs_path(contract) -> str | None:
    # 1) Blob primeiro (se campo existir e azure estiver configurado)
    try:
        sig_blob = getattr(contract, "signature_blob", None)
    except Exception:
        sig_blob = None

    if sig_blob and blob_service and container_client:
        try:
            return blob_to_temp_png(sig_blob)
        except Exception:
            pass

    # 2) Legado local
    sig_rel = getattr(contract, "signature_path", None)
    if sig_rel:
        # procurar tanto em BASE_DIR/uploads quanto em UPLOAD_ROOT/signatures
        rel_name = os.path.basename(sig_rel)
        cand1 = os.path.join(BASE_DIR, sig_rel.replace("/", os.sep))
        cand2 = os.path.join(UPLOAD_SIGS_DIR, rel_name)
        if os.path.exists(cand1):
            return cand1
        if os.path.exists(cand2):
            return cand2

    return None


def _access_request_pdf_path(ar_id: int) -> str:
    folder = os.path.join(BASE_DIR, "uploads", "access_requests")
    os.makedirs(folder, exist_ok=True)
    return os.path.join(folder, f"access-request-{ar_id}.pdf")


def _header_pdf(canvas, title: str) -> float:
    PAGE_W, PAGE_H = LETTER
    MARGIN_L = 72
    MARGIN_R = 72
    MARGIN_T = 72
    LOGO_H = 28

    y_top = PAGE_H - MARGIN_T
    x = MARGIN_L
    logo_path = os.path.join(BASE_DIR, "static", "img", "4uit.png")

    logo_w = 0
    if os.path.exists(logo_path):
        try:
            img = ImageReader(logo_path)
            iw, ih = img.getSize()
            logo_w = int(LOGO_H * (iw / float(ih)))
            canvas.drawImage(
                img, x, y_top - LOGO_H,
                width=logo_w, height=LOGO_H,
                preserveAspectRatio=True, mask="auto"
            )
        except Exception:
            logo_w = 0

    canvas.setFont("Helvetica-Bold", 14)
    canvas.drawString(x + (logo_w + 10 if logo_w else 0), y_top - 2, title)
    y_line = y_top - LOGO_H - 6
    canvas.setLineWidth(0.5)
    canvas.setStrokeColorRGB(0.7, 0.7, 0.7)
    canvas.line(MARGIN_L, y_line, PAGE_W - MARGIN_R, y_line)
    canvas.setStrokeColorRGB(0, 0, 0)
    return y_line - 14

# (logo após _header_pdf)

FOOTER_TEXT = "4UIT Solutions LLC • 7362 Futures Dr, Bay 15, Orlando, FL 32819 • https://4uit.us • contact@4uit.us"

def _footer_pdf(canvas):
    """Desenha o rodapé padrão em todas as páginas."""
    from reportlab.lib.pagesizes import LETTER
    PAGE_W, PAGE_H = LETTER
    MARGIN_L = 72
    MARGIN_R = 72
    MARGIN_B = 48

    canvas.setLineWidth(0.3)
    canvas.setStrokeColorRGB(0.75, 0.75, 0.75)
    canvas.line(MARGIN_L, MARGIN_B + 12, PAGE_W - MARGIN_R, MARGIN_B + 12)
    canvas.setStrokeColorRGB(0, 0, 0)

    canvas.setFont("Helvetica", 9)
    # texto centralizado
    from reportlab.pdfbase.pdfmetrics import stringWidth
    w = stringWidth(FOOTER_TEXT, "Helvetica", 9)
    x = (PAGE_W - w) / 2.0
    canvas.drawString(x, MARGIN_B, FOOTER_TEXT)


def _wrap_lines_kv(canvas, key: str, value: str, y: float, max_width: float, font="Helvetica", size=10, bullet=True):
    from reportlab.pdfbase.pdfmetrics import stringWidth
    canvas.setFont(font, size)

    prefix = f"{key}: "
    bullet_txt = "• " if bullet else ""
    k_w = stringWidth(bullet_txt + prefix, font, size)
    words = (value or "").replace("\r\n", "\n").split(" ")
    cur = ""
    first_line = True
    for w in words:
        test = (cur + " " + w).strip()
        if stringWidth(test, font, size) <= (max_width - (k_w if first_line else 0)):
            cur = test
        else:
            if first_line:
                canvas.drawString(72, y, bullet_txt + prefix)
                canvas.drawString(72 + k_w, y, cur)
                first_line = False
            else:
                canvas.drawString(72, y, cur)
            y -= 14
            cur = w
    if first_line:
        canvas.drawString(72, y, bullet_txt + prefix)
        canvas.drawString(72 + k_w, y, cur)
    else:
        canvas.drawString(72, y, cur)
    return y - 14


def _generate_contract_pdf(contract) -> str | None:
    """
    Gera o PDF do contrato e salva em uploads/contracts.
    Retorna caminho absoluto ou None se indisponível.
    """
    if not REPORTLAB_AVAILABLE:
        return None
    try:
        from reportlab.pdfbase.pdfmetrics import stringWidth
        from reportlab.lib.utils import ImageReader
    except Exception:
        return None

    PAGE_W, PAGE_H = LETTER
    MARGIN_L = 72
    MARGIN_R = 72
    MARGIN_T = 72
    MARGIN_B = 72
    LINE = 14
    CONTENT_W = PAGE_W - MARGIN_L - MARGIN_R
    LOGO_H = 28

    FOOTER_TEXT = "4UIT Solutions LLC • 7362 Futures Dr, Bay 15, Orlando, FL 32819 • https://4uit.us • contact@4uit.us"
    logo_path = os.path.join(BASE_DIR, "static", "img", "4uit.png")

    def footer(cnv):
        cnv.saveState()
        try:
            cnv.setFont("Helvetica", 9)
            cnv.setFillGray(0.35)
            cnv.drawCentredString(PAGE_W / 2.0, 36, FOOTER_TEXT)
        finally:
            cnv.setFillGray(0)
            cnv.restoreState()

    def header(cnv, title="Master Services Agreement"):
        y_top = PAGE_H - MARGIN_T
        x = MARGIN_L
        logo_w = 0
        if os.path.exists(logo_path):
            try:
                img = ImageReader(logo_path)
                iw, ih = img.getSize()
                logo_w = int(LOGO_H * (iw / float(ih)))
                cnv.drawImage(
                    img,
                    x, y_top - LOGO_H,
                    width=logo_w, height=LOGO_H,
                    preserveAspectRatio=True, mask="auto",
                )
            except Exception:
                logo_w = 0

        cnv.setFont("Helvetica-Bold", 14)
        cnv.drawString(x + (logo_w + 10 if logo_w else 0), y_top - 2, title)
        y_line = y_top - LOGO_H - 6
        cnv.setLineWidth(0.5)
        cnv.setStrokeColorRGB(0.7, 0.7, 0.7)
        cnv.line(MARGIN_L, y_line, PAGE_W - MARGIN_R, y_line)
        cnv.setStrokeColorRGB(0, 0, 0)
        return y_line - 14  # y inicial do conteúdo

    def wrap_lines(text: str, font_name: str = "Helvetica", font_size: int = 10):
        out = []
        for raw in (text or "").replace("\r\n", "\n").split("\n"):
            words, cur = raw.split(" "), ""
            for w in words:
                test = (cur + " " + w).strip()
                if stringWidth(test, font_name, font_size) <= CONTENT_W:
                    cur = test
                else:
                    if cur:
                        out.append(cur)
                    cur = w
            out.append(cur)
        return out

    abs_path = _contract_pdf_path(contract.id)
    c = rl_canvas.Canvas(abs_path, pagesize=LETTER)

    # Página 1
    y = header(c)

    # Metadados
    c.setFont("Helvetica", 10)
    meta = [
        f"Contract ID: {contract.id}",
        f"Client: {contract.client.company_name if contract.client else '-'}",
        f"Signer: {contract.signer_name or '-'}",
        f"Email: {contract.signer_email or '-'}",
    ]
    if contract.signed_at:
        meta.append(f"Signed (UTC): {contract.signed_at.isoformat()}")
    if contract.signer_ip:
        meta.append(f"IP: {contract.signer_ip}")

    for line in meta:
        if y - LINE < MARGIN_B:
            footer(c); c.showPage()
            y = header(c, "4UIT Solutions — MSA (cont.)")
            c.setFont("Helvetica", 10)
        c.drawString(MARGIN_L, y, line)
        y -= LINE

    # Título “Contract text”
    y -= 6
    c.setFont("Helvetica-Bold", 11)
    if y - LINE < MARGIN_B:
        footer(c); c.showPage()
        y = header(c, "4UIT Solutions — MSA (cont.)")
    c.drawString(MARGIN_L, y, "Contract text:")
    y -= LINE

    # Corpo do contrato
    c.setFont("Helvetica", 10)
    for line in wrap_lines(contract.contract_text or ""):
        if y - LINE < MARGIN_B:
            footer(c); c.showPage()
            y = header(c, "4UIT Solutions — MSA (cont.)")
            c.setFont("Helvetica", 10)
        c.drawString(MARGIN_L, y, line)
        y -= LINE

    # Bloco da assinatura
    sig_w = min(CONTENT_W, 460)
    sig_h = 0
    sig_abs = contract_signature_abs_path(contract)
    if sig_abs:
        try:
            from PIL import Image as _PILImage
            sig_norm = normalize_signature_png(sig_abs)
            im = _PILImage.open(sig_norm)
            iw, ih = im.size
            scale = sig_w / float(iw)
            sig_h = int(ih * scale)
        except Exception:
            sig_h = 110

    meta_lines = 2 + (1 if contract.signed_at else 0) + (1 if contract.signer_ip else 0)
    needed = 20 + (meta_lines * LINE) + (sig_h or 110) + 10
    if y - needed < MARGIN_B:
        footer(c); c.showPage()
        y = header(c, "4UIT Solutions — MSA (cont.)")

    c.setFont("Helvetica-Bold", 12)
    c.drawString(MARGIN_L, y, "Signature")
    y -= 20

    c.setFont("Helvetica", 10)
    c.drawString(MARGIN_L, y, f"Client: {contract.client.company_name if contract.client else '-'}"); y -= LINE
    c.drawString(MARGIN_L, y, f"Signer: {contract.signer_name or '-'} <{contract.signer_email or '-'}>"); y -= LINE
    if contract.signed_at:
        c.drawString(MARGIN_L, y, f"Signed (UTC): {contract.signed_at.isoformat()}"); y -= LINE
    if contract.signer_ip:
        c.drawString(MARGIN_L, y, f"IP: {contract.signer_ip}"); y -= LINE
    y -= 6

    if sig_abs:
        try:
            sig_norm = normalize_signature_png(sig_abs)
            img = ImageReader(sig_norm)
            c.drawImage(
                img,
                MARGIN_L, y - sig_h,
                width=sig_w, height=sig_h,
                preserveAspectRatio=True,
                anchor="nw"
            )
            y -= sig_h + 6
        except Exception:
            pass

    # Rodapé final da última página
    footer(c)
    c.save()
    return abs_path


def _safe_generate_contract_pdf(contract):
    """Gera o PDF do contrato e captura qualquer falha sem derrubar a view."""
    try:
        return _generate_contract_pdf(contract)
    except Exception:
        return None


def _generate_access_request_pdf(ar: "AccessRequest") -> str:
    abs_path = _access_request_pdf_path(ar.id)
    c = rl_canvas.Canvas(abs_path, pagesize=LETTER)

    PAGE_W, PAGE_H = LETTER
    MARGIN_L = 72
    MARGIN_R = 72
    MARGIN_B = 72
    LINE = 14
    CONTENT_W = PAGE_W - MARGIN_L - MARGIN_R

    def page_header(title="4UIT Solutions — Access Information"):
        return _header_pdf(c, title)

    def page_break(title="4UIT Solutions — Access Information (cont.)"):
        _footer_pdf(c)
        c.showPage()
        return _header_pdf(c, title)

    def wrap(text: str, font="Helvetica", size=10):
        from reportlab.pdfbase.pdfmetrics import stringWidth
        out = []
        for raw in (text or "").replace("\r\n", "\n").split("\n"):
            words, cur = raw.split(" "), ""
            for w in words:
                test = (cur + " " + w).strip()
                if stringWidth(test, font, size) <= CONTENT_W:
                    cur = test
                else:
                    if cur: out.append(cur)
                    cur = w
            out.append(cur)
        return out

    y = page_header()

    # ===== Cabeçalho de auditoria
    c.setFont("Helvetica", 10)
    client_name = "-"
    if getattr(ar, "client", None):
        client_name = ar.client.company_name or "-"
    elif getattr(ar, "client_company", None):
        client_name = ar.client_company or "-"

    audit = [
        f"Client: {client_name}",
        f"Signer: {ar.signer_name or '-'} <{ar.signer_email or '-'}>",
        f"Submitted (UTC): {ar.submitted_at.isoformat() if ar.submitted_at else '-'}",
    ]
    if getattr(ar, "signer_ip", None):
        audit.append(f"IP: {ar.signer_ip}")

    for line in audit:
        if y - LINE < MARGIN_B:
            y = page_break()
            c.setFont("Helvetica", 10)
        c.drawString(MARGIN_L, y, line); y -= LINE

    # ===== Detalhes
    y -= 6
    c.setFont("Helvetica-Bold", 11)
    if y - LINE < MARGIN_B:
        y = page_break()
    c.drawString(MARGIN_L, y, "Access details")
    y -= LINE
    c.setFont("Helvetica", 10)

    pairs = [
        ("Instagram (user)", ar.instagram_user),
        ("Facebook Page", ar.facebook_page),
        ("Meta BM ID", ar.meta_bm_id),
        ("Meta Ads Account", ar.meta_ads_account_id),
        ("Google Ads ID", ar.google_ads_id),
        ("Website URL", ar.website_url),
        ("Hosting", ar.hosting),
        ("Hosting Login", ar.hosting_login),
        ("Hosting Password", ar.hosting_password),
        ("Domain Registrar", ar.domain_registrar),
        ("Domain Login", ar.domain_login),
        ("Domain Password", ar.domain_password),
        ("Brand notes", ar.brand_notes),
    ]

    for label, value in pairs:
        txt = f"{label}: {value or '-'}"
        lines = wrap(txt, size=10)
        for ln in lines:
            if y - LINE < MARGIN_B:
                y = page_break()
                c.setFont("Helvetica", 10)
            c.drawString(MARGIN_L, y, ln); y -= LINE
        y -= 2

    # ===== Assinatura
    c.setFont("Helvetica-Bold", 12)
    if y - (LINE*2 + 120) < MARGIN_B:
        y = page_break()
    c.drawString(MARGIN_L, y, "Signature")
    y -= 18

    c.setFont("Helvetica", 10)
    c.drawString(MARGIN_L, y, f"Client: {client_name}"); y -= LINE
    c.drawString(MARGIN_L, y, f"Signer: {ar.signer_name or '-'} <{ar.signer_email or '-'}>"); y -= LINE
    if ar.submitted_at:
        c.drawString(MARGIN_L, y, f"Submitted (UTC): {ar.submitted_at.isoformat()}"); y -= LINE
    y -= 6

    if ar.signature_path:
        try:
            sig_rel = ar.signature_path.replace("\\", "/")
            sig_abs = os.path.join(UPLOAD_ROOT, sig_rel.replace("uploads/", ""))
            if os.path.exists(sig_abs):
                sig_use = normalize_signature_png(sig_abs)
                from PIL import Image as _PILImage
                iw, ih = _PILImage.open(sig_use).size
                max_w = min(CONTENT_W, 460)
                scale = max_w / float(iw)
                sig_w = max_w
                sig_h = int(ih * scale)
                if y - sig_h < MARGIN_B:
                    y = page_break()
                img = ImageReader(sig_use)
                c.drawImage(img, MARGIN_L, y - sig_h, width=sig_w, height=sig_h,
                            preserveAspectRatio=True, anchor='nw')
                y -= sig_h + 6
        except Exception:
            pass

    _footer_pdf(c)
    c.save()
    return abs_path


# Jinja filter: highlight
@app.template_filter("hl")
def jinja_highlight(text, q):
    if not text or not q:
        return text
    try:
        pattern = re.compile(re.escape(q), re.IGNORECASE)
        esc = escape(str(text))
        result = pattern.sub(lambda m: Markup(f"<mark>{escape(m.group(0))}</mark>"), str(esc))
        return Markup(result)
    except Exception:
        return text


# Expor helper SAS no Jinja (para thumbnails/visualização se um dia precisar)
@app.context_processor
def inject_blob_helpers():
    return {"make_sas_url": make_sas_url if (blob_service and container_client) else lambda *a, **k: ""}



# -------------------------------------------------
# Util
# -------------------------------------------------
@app.get("/admin/assets/ensure-tokens")
@admin_required
def admin_assets_ensure_tokens():
    missing = Asset.query.filter(Asset.public_token.is_(None)).all()
    for a in missing:
        ensure_public_token(a)
    db.session.commit()
    return jsonify({"ok": True, "updated": len(missing)})


def _abs_from_rel_upload(rel_path: str | None) -> str | None:
    """
    Resolve um caminho absoluto a partir de um caminho relativo tipo 'uploads/...'
    tentando as raízes conhecidas.
    """
    if not rel_path:
        return None
    rel = rel_path.lstrip("/").replace("\\", "/")
    # Prioridade: UPLOAD_ROOT (persistente)
    cand1 = os.path.join(UPLOAD_ROOT, rel.replace("uploads/", ""))
    if os.path.exists(cand1):
        return cand1
    # Fallback: BASE_DIR
    cand2 = os.path.join(BASE_DIR, rel)
    if os.path.exists(cand2):
        return cand2
    return cand1  # ainda retorna o esperado na raiz persistente


# -------------------------------------------------
# Public pages
# -------------------------------------------------
@app.get("/")
def home():
    return render_template("home.html")


@app.get("/contract")
def contract_page():
    client_id = request.args.get("client_id", type=int)
    tpl_id = request.args.get("tpl", type=int)
    prefill_email = (request.args.get("email") or "").strip()
    prefill_company = (request.args.get("company") or "").strip()
    contract_text = None

    client = Client.query.get(client_id) if client_id else None
    if client:
        prefill_company = prefill_company or (client.company_name or "")
        if not prefill_email:
            prefill_email = (client.contact_email or "")

        pref = ClientContractPref.query.filter_by(client_id=client.id).first()
        if pref:
            if pref.override_text:
                contract_text = pref.override_text
            elif pref.template:
                contract_text = pref.template.body

    if not contract_text and tpl_id:
        tpl = ContractTemplate.query.get(tpl_id)
        if tpl:
            contract_text = tpl.body

    if not contract_text:
        tpl = ContractTemplate.query.filter_by(is_default=True).order_by(ContractTemplate.id.desc()).first()
        if not tpl:
            tpl = ContractTemplate.query.order_by(ContractTemplate.id.asc()).first()
        contract_text = tpl.body if tpl else "No contract template found. Please contact 4UIT."

    return render_template(
        "marketing_contract.html",
        contract_text=contract_text,
        prefill_company=prefill_company,
        prefill_email=prefill_email,
    )


@app.get("/access-request")
def access_request_page():
    prefill_company = (request.args.get("company") or "").strip()
    prefill_email = (request.args.get("email") or "").strip()
    return render_template("access_request.html",
                           prefill_company=prefill_company,
                           prefill_email=prefill_email)


# -------------------------------------------------
# Login / Logout
# -------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        remember = bool(request.form.get("remember"))
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user, remember=remember)

            nxt = request.args.get("next") or request.form.get("next")
            if nxt and is_safe_next(nxt):
                return redirect(nxt)

            dest = "admin_home" if getattr(user, "role", "") == "admin" else "portal_home"
            return redirect(url_for(dest))

        flash("Invalid credentials.", "danger")
        return redirect(url_for("login"))

    return render_template("login.html", next=request.args.get("next"))


@app.get("/logout")
@login_required
def logout():
    logout_user()
    flash("Signed out.", "info")
    return redirect(url_for("login"))

# --- Rotas locais para servir assets (dev / ambiente sem CDN) ---
from flask import send_from_directory, abort

# /uploads/assets/<arquivo>
@app.route("/uploads/assets/<path:filename>")
def serve_asset_file(filename):
    return send_from_directory(UPLOAD_ASSETS_DIR, filename, as_attachment=False, max_age=3600)

# /uploads/assets/thumbs/<arquivo>
@app.route("/uploads/assets/thumbs/<path:filename>")
def serve_asset_thumb(filename):
    return send_from_directory(UPLOAD_ASSETS_THUMBS_DIR, filename, as_attachment=False, max_age=3600)

# (Opcional) genérica para qualquer coisa em /uploads
@app.route("/uploads/<path:path>")
def serve_asset_generic(path):
    abspath = os.path.join(UPLOAD_ROOT, path)
    if not os.path.abspath(abspath).startswith(os.path.abspath(UPLOAD_ROOT)):
        abort(404)
    directory, fname = os.path.split(abspath)
    if not os.path.exists(abspath):
        abort(404)
    return send_from_directory(directory, fname, as_attachment=False, max_age=3600)

# -------------------------------------------------
# APIs
# -------------------------------------------------
def _access_sig_dir():
    p = os.path.join(BASE_DIR, "uploads", "access_signatures")
    os.makedirs(p, exist_ok=True)
    return p

def _access_pdf_dir():
    p = os.path.join(BASE_DIR, "uploads", "access_pdfs")
    os.makedirs(p, exist_ok=True)
    return p

def _access_pdf_path(ar_id: int) -> str:
    folder = os.path.join(BASE_DIR, "uploads", "access", "pdf")
    os.makedirs(folder, exist_ok=True)
    return os.path.join(folder, f"access-{ar_id}.pdf")

def _contract_pdf_path(contract_id: int) -> str:
    return os.path.join(UPLOAD_CONTRACTS_DIR, f"contract_{contract_id}.pdf")


@app.post("/api/whoami")
@app.get("/api/whoami")
def whoami():
    return jsonify({
        "ip": get_request_ip(),
        "user_agent": request.headers.get("User-Agent", "")
    })


@app.post("/api/signature")
def api_signature():
    data = request.get_json() or {}
    required = ["client_company", "signer_name", "signer_email", "signature_data_url", "contract_text"]
    missing = [k for k in required if not data.get(k)]
    if missing:
        return jsonify({"ok": False, "error": f"Missing fields: {', '.join(missing)}"}), 400

    # --- client
    client = Client.query.filter_by(company_name=data["client_company"]).first()
    if not client:
        client = Client(
            company_name=data["client_company"],
            ein=data.get("client_ein"),
            address=data.get("client_address"),
            legal_representative=data.get("client_legal_rep"),
            contact_email=data.get("signer_email"),
        )
        db.session.add(client)
        db.session.flush()

    # --- assinatura: tenta Blob; fallback local
    try:
        sig_info = save_signature_unified(data["signature_data_url"])
    except Exception as e:
        return jsonify({"ok": False, "error": f"Invalid signature: {e}"}), 400

    # cria o contrato
    contract = Contract(
        client_id=client.id,
        signer_name=data["signer_name"],
        signer_email=data["signer_email"],
        signed_at=utcnow(),
        signer_ip=get_request_ip(),
        user_agent=request.headers.get("User-Agent", ""),
        contract_text=data.get("contract_text", ""),
    )

    # Preenche campos de assinatura, respeitando o modelo atual
    if sig_info["blob_name"] and hasattr(Contract, "signature_blob"):
        try:
            contract.signature_blob = sig_info["blob_name"]
        except Exception:
            pass
    if sig_info["local_relpath"]:
        contract.signature_path = sig_info["local_relpath"]

    db.session.add(contract)
    db.session.commit()

    # --- cria/garante usuário cliente + link set-password
    sp_link = None
    try:
        signer_email = (data.get("signer_email") or "").strip().lower()
        signer_name = (data.get("signer_name") or "").strip() or (client.company_name or "Client")
        if signer_email:
            u = User.query.filter_by(email=signer_email).first()
            if not u:
                u = User(name=signer_name, email=signer_email, role="client")
                u.set_password(secrets.token_urlsafe(12))
                db.session.add(u)
                db.session.commit()
            else:
                if u.role not in ("admin", "client"):
                    u.role = "client"
                    db.session.commit()
            sp_token = make_setpwd_token(signer_email)
            sp_link = url_for("set_password", token=sp_token, _external=True)
    except Exception:
        pass

    # --- gera PDF e prepara anexo
    attachments = []
    pdf_abs = _safe_generate_contract_pdf(contract)
    if pdf_abs and os.path.exists(pdf_abs):
        attachments.append((pdf_abs, f"4UIT-contract-{contract.id}.pdf"))

    # --- e-mail ao cliente (assinado)
    try:
        brand = "4UIT Solutions"
        portal_link = url_for("portal_home", _external=True)
        subject = f"Your contract with 4UIT — signed (#{contract.id})"

        text_lines = [
            f"Hi {contract.signer_name},",
            "",
            "Your contract has been signed successfully.",
            "",
            f"Contract ID: {contract.id}",
            f"Client: {client.company_name if client else '-'}",
            "",
            "You can access your portal here:",
            f"{portal_link}",
            "",
        ]
        if sp_link:
            text_lines.append("Set your password here:")
            text_lines.append(sp_link)
        else:
            text_lines.append("If you already set a password, just sign in.")
        text_lines.extend(["", "The signed PDF is attached.", "", "Thanks,", brand])

        text_body = "\n".join(text_lines)

        signer_name_safe = escape(contract.signer_name or "")
        client_name_safe = escape(client.company_name or "-") if client else "-"
        portal_link_safe = portal_link
        if sp_link:
            password_html = f'<span>Set your password: </span><a href="{sp_link}">{sp_link}</a>'
        else:
            password_html = '<em>If you already set a password, just sign in.</em>'

        html_body = (
            '<div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif">'
            f'<h2 style="margin:0 0 8px">{brand}</h2>'
            f'<p>Hi <strong>{signer_name_safe}</strong>,</p>'
            '<p>Your contract has been signed successfully.</p>'
            '<p style="margin:10px 0">'
            f'<strong>Contract ID:</strong> {contract.id}<br/>'
            f'<strong>Client:</strong> {client_name_safe}'
            '</p>'
            f'<p>Access your portal: <a href="{portal_link_safe}">{portal_link_safe}</a><br/>{password_html}</p>'
            '<p>The signed PDF is attached.</p>'
            f'<p>Thanks,<br/>{brand}</p>'
            '</div>'
        )

        to_addrs = [contract.signer_email]
        cc_list = []
        admin_notify = _split_emails(os.getenv("ADMIN_EMAIL")) or _split_emails(os.getenv("NOTIFY_TO"))
        if admin_notify:
            cc_list.extend(admin_notify)

        send_email(
            subject=subject,
            text_body=text_body,
            html_body=html_body,
            to_addrs=to_addrs,
            cc_addrs=cc_list,
            attachments=attachments,
        )
    except Exception:
        pass

    # URL da assinatura para retorno da API
    if getattr(contract, "signature_blob", None) and blob_service and container_client:
        try:
            sig_url = make_sas_url(contract.signature_blob, minutes=30)
        except Exception:
            sig_url = None
    else:
        sig_rel = getattr(contract, "signature_path", None)
        sig_url = ("/" + sig_rel.replace("\\", "/")) if sig_rel else None

    return jsonify({
        "ok": True,
        "message": "Signature stored successfully.",
        "signed_at_utc": contract.signed_at.isoformat(),
        "signer_ip": contract.signer_ip,
        "signature_url": sig_url,
        "client_id": client.id,
        "contract_id": contract.id
    })


@app.route("/set-password/<token>", methods=["GET", "POST"])
def set_password(token: str):
    try:
        data = decode_setpwd_token(token)
        email = (data.get("email") or "").strip().lower()
    except (BadSignature, SignatureExpired, KeyError):
        flash("Invalid or expired link.", "danger")
        return redirect(url_for("login"))

    u = User.query.filter_by(email=email).first_or_404()

    if request.method == "POST":
        pw = (request.form.get("password") or "").strip()
        pw2 = (request.form.get("password2") or "").strip()
        if len(pw) < 8:
            flash("Password must have at least 8 characters.", "danger")
            return redirect(request.url)
        if pw != pw2:
            flash("Passwords do not match.", "danger")
            return redirect(request.url)
        u.set_password(pw)
        db.session.commit()
        flash("Password set successfully. You can sign in now.", "success")
        return redirect(url_for("login"))

    return render_template("set_password.html", email=email)


# --- API: Access Request ------------------------------------------------------
@app.post("/api/access-request")
@login_required
def api_access_request():
    data = request.get_json(force=True) or {}

    company_name = (data.get("client_company") or "").strip()
    signer_email = (data.get("signer_email") or "").strip()

    client = None
    if company_name:
        client = Client.query.filter_by(company_name=company_name).first()
        if not client:
            client = Client(company_name=company_name, contact_email=signer_email)
            db.session.add(client)
            db.session.flush()

    sig_relpath = None
    sig_data_url = data.get("signature_data_url") or ""
    if sig_data_url.startswith("data:image"):
        try:
            b64 = sig_data_url.split(",", 1)[1]
            raw = base64.b64decode(b64)
            fname = f"access_{uuid.uuid4().hex}.png"
            abs_path = os.path.join(ACCESS_SIGS_DIR, fname)
            with open(abs_path, "wb") as f:
                f.write(raw)
            sig_relpath = f"uploads/access_signatures/{fname}"
        except Exception as e:
            return jsonify(ok=False, error=f"signature decode error: {e}"), 400

    allowed_cols = {c.name for c in AccessRequest.__table__.columns}
    kwargs = {}
    for k, v in data.items():
        if k in allowed_cols:
            kwargs[k] = v
    if client and "client_id" in allowed_cols:
        kwargs["client_id"] = client.id
    if sig_relpath and "signature_path" in allowed_cols:
        kwargs["signature_path"] = sig_relpath
    kwargs.pop("client_company", None)
    kwargs.pop("signature_data_url", None)

    try:
        ar = AccessRequest(**kwargs)
        ip = get_request_ip()
        if hasattr(ar, "submitted_ip"):
            ar.submitted_ip = ip
        if hasattr(ar, "signer_ip"):
            ar.signer_ip = ip
        if hasattr(ar, "submitted_by") and getattr(current_user, "email", None):
            ar.submitted_by = current_user.email
        if hasattr(ar, "submitted_email") and not ar.submitted_email:
            ar.submitted_email = (data.get("signer_email") or "").strip()

        db.session.add(ar)
        db.session.commit()
        return jsonify(ok=True, id=ar.id)
    except Exception as e:
        db.session.rollback()
        return jsonify(ok=False, error=str(e)), 400


@app.get("/admin/access/<int:ar_id>")
@login_required
def admin_access_view(ar_id):
    ar = AccessRequest.query.options(joinedload(AccessRequest.client)).get_or_404(ar_id)
    return render_template("access_view.html", ar=ar)

@app.get("/admin/access/<int:ar_id>/pdf")
@login_required
def admin_access_pdf(ar_id):
    ar = AccessRequest.query.get_or_404(ar_id)
    pdf_abs = _access_request_pdf_path(ar.id)
    if not os.path.exists(pdf_abs):
        _generate_access_request_pdf(ar)
    return send_file(pdf_abs, as_attachment=True, download_name=f"access_{ar.id}.pdf")


# -------------------------------------------------
# Assets — routes (admin)
# -------------------------------------------------
ALLOWED_EXTS = {"png", "jpg", "jpeg", "gif", "webp", "mp4", "mov", "mkv", "pdf"}

@app.get("/assets")
@admin_required
def assets_list():
    qtext = (request.args.get("q") or "").strip()
    selected_statuses = request.args.getlist("status")
    if not selected_statuses:
        single_status = (request.args.get("status") or "").strip()
        if single_status:
            selected_statuses = [single_status]

    selected_client_id = request.args.get("client_id", type=int)
    page = max(1, request.args.get("page", default=1, type=int))
    per_page = min(max(request.args.get("per_page", type=int, default=12), 5), 100)
    sort = (request.args.get("sort") or "created_desc").strip()

    q = Asset.query

    if selected_statuses:
        allowed = {"pending", "approved", "rejected", "posted"}
        chosen = [s for s in selected_statuses if s in allowed]
        if chosen:
            q = q.filter(Asset.status.in_(chosen))

    if selected_client_id:
        q = q.filter(Asset.client_id == selected_client_id)

    if qtext:
        like = f"%{qtext}%"
        q = q.filter(or_(Asset.title.ilike(like), Asset.description.ilike(like)))

    if sort.endswith("_desc"):
        sort_field = sort[:-5]; sort_dir = "desc"
    elif sort.endswith("_asc"):
        sort_field = sort[:-4]; sort_dir = "asc"
    else:
        sort_field = sort or "created"; sort_dir = "desc"

    if sort_field == "client":
        q = q.join(Client, Asset.client_id == Client.id, isouter=True)
        col = Client.company_name
    elif sort_field == "title":
        col = Asset.title
    elif sort_field == "kind":
        col = Asset.kind
    elif sort_field == "status":
        col = Asset.status
    elif sort_field == "scheduled":
        col = Asset.scheduled_for
    elif sort_field == "id":
        col = Asset.id
    else:
        col = Asset.created_at

    q = q.order_by(desc(col) if sort_dir == "desc" else asc(col), desc(Asset.id))

    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()

    def qs(**over):
        args = request.args.to_dict(flat=False)
        for k, v in over.items():
            if v is None:
                args.pop(k, None)
            elif isinstance(v, list):
                args[k] = v
            else:
                args[k] = [str(v)]
        return "?" + urlencode(args, doseq=True)

    def page_url(p):
        return url_for("assets_list") + qs(page=p)

    last_page = max(1, (total + per_page - 1) // per_page)
    first_url = page_url(1) if page > 1 else None
    prev_url = page_url(page - 1) if page > 1 else None
    next_url = page_url(page + 1) if page < last_page else None
    last_url = page_url(last_page) if page < last_page else None

    start = max(1, page - 2)
    end = min(last_page, page + 2)
    page_links = [{"num": i, "url": page_url(i), "active": (i == page)} for i in range(start, end + 1)]

    review_base = request.host_url.rstrip("/") + "/review/"
    start_idx = 0 if total == 0 else (page - 1) * per_page + 1
    end_idx = (page - 1) * per_page + len(items)

    def sort_url(field: str):
        cur = (request.args.get("sort") or "created_desc")
        cur_field = cur.replace("_desc", "").replace("_asc", "")
        next_sort = f"{field}_asc"
        if cur_field == field and cur.endswith("_asc"):
            next_sort = f"{field}_desc"
        return url_for("assets_list") + qs(sort=next_sort, page=1)

    def caret(field: str):
        cur = (request.args.get("sort") or "created_desc")
        if cur.startswith(field + "_"):
            return "▲" if cur.endswith("_asc") else "▼"
        return ""

    clients = Client.query.order_by(Client.company_name.asc()).all()

    return render_template(
        "assets_list.html",
        assets=items,
        clients=clients,
        qtext=qtext,
        selected_statuses=selected_statuses,
        selected_client_id=selected_client_id,
        total=total,
        start_idx=start_idx,
        end_idx=end_idx,
        first_url=first_url,
        prev_url=prev_url,
        next_url=next_url,
        last_url=last_url,
        page_links=page_links,
        review_base=review_base,
        sort_url=sort_url,
        caret=caret,
    )


@app.get("/assets/<int:asset_id>")
@admin_required
def asset_detail(asset_id: int):
    a = Asset.query.get_or_404(asset_id)
    if not a.public_token:
        ensure_public_token(a)
        db.session.commit()

    review_url = f"{request.host_url.rstrip('/')}/review/{a.public_token}"
    preview_url = f"/{a.thumbnail_path or a.storage_path}" if (a.thumbnail_path or a.storage_path) else None

    default_to = (a.client.contact_email if a.client and a.client.contact_email else "")
    default_cc = (a.client.account_manager_email if a.client and getattr(a.client, "account_manager_email", None) else "")

    return render_template(
        "asset_detail.html",
        a=a,
        review_url=review_url,
        preview_url=preview_url,
        default_to=default_to,
        default_cc=default_cc,
    )


def notify_client_asset_needs_review(asset):
    from models import Client
    client = getattr(asset, "client", None) or Client.query.get(getattr(asset, "client_id", None))
    to = (client.contact_email if client and client.contact_email else None) or _env("NOTIFY_TO")
    if not to:
        return False

    bcc = _env("EMAIL_BCC")
    link = _asset_public_review_link(asset)
    subject = f"[4UIT] Asset awaiting your review: {asset.title or f'#{asset.id}'}"
    html = f"""
    <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:14px">
      <p>Hello{(' ' + (client.company_name or '')) if client else ''},</p>
      <p>There is a new item waiting for your approval:</p>
      <p><strong>{asset.title or 'Asset'}</strong></p>
      <p><a href="{link}" target="_blank" rel="noopener">Click here to review and approve</a></p>
      <hr><p style="color:#6b7280">4UIT • Marketing & Software</p>
    </div>
    """
    return send_mail_4uit(subject, html, to=to, bcc=bcc)


def notify_team_asset_review_feedback(asset, review, action_label: str):
    from models import Client
    client = getattr(asset, "client", None) or Client.query.get(getattr(asset, "client_id", None))
    to = None
    if client and getattr(client, "account_manager_email", None):
        to = client.account_manager_email
    if not to:
        to = _env("NOTIFY_TO")
    if not to:
        return False

    bcc = _env("EMAIL_BCC")
    link = _asset_public_review_link(asset)
    subject = f"[4UIT] Client {action_label} • {asset.title or f'#{asset.id}'}"
    comments = ""
    if review and getattr(review, "comments", None):
        comments = f"<p><strong>Client comments:</strong><br>{review.comments}</p>"

    html = f"""
    <div style="font-family:Segoe UI,Arial,Helvetica,sans-serif;font-size:14px">
      <p><strong>Client:</strong> {(client.company_name if client else '-') }</p>
      <p><strong>Action:</strong> {action_label}</p>
      <p><strong>Asset:</strong> {asset.title or f'#{asset.id}'}</p>
      {comments}
      <p><a href="{link}" target="_blank" rel="noopener">Open asset</a></p>
      <hr><p style="color:#6b7280">4UIT • Marketing & Software</p>
    </div>
    """
    return send_mail_4uit(subject, html, to=to, bcc=bcc)


def _asset_public_review_link(asset):
    base = request.host_url.rstrip("/")
    if getattr(asset, "public_token", None):
        return f"{base}/review/{asset.public_token}"
    return f"{base}{url_for('portal_asset_review', asset_id=asset.id)}"


def send_mail_4uit(subject: str, html: str, to: list[str] | str,
                   bcc: list[str] | str | None = None,
                   text: str | None = None):
    if isinstance(to, str):
        to_list = [to]
    else:
        to_list = [t for t in to if t]

    text_body = text or _html_to_text(html)
    html_body = html or (text or "")

    try:
        return send_email(
            subject=subject,
            text_body=text_body,
            html_body=html_body,
            to_addrs=to_list,
            cc_addrs=None,
            attachments=None
        )
    except Exception as e:
        current_app.logger.warning("send_mail_4uit: native send_email failed (%s). Falling back to SMTP.", e)
        return _send_email_fallback(subject, html_body, to_list, bcc=bcc, text=text_body)


@app.post("/assets/<int:asset_id>/send-review-email")
@admin_required
def assets_send_review_email(asset_id: int):
    asset = Asset.query.get_or_404(asset_id)
    client = asset.client

    to_addr = (request.form.get("to") or (client.contact_email if client else "") or os.getenv("FALLBACK_TO") or "").strip()
    cc_field = (request.form.get("cc") or "").strip()
    cc_list = _split_emails(cc_field)

    if not to_addr:
        flash("Recipient (To) is required.", "danger")
        return redirect(url_for("asset_detail", asset_id=asset.id))

    if not asset.public_token:
        ensure_public_token(asset)
        db.session.commit()
    review_url = url_for("public_review", token=asset.public_token, _external=True)

    storage_url = f"{request.host_url.rstrip('/')}/{asset.storage_path}" if asset.storage_path else None

    subject = f"[Review] {asset.title} — {client.company_name if client else '4UIT Client'}"
    brand = "4UIT Solutions"

    text_body = f"""Hi,
There's a new asset ready for your review.

Title: {asset.title}
Client: {client.company_name if client else '-'}

Review & approve/reject here:
{review_url}

{('File: ' + storage_url) if storage_url else ''}

Thanks,
{brand}
"""

    html_body = f"""<!doctype html><html><body style="margin:0;background:#0f172a;color:#e5e7eb;font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif">
    <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="background:#0f172a;padding:26px 0">
      <tr><td>
        <table role="presentation" cellpadding="0" cellspacing="0" width="640" align="center" style="margin:0 auto;background:#111827;border:1px solid #1f2937;border-radius:14px">
          <tr>
            <td style="padding:18px 20px;border-bottom:1px solid #1f2937">
              <table width="100%" role="presentation"><tr>
                <td style="font-weight:700;font-size:18px;color:#fff">4UIT • Asset Review</td>
                <td align="right" style="color:#9ca3af;font-size:12px">{brand}</td>
              </tr></table>
            </td>
          </tr>
          <tr>
            <td style="padding:22px 20px">
              <div style="font-size:16px;color:#e5e7eb;margin-bottom:8px"><strong>{escape(asset.title)}</strong></div>
              <div style="font-size:13px;color:#9ca3af;margin-bottom:16px">
                {escape(client.company_name) if client else '-'} • Status: <span style="border:1px solid #374151;border-radius:999px;padding:2px 8px">{escape(asset.status)}</span>
              </div>
              {("<div style='margin-bottom:16px'><img src='" + storage_url + "' style='max-width:100%;border-radius:12px;border:1px solid #1f2937'/></div>" if (storage_url and (asset.kind in ('image','copy'))) else "")}
              <div style='margin:18px 0'>
                <a href="{review_url}" style="background:#0ea5e9;color:#001018;text-decoration:none;padding:10px 16px;border-radius:10px;display:inline-block;font-weight:700">Review & Approve/Reject</a>
              </div>
              {("<div style='font-size:12px;color:#9ca3af;margin-top:8px'>File: <a style='color:#93c5fd' href='" + storage_url + "'>" + storage_url + "</a></div>" if storage_url else "")}
            </td>
          </tr>
          <tr>
            <td style="padding:14px 20px;border-top:1px solid #1f2937;color:#9ca3af;font-size:12px">
              Sent by {brand}. If the button doesn't work, use this link:<br/>
              <a href="{review_url}" style="color:#93c5fd">{review_url}</a>
            </td>
          </tr>
        </table>
      </td></tr>
    </table>
  </body></html>"""

    attachments = []
    attach_flag = (request.form.get("attach") == "1")
    if attach_flag and asset.storage_path:
        abs_path = _abs_from_rel_upload(asset.storage_path)
        if abs_path and os.path.exists(abs_path):
            attachments.append((abs_path, os.path.basename(abs_path)))

    try:
        send_email(
            subject=subject,
            text_body=text_body,
            html_body=html_body,
            to_addrs=[to_addr],
            cc_addrs=cc_list,
            attachments=attachments
        )
        app.logger.info("Review email sent to %s (cc: %s)", to_addr, ", ".join(cc_list) or "-")
        flash(f"Email sent to {to_addr}" + (f" (cc: {', '.join(cc_list)})" if cc_list else ""), "success")
    except Exception as e:
        app.logger.exception("Error sending email: %s", e)
        flash(f"Failed to send email: {e}", "danger")

    return redirect(url_for("asset_detail", asset_id=asset.id))


from io import BytesIO

@app.route("/assets/upload", methods=["GET", "POST"])
@admin_required
def asset_upload():
    clients = Client.query.order_by(Client.company_name.asc()).all()
    if request.method == "POST":
        client_id = request.form.get("client_id", type=int)
        title = (request.form.get("title") or "").strip()
        description = request.form.get("description")
        kind = (request.form.get("kind") or "image").strip().lower()
        external_url = (request.form.get("external_url") or "").strip()

        f = request.files.get("file")
        storage_rel = None
        thumb_rel = None
        file_mime = None
        file_size = None

        if f and f.filename:
            ext = (f.filename.rsplit(".", 1)[-1] or "").lower()
            if ext not in ALLOWED_EXTS:
                flash("File type not allowed.", "danger")
                return redirect(url_for("asset_upload"))

            newname = f"{uuid.uuid4().hex}.{ext}"
            rel_main = os.path.join("assets", newname).replace("\\", "/")

            # lê em memória para suportar Blob e Local
            raw = f.read()
            file_size = len(raw) if raw is not None else None
            file_mime = f.mimetype or _guess_mime(newname)

            # salva principal (Blob ou Local)
            storage_path = _store_file(raw, rel_main, content_type=file_mime)
            storage_rel = storage_path  # 'blob:assets/...' ou 'uploads/assets/...'

            # Miniatura somente para imagens
            if _is_image(file_mime, ext) and PIL_AVAILABLE:
                try:
                    from PIL import Image as _IM
                    im = _IM.open(BytesIO(raw))

                    # normaliza modo
                    if im.mode == "P":
                        try:
                            im = im.convert("RGBA")
                        except Exception:
                            im = im.convert("RGB")
                    elif im.mode not in ("RGB", "RGBA"):
                        im = im.convert("RGBA" if "A" in im.getbands() else "RGB")

                    im.thumbnail((480, 480))

                    # garante JPEG (remove alpha se houver)
                    buf = BytesIO()
                    if im.mode == "RGBA":
                        from PIL import Image as _PILImage
                        bg = _PILImage.new("RGB", im.size, (255, 255, 255))
                        bg.paste(im, mask=im.split()[3])
                        im = bg
                    im.save(buf, "JPEG", quality=82)
                    buf.seek(0)

                    thumb_name = f"{uuid.uuid4().hex}.jpg"
                    rel_thumb = os.path.join("assets", "thumbs", thumb_name).replace("\\", "/")
                    thumb_path = _store_file(buf.getvalue(), rel_thumb, content_type="image/jpeg")
                    thumb_rel = thumb_path  # 'blob:assets/thumbs/...' ou 'uploads/assets/thumbs/...'
                except Exception as e:
                    app.logger.warning("thumbnail generation failed: %s", e)

        if not client_id or not title:
            flash("Client and title are required.", "danger")
            return redirect(url_for("asset_upload"))

        asset = Asset(
            client_id=client_id,
            title=title,
            description=description,
            kind=kind,
            storage_path=storage_rel,
            thumbnail_path=thumb_rel,
            external_url=external_url,
            file_mime=file_mime,
            file_size=file_size,
            uploaded_by_user_id=current_user.id if current_user.is_authenticated else None,
            status="pending",
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        ensure_public_token(asset)
        db.session.add(asset)
        db.session.commit()

        try:
            sent = notify_client_asset_needs_review(asset)
            if sent is not False:
                app.logger.info("Client review email queued/sent for asset #%s", asset.id)
            else:
                app.logger.warning(
                    "notify_client_asset_needs_review returned False (no recipient?) for asset #%s",
                    asset.id
                )
        except Exception as e:
            app.logger.exception("Failed to send client review email for asset #%s: %s", asset.id, e)
            flash("Asset uploaded, but failed to send client notification email. Check SMTP/env and logs.", "warning")

        flash("Asset uploaded.", "success")
        return redirect(url_for("assets_list"))

    return render_template("asset_upload.html", clients=clients)


@app.post("/assets/<int:asset_id>/approve")
@admin_required
def asset_approve(asset_id: int):
    asset = Asset.query.get_or_404(asset_id)
    asset.status = "approved"
    asset.approved_by_user_id = current_user.id
    asset.approved_at = utcnow()
    asset.updated_at = utcnow()
    db.session.commit()
    flash("Asset approved.", "success")
    return redirect(url_for("assets_list", **request.args))


@app.post("/assets/<int:asset_id>/reject")
@admin_required
def asset_reject(asset_id: int):
    asset = Asset.query.get_or_404(asset_id)
    reason = (request.form.get("reason") or "").strip()
    asset.status = "rejected"
    asset.rejection_reason = reason or None
    asset.approved_by_user_id = None
    asset.approved_at = None
    asset.updated_at = utcnow()
    db.session.commit()
    flash("Asset rejected.", "warning")
    return redirect(url_for("assets_list", **request.args))


@app.post("/assets/<int:asset_id>/mark-posted")
@admin_required
def assets_mark_posted(asset_id: int):
    asset = Asset.query.get_or_404(asset_id)
    asset.status = "posted"
    asset.posted_at = utcnow()
    asset.updated_at = utcnow()
    db.session.commit()
    flash("Asset marked as 'posted'.", "success")
    return redirect(url_for("assets_list", **request.args))


# === Editar Asset ======================================================
@app.route("/assets/<int:asset_id>/edit", methods=["GET", "POST"])
@admin_required
def asset_edit(asset_id):
    a = Asset.query.get_or_404(asset_id)
    clients = Client.query.order_by(Client.company_name.asc()).all()

    if request.method == "POST":
        client_id = request.form.get("client_id", type=int)
        title = (request.form.get("title") or "").strip()
        description = request.form.get("description")
        kind = (request.form.get("kind") or "image").strip().lower()
        external_url = (request.form.get("external_url") or "").strip()
        status = (request.form.get("status") or a.status or "pending").strip().lower()

        if not client_id or not title:
            flash("Client and title are required.", "danger")
            return redirect(url_for("asset_edit", asset_id=a.id))

        # Atualiza campos básicos
        a.client_id = client_id
        a.title = title
        a.description = description
        a.kind = kind
        a.external_url = external_url
        a.status = status
        a.updated_at = utcnow()

        # Substituição de arquivo (opcional)
        f = request.files.get("file")
        if f and f.filename:
            ext = (f.filename.rsplit(".", 1)[-1] or "").lower()
            if ext not in ALLOWED_EXTS:
                flash("File type not allowed.", "danger")
                return redirect(url_for("asset_edit", asset_id=a.id))

            # Apaga arquivos antigos, se existirem
            if a.storage_path:
                _delete_storage_file(a.storage_path)
            if a.thumbnail_path:
                _delete_storage_file(a.thumbnail_path)

            # Salva novo arquivo (modo local). Para Azure, aqui podemos enviar ao Blob.
            newname = f"{uuid.uuid4().hex}.{ext}"
            storage_rel = os.path.join("uploads", "assets", newname)
            storage_abs = os.path.join(UPLOAD_ASSETS_DIR, newname)

            if _storage_is_azure():
                # Upload para Azure Blob
                from azure.storage.blob import ContentSettings
                bsc = _azure_blob_client()
                container = _blob_container_name()
                blob_name = _blob_name_from_rel(storage_rel)
                content = f.read()
                bsc.get_container_client(container).upload_blob(
                    name=blob_name,
                    data=content,
                    overwrite=True,
                    content_settings=ContentSettings(content_type=f.mimetype or "application/octet-stream"),
                )
            else:
                f.save(storage_abs)

            a.storage_path = storage_rel
            a.file_mime = getattr(f, "mimetype", None)
            try:
                if _storage_is_azure():
                    a.file_size = len(content)
                else:
                    a.file_size = pathlib.Path(storage_abs).stat().st_size
            except Exception:
                a.file_size = None

            # Gera thumbnail (apenas se imagem e em modo local; para Azure, gere thumb local e suba)
            a.thumbnail_path = None
            if _is_image(a.file_mime, ext):
                thumb_name = f"{uuid.uuid4().hex}.jpg"
                thumb_rel = os.path.join("uploads", "assets", "thumbs", thumb_name)
                thumb_abs = os.path.join(UPLOAD_ASSETS_THUMBS_DIR, thumb_name)

                if _storage_is_azure():
                    # baixa temporário, gera thumb e reenvia
                    tmp_abs = storage_abs if not _storage_is_azure() else os.path.join(BASE_DIR, "tmp_" + newname)
                    if _storage_is_azure():
                        # baixa o blob recém enviado para gerar thumb
                        bsc = _azure_blob_client()
                        container = _blob_container_name()
                        blob_name = _blob_name_from_rel(storage_rel)
                        with open(tmp_abs, "wb") as wf:
                            stream = bsc.get_container_client(container).download_blob(blob_name)
                            wf.write(stream.readall())
                    _gen_thumb(tmp_abs, thumb_abs)
                    # envia thumb ao Azure
                    from azure.storage.blob import ContentSettings
                    bsc = _azure_blob_client()
                    container = _blob_container_name()
                    bsc.get_container_client(container).upload_blob(
                        name=_blob_name_from_rel(thumb_rel),
                        data=open(thumb_abs, "rb"),
                        overwrite=True,
                        content_settings=ContentSettings(content_type="image/jpeg"),
                    )
                    # limpa temporários locais se quiser
                    try:
                        if _storage_is_azure() and os.path.exists(tmp_abs):
                            os.remove(tmp_abs)
                        if os.path.exists(thumb_abs):
                            os.remove(thumb_abs)
                    except Exception:
                        pass
                else:
                    _gen_thumb(storage_abs, thumb_abs)

                a.thumbnail_path = thumb_rel

        db.session.commit()
        flash("Asset updated.", "success")
        return redirect(url_for("asset_detail", asset_id=a.id))

    return render_template("asset_edit.html", a=a, clients=clients)

# === Excluir Asset ======================================================
@app.route("/assets/<int:asset_id>/delete", methods=["POST"])
@admin_required
def asset_delete(asset_id):
    a = Asset.query.get_or_404(asset_id)

    try:
        # Remove arquivos do storage (se existirem)
        if a.storage_path:
            _delete_storage_file(a.storage_path)
        if a.thumbnail_path:
            _delete_storage_file(a.thumbnail_path)

        db.session.delete(a)
        db.session.commit()
        flash(f"Asset #{asset_id} deleted.", "success")
    except Exception as e:
        db.session.rollback()
        app.logger.exception("Erro ao excluir asset #%s: %s", asset_id, e)
        flash("Failed to delete asset.", "danger")

    return redirect(url_for("assets_list"))


# -------------------------------------------------
# Clients — CRUD (admin)
# -------------------------------------------------
@app.get("/clients")
@admin_required
def clients_list():
    qtext = (request.args.get("q") or "").strip()
    sort = (request.args.get("sort") or "name_asc").strip()

    q = Client.query

    if qtext:
        like = f"%{qtext}%"
        q = q.filter(
            or_(
                Client.company_name.ilike(like),
                Client.contact_email.ilike(like),
                Client.account_manager_email.ilike(like),
                Client.ein.ilike(like),
            )
        )

    if sort == "name_desc":
        q = q.order_by(desc(Client.company_name), desc(Client.id))
    else:
        sort = "name_asc"
        q = q.order_by(asc(Client.company_name), desc(Client.id))

    clients = q.all()

    def qs(**over):
        args = request.args.to_dict(flat=False)
        for k, v in over.items():
            if v is None:
                args.pop(k, None)
            else:
                args[k] = [str(v)]
        return "?" + urlencode(args, doseq=True)

    def sort_url():
        next_sort = "name_desc" if sort == "name_asc" else "name_asc"
        return url_for("clients_list") + qs(sort=next_sort)

    def caret():
        return "▲" if sort == "name_asc" else "▼"

    return render_template(
        "clients_list.html",
        clients=clients,
        qtext=qtext,
        sort=sort,
        sort_url=sort_url,
        caret=caret,
    )


def _build_onboarding_links(c: Client, external: bool = True) -> tuple[str, str]:
    contract_url = url_for("contract_page", _external=external, client_id=c.id)
    access_url = url_for("access_request_page", _external=external) + \
                 f"?company={quote(c.company_name or '')}&email={quote(c.contact_email or '')}"
    return contract_url, access_url


@app.post("/clients/new")
@admin_required
def clients_new():
    c = Client(
        company_name=(request.form.get("company_name") or "").strip(),
        contact_email=(request.form.get("contact_email") or "").strip() or None,
        account_manager_email=(request.form.get("account_manager_email") or "").strip() or None,
        ein=(request.form.get("ein") or "").strip() or None,
        address=(request.form.get("address") or "").strip() or None,
        legal_representative=(request.form.get("legal_representative") or "").strip() or None,
    )
    if not c.company_name:
        flash("Company name is required.", "danger")
        return redirect(url_for("clients_list"))

    db.session.add(c)
    db.session.commit()
    flash("Client added. Choose the contract template and click Save to send the onboarding e-mail.", "info")
    return redirect(url_for("client_contract_pref", client_id=c.id))


@app.route("/clients/<int:client_id>/edit", methods=["GET", "POST"])
@admin_required
def clients_edit(client_id: int):
    c = Client.query.get_or_404(client_id)
    if request.method == "POST":
        c.company_name = (request.form.get("company_name") or "").strip()
        c.contact_email = (request.form.get("contact_email") or "").strip() or None
        c.account_manager_email = (request.form.get("account_manager_email") or "").strip() or None
        c.ein = (request.form.get("ein") or "").strip() or None
        c.address = (request.form.get("address") or "").strip() or None
        c.legal_representative = (request.form.get("legal_representative") or "").strip() or None
        if not c.company_name:
            flash("Company name is required.", "danger")
            return redirect(url_for("clients_edit", client_id=client_id))
        db.session.commit()
        flash("Client saved.", "success")
        return redirect(url_for("clients_list"))

    return render_template("clients_edit.html", c=c)


@app.post("/clients/<int:client_id>/delete")
@admin_required
def clients_delete(client_id: int):
    c = Client.query.get_or_404(client_id)
    force = (request.args.get("force") == "1") or (request.form.get("force") == "1")
    try:
        ClientContractPref.query.filter_by(client_id=c.id).delete(synchronize_session=False)

        if not force:
            deps = {
                "contracts": Contract.query.filter_by(client_id=c.id).count(),
                "assets": Asset.query.filter_by(client_id=c.id).count(),
                "access": AccessRequest.query.filter_by(client_id=c.id).count(),
            }
            if sum(deps.values()) > 0:
                db.session.rollback()
                flash(
                    f"Não foi possível excluir '{c.company_name}'. "
                    f"Existem {deps['contracts']} contrato(s), {deps['assets']} asset(s) "
                    f"e {deps['access']} access request(s) vinculados. "
                    f"Remova/mova primeiro ou use a opção de exclusão forçada.",
                    "danger"
                )
                return redirect(url_for("clients_list"))

        if force:
            Contract.query.filter_by(client_id=c.id).delete(synchronize_session=False)
            Asset.query.filter_by(client_id=c.id).delete(synchronize_session=False)
            AccessRequest.query.filter_by(client_id=c.id).delete(synchronize_session=False)

        db.session.delete(c)
        db.session.commit()
        flash("Cliente excluído.", "warning")
    except Exception as e:
        db.session.rollback()
        flash(f"Erro ao excluir: {e}", "danger")

    return redirect(url_for("clients_list"))


@app.get("/uploads/access_signatures/<path:filename>")
def get_access_signature(filename):
    return send_from_directory(ACCESS_SIGS_DIR, filename)


@app.get("/admin/clients/<int:client_id>/links")
@admin_required
def clients_links(client_id: int):
    c = Client.query.get_or_404(client_id)
    token = make_onboarding_token(c.id)

    contract_url, access_url = _build_onboarding_links(c, external=True)
    onboarding_url = url_for("onboarding_page", token=token, _external=True)

    return render_template("onboarding_links.html",
                           c=c,
                           contract_url=contract_url,
                           access_url=access_url,
                           onboarding_url=onboarding_url)


@app.get("/onboarding/<token>")
def onboarding_page(token: str):
    try:
        data = decode_onboarding_token(token)
        c = Client.query.get_or_404(int(data["cid"]))
    except (BadSignature, SignatureExpired, KeyError, ValueError):
        abort(404)

    contract_url, access_url = _build_onboarding_links(c, external=False)

    return render_template("onboarding.html",
                           c=c,
                           contract_url=contract_url,
                           access_url=access_url)


# -------------------------------------------------
# Admin (protected)
# -------------------------------------------------
@app.get("/admin")
@login_required
def admin_home():
    contracts = Contract.query.options(joinedload(Contract.client)).order_by(Contract.id.desc()).all()
    access_list = AccessRequest.query.options(joinedload(AccessRequest.client)).order_by(AccessRequest.id.desc()).all()
    assets = Asset.query.options(joinedload(Asset.client)).order_by(Asset.id.desc()).all()
    return render_template("admin.html", contracts=contracts, access_list=access_list, assets=assets)


# ---------------------------------------------
# Admin — Contracts (view / pdf)
# ---------------------------------------------

@app.route("/admin/contracts/<int:contract_id>")
def admin_contract_view(contract_id):
    contract = Contract.query.get_or_404(contract_id)
    client = Client.query.get(contract.client_id)

    signature_url = None

    # 1) Se tiver caminho local salvo
    if getattr(contract, "signature_path", None):
        signature_url = "/" + contract.signature_path.lstrip("/")

    # 2) Se tiver blob e Azure configurado, gerar SAS
    if not signature_url and getattr(contract, "signature_blob", None) and blob_service and container_client:
        try:
            signature_url = make_sas_url(contract.signature_blob, minutes=30)
        except Exception:
            signature_url = None

    return render_template(
        "contract_view.html",
        contract=contract, client=client, signature_url=signature_url
    )


@app.get("/admin/contracts/<int:contract_id>/pdf")
@admin_required
def admin_contract_pdf(contract_id: int):
    cn = Contract.query.get_or_404(contract_id)
    pdf_abs = _generate_contract_pdf(cn)

    if not (pdf_abs and os.path.exists(pdf_abs)):
        flash("PDF engine not available or failed to generate. Check ReportLab and logs.", "danger")
        return redirect(url_for("admin_contract_view", contract_id=contract_id))

    return send_file(
        pdf_abs,
        as_attachment=True,
        download_name=f"4UIT-contract-{cn.id}.pdf"
    )


# -------------------------------------------------
# Static for uploads
# -------------------------------------------------
@app.get("/uploads/signatures/<path:filename>")
def get_signature(filename):
    """
    Serve assinaturas procurando em múltiplas raízes:
    - UPLOAD_SIGS_DIR (persistente)
    - BASE_DIR/uploads/signatures (legado)
    - BASE_DIR/uploads (se o caminho veio completo "uploads/signatures/...")
    """
    candidates = []

    # 1) Persistente
    candidates.append(os.path.join(UPLOAD_SIGS_DIR, filename))

    # 2) Legado (BASE_DIR/uploads/signatures)
    legacy_dir = os.path.join(BASE_DIR, "uploads", "signatures")
    candidates.append(os.path.join(legacy_dir, filename))

    # 3) Caso o filename já venha com "uploads/signatures/..."
    if filename.startswith("uploads/"):
        candidates.append(os.path.join(BASE_DIR, filename))
        # e também tentar relativo à raiz persistente
        candidates.append(os.path.join(UPLOAD_ROOT, filename.replace("uploads/", "")))

    for cand in candidates:
        if os.path.isfile(cand):
            # devolver do diretório em que achamos
            return send_file(cand)

    # não achou: 404
    abort(404)



# ============================
# Public review (client)
# ============================
@app.get("/review/<token>")
def public_review(token):
    asset = Asset.query.filter_by(public_token=token).first_or_404()
    storage_url = _public_url(asset.storage_path)
    thumb_url   = _public_url(asset.thumbnail_path)
    external_url = asset.external_url

    return render_template(
        "public_review.html",
        asset=asset,
        token=token,
        storage_url=storage_url,
        thumb_url=thumb_url,
        external_url=external_url,
    )


@app.post("/review/<token>/decision")
def public_review_decision(token):
    asset = Asset.query.filter_by(public_token=token).first_or_404()

    decision = (request.form.get("decision") or "").strip().lower()
    comment = (request.form.get("comment") or "").strip()
    scheduled_for_raw = (request.form.get("scheduled_for") or "").strip()

    if decision not in ("approve", "reject"):
        return render_template_string("<p class='error'>Invalid decision.</p>"), 400

    scheduled_dt = None
    if scheduled_for_raw:
        try:
            scheduled_dt = datetime.fromisoformat(scheduled_for_raw)
            if scheduled_dt.tzinfo is None:
                scheduled_dt = scheduled_dt.replace(tzinfo=timezone.utc)
        except Exception:
            scheduled_dt = None

    if decision == "reject" and not comment:
        storage_url = f"/{asset.storage_path}" if asset.storage_path else None
        thumb_url = f"/{asset.thumbnail_path}" if asset.thumbnail_path else None
        return render_template(
            "public_review.html",
            asset=asset,
            token=token,
            storage_url=storage_url,
            external_url=asset.external_url,
            error="Please add a comment to explain the rejection."
        ), 400

    if decision == "approve":
        asset.status = "approved"
        asset.approved_at = utcnow()
        asset.rejection_reason = None
    else:
        asset.status = "rejected"
        asset.rejection_reason = comment or "Rejected by client"
        asset.approved_at = None

    asset.client_comment = comment or None
    if scheduled_dt:
        asset.scheduled_for = scheduled_dt

    asset.updated_at = utcnow()
    try:
        db.session.flush()
        db.session.commit()
        db.session.refresh(asset)
        app.logger.info("Asset #%s marked as %s by public review", asset.id, asset.status)
    except Exception as e:
        db.session.rollback()
        app.logger.exception("Failed to persist public decision for asset #%s: %s", asset.id, e)
        return render_template_string("<p class='error'>Could not save your decision. Please try again.</p>"), 500

    try:
        action_label = "approved" if decision == "approve" else "rejected"
        class _Review: ...
        review = _Review()
        review.comments = comment or None
        notify_team_asset_review_feedback(asset, review, action_label)
    except Exception as e:
        app.logger.warning("public_review_decision: notify_team_asset_review_feedback failed: %s", e)

    return render_template("review_confirmation.html", asset=asset)


# ============================
# Portal do Cliente
# ============================
def _client_assets_query_for_user(user: User):
    return (Asset.query
            .join(Client, Asset.client_id == Client.id, isouter=True)
            .filter(Client.contact_email == user.email))

@app.get("/portal")
@login_required
def portal_home():
    if getattr(current_user, "role", "") == "admin":
        return redirect(url_for("admin_home"))
    return redirect(url_for("portal_contracts"))


@app.get("/portal/assets")
@login_required
def portal_assets():
    if getattr(current_user, "role", "") == "admin":
        return redirect(url_for("assets_list"))
    assets = (_client_assets_query_for_user(current_user)
              .order_by(desc(Asset.created_at), desc(Asset.id)).all())
    review_base = request.host_url.rstrip("/") + "/review/"
    return render_template("portal_assets.html", portal_active="assets", assets=assets, review_base=review_base)


@app.get("/portal/assets/<int:asset_id>")
@login_required
def portal_asset_detail(asset_id: int):
    if getattr(current_user, "role", "") == "admin":
        return redirect(url_for("asset_detail", asset_id=asset_id))
    a = (_client_assets_query_for_user(current_user)
         .filter(Asset.id == asset_id).first_or_404())
    if not a.public_token:
        ensure_public_token(a)
        db.session.commit()
    review_url = f"{request.host_url.rstrip('/')}/review/{a.public_token}"
    preview_url = f"/{a.thumbnail_path or a.storage_path}" if (a.thumbnail_path or a.storage_path) else None
    return render_template("portal_asset_detail.html", a=a, review_url=review_url, preview_url=preview_url)


@app.get("/portal/reports")
@login_required
def portal_reports():
    if getattr(current_user, "role", "") == "admin":
        return redirect(url_for("admin_home"))
    return render_template("portal_reports.html")


# -------------------------------------------------
# Contract Templates (Admin)
# -------------------------------------------------
@app.route("/admin/contract-templates", methods=["GET", "POST"])
@admin_required
def contract_templates_list():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        body = (request.form.get("body") or "").strip()
        is_default = bool(request.form.get("is_default"))
        if not name or not body:
            flash("Name and Body are required.", "danger")
        else:
            if is_default:
                ContractTemplate.query.update({ContractTemplate.is_default: False})
            t = ContractTemplate(name=name, body=body, is_default=is_default)
            db.session.add(t)
            db.session.commit()
            flash("Template created.", "success")
            return redirect(url_for("contract_templates_list"))

    templates = ContractTemplate.query.order_by(ContractTemplate.updated_at.desc()).all()
    return render_template("contract_templates_list.html", templates=templates)


@app.route("/admin/contract-templates/<int:tpl_id>/edit", methods=["GET", "POST"])
@admin_required
def contract_templates_edit(tpl_id: int):
    tpl = ContractTemplate.query.get_or_404(tpl_id)
    if request.method == "POST":
        tpl.name = (request.form.get("name") or "").strip()
        tpl.body = (request.form.get("body") or "").strip()
        is_default = bool(request.form.get("is_default"))
        if is_default:
            ContractTemplate.query.update({ContractTemplate.is_default: False})
            tpl.is_default = True
        else:
            tpl.is_default = False
        if not tpl.name or not tpl.body:
            flash("Name and Body are required.", "danger")
        else:
            db.session.commit()
            flash("Template saved.", "success")
            return redirect(url_for("contract_templates_list"))

    return render_template("contract_template_edit.html", tpl=tpl)


@app.post("/admin/contract-templates/<int:tpl_id>/delete")
@admin_required
def contract_templates_delete(tpl_id: int):
    tpl = ContractTemplate.query.get_or_404(tpl_id)
    db.session.delete(tpl)
    db.session.commit()
    flash("Template deleted.", "warning")
    return redirect(url_for("contract_templates_list"))


@app.route("/admin/clients/<int:client_id>/contract", methods=["GET", "POST"])
@admin_required
def client_contract_pref(client_id: int):
    c = Client.query.get_or_404(client_id)
    pref = ClientContractPref.query.filter_by(client_id=c.id).first()
    templates = ContractTemplate.query.order_by(ContractTemplate.name.asc()).all()

    if request.method == "POST":
        tpl_id = request.form.get("template_id", type=int)
        override_text = (request.form.get("override_text") or "").strip() or None

        if not pref:
            pref = ClientContractPref(client_id=c.id)
            db.session.add(pref)

        pref.template_id = tpl_id
        pref.override_text = override_text
        db.session.commit()

        to = (c.contact_email or "").strip()
        if to:
            brand = "4UIT Solutions"
            contract_url, access_url = _build_onboarding_links(c, external=True)
            subject = f"{c.company_name or 'Client'} — Please review and e-sign your 4UIT agreement"

            text_body = f"""Hello,

Please review and e-sign your agreement with {brand}:

Contract: {contract_url}

(Optional) You can also pre-share access info for Ads/Analytics/Domain/Hosting here:
{access_url}

Thank you,
{brand}
"""

            html_body = f"""
            <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif">
              <p>Hello{(' ' + (c.legal_representative or '')).strip()}</p>
              <p>Please review and e-sign your agreement with <strong>{brand}</strong>:</p>
              <p>
                <a href="{contract_url}" style="background:#0d6efd;color:#fff;padding:10px 14px;border-radius:10px;text-decoration:none;font-weight:600">
                  Open &amp; Sign Contract
                </a>
              </p>
              <p style="margin-top:12px">
                (Optional) You can also pre-share access info for Ads/Analytics/Domain/Hosting:<br/>
                <a href="{access_url}">{access_url}</a>
              </p>
              <p>Thank you,<br/>{brand}</p>
            </div>
            """

            cc_list = _split_emails(os.getenv("ADMIN_EMAIL")) or _split_emails(os.getenv("NOTIFY_TO")) or None
            try:
                send_email(subject, text_body, html_body, to_addrs=[to], cc_addrs=cc_list, attachments=None)
                flash(f"Onboarding e-mail sent to {to}.", "success")
            except Exception as e:
                app.logger.exception("Failed to send onboarding email: %s", e)
                flash(f"Preference saved, but failed to send onboarding e-mail: {e}", "danger")
        else:
            flash("Preference saved. No e-mail sent (client has no contact_email).", "warning")

        return redirect(url_for("clients_list"))

    share_url = url_for("contract_page", client_id=c.id, _external=True)
    return render_template(
        "client_contract_pref.html",
        client=c,
        pref=pref,
        templates=templates,
        share_url=share_url,
    )


# --- Helpers de vínculo cliente-usuário ---
def _client_for_user(user: User):
    if not user or not user.is_authenticated:
        return None
    return Client.query.filter(Client.contact_email == user.email).first()


# ================
# Portal — CONTRATOS
# ================
@app.get("/portal/contracts")
@login_required
def portal_contracts():
    client = _portal_find_client_for_user()

    contracts = []
    access_rows = []
    access_last = None

    if client:
        contracts = (Contract.query
                     .filter_by(client_id=client.id)
                     .order_by(Contract.id.asc())
                     .all())

        access_rows = (AccessRequest.query
                       .filter_by(client_id=client.id)
                       .order_by(AccessRequest.id.asc())
                       .all())

        access_last = access_rows[-1] if access_rows else None

    # destino do botão "Fill my access info" -> rota existente do portal
    access_prefill = url_for("portal_access")

    return render_template(
        "portal_contracts.html",
        client=client,
        contracts=contracts,
        access_rows=access_rows,
        access_last=access_last,
        access_prefill=access_prefill,
    )



@app.get("/portal/contract/<int:contract_id>/pdf")
@login_required
def portal_contract_pdf(contract_id):
    contract = Contract.query.get_or_404(contract_id)
    client = Client.query.get_or_404(contract.client_id)

    # autorização básica: o usuário do portal precisa pertencer a este client
    my_client = _portal_find_client_for_user()
    if not my_client or my_client.id != client.id:
        abort(403)

    # Gera (se preciso) e devolve o PDF existente (mesmo gerador do Admin)
    pdf_abs = _safe_generate_contract_pdf(contract)
    if not (pdf_abs and os.path.exists(pdf_abs)):
        abort(404)
    return send_file(
    pdf_abs,
    mimetype="application/pdf",
    as_attachment=True,
    download_name=f"contract_{contract.id}.pdf",
)


# ======================
# Portal — ACCESS REQUESTS
# ======================
@app.get("/portal/access")
@login_required
def portal_access():
    # encontrar o client do usuário logado
    client = _portal_find_client_for_user()
    if not client:
        flash("We couldn't link your user to a client. Please contact support.", "warning")
        return redirect(url_for("portal_contracts"))

    # (opcional) últimos envios só para contexto, caso seu template use
    access_rows = (AccessRequest.query
                   .filter_by(client_id=client.id)
                   .order_by(AccessRequest.submitted_at.desc())
                   .all())
    access_last = access_rows[0] if access_rows else None

    # renderiza o MESMO template já usado na rota pública
    # mantendo as mesmas variáveis esperadas pelo access_request.html
    return render_template(
        "access_request.html",
        prefill_company=(client.company_name or ""),
        prefill_email=(getattr(current_user, "email", None) or client.contact_email or ""),
        access_last=access_last,
        access_rows=access_rows,
    )


# --------------- ROTA: Portal (cliente) baixar PDF do Access ----------------
@app.route("/portal/access/<int:access_id>/pdf")
@login_required
def portal_access_pdf(access_id):
    # autorização: usuário logado precisa pertencer ao mesmo Client do AccessRequest
    ar = AccessRequest.query.get_or_404(access_id)
    my_client = _portal_find_client_for_user()
    if not my_client or my_client.id != ar.client_id:
        abort(403)

    # Reaproveita o mesmo gerador padronizado do admin
    abs_path = _access_request_pdf_path(ar.id)
    if not os.path.exists(abs_path):
        _generate_access_request_pdf(ar)

    return send_file(
        abs_path,
        mimetype="application/pdf",
        download_name=f"access-{access_id}.pdf",
        as_attachment=True
    )



# ======================
# Portal — Asset Review (única definição)
# ======================
def _resolve_user_client_id():
    cid = getattr(current_user, "client_id", None)
    if cid:
        return cid
    if hasattr(current_user, "client") and getattr(current_user, "client", None):
        try:
            return current_user.client.id
        except Exception:
            pass
    user_email = getattr(current_user, "email", None)
    if user_email:
        c = Client.query.filter(
            or_(
                Client.contact_email == user_email,
                Client.account_manager_email == user_email,
            )
        ).first()
        if c:
            return c.id
    return None


def _client_asset_for_user(asset_id: int):
    asset = Asset.query.get_or_404(asset_id)
    if getattr(current_user, "role", None) == "admin":
        client = asset.client if hasattr(asset, "client") else Client.query.get(asset.client_id)
        return client, asset
    user_client_id = _resolve_user_client_id()
    if not user_client_id:
        abort(403)
    if asset.client_id != user_client_id:
        abort(403)
    client = asset.client if hasattr(asset, "client") else Client.query.get(user_client_id)
    return client, asset


@app.get("/portal/assets/<int:asset_id>/review")
@login_required
def portal_asset_review(asset_id: int):
    if getattr(current_user, "role", "") == "admin":
        return redirect(url_for("asset_detail", asset_id=asset_id))

    client, asset = _client_asset_for_user(asset_id)
    if not asset:
        flash("Asset not found for your account.", "error")
        return redirect(url_for("portal_assets"))

    preview_url = None
    if getattr(asset, "thumbnail_path", None):
        preview_url = f"/{asset.thumbnail_path}"
    elif getattr(asset, "storage_path", None):
        preview_url = f"/{asset.storage_path}"

    reviews = (AssetReview.query
               .filter_by(asset_id=asset.id, client_id=client.id)
               .order_by(desc(AssetReview.created_at), desc(AssetReview.id))
               .all())

    return render_template("portal_asset_review.html",
                           portal_active="assets",
                           a=asset,
                           preview_url=preview_url,
                           reviews=reviews)


@app.post("/portal/assets/<int:asset_id>/review")
@login_required
def portal_asset_review_submit(asset_id: int):
    if getattr(current_user, "role", "") == "admin":
        return redirect(url_for("asset_detail", asset_id=asset_id))

    client, asset = _client_asset_for_user(asset_id)
    if not asset:
        flash("Asset not found for your account.", "error")
        return redirect(url_for("portal_assets"))

    action = request.form.get("action")  # approve | changes | reject
    note = (request.form.get("note") or "").strip()

    status_map = {
        "approve": "approved",
        "changes": "changes_requested",
        "reject": "rejected",
    }
    if action not in status_map:
        flash("Invalid action.", "error")
        return redirect(url_for("portal_asset_review", asset_id=asset.id))

    if action in ("changes", "reject") and not note:
        flash("Please add a note explaining your request.", "error")
        return redirect(url_for("portal_asset_review", asset_id=asset.id))

    rev = AssetReview(
        asset_id=asset.id,
        client_id=client.id,
        status=status_map[action],
        note=note or None,
        created_by_email=getattr(current_user, "email", None),
    )
    db.session.add(rev)

    asset.status = rev.status
    db.session.commit()

    try:
        action_map = {
            "approved": "approved",
            "changes_requested": "changes requested",
            "rejected": "rejected",
        }
        action_label = action_map.get(rev.status, rev.status)
        class _Review: ...
        review = _Review()
        review.comments = note or None
        notify_team_asset_review_feedback(asset, review, action_label)
    except Exception as e:
        app.logger.warning("portal_asset_review_submit: notify_team_asset_review_feedback failed: %s", e)

    flash("Feedback submitted. Thank you!", "success")
    return redirect(url_for("portal_asset_review", asset_id=asset.id))


# -------------------------------------------------
# Main
# -------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
