from extensions import db
from datetime import datetime, timezone
from sqlalchemy import Index, UniqueConstraint
from sqlalchemy.orm import relationship
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


def utcnow():
    return datetime.now(timezone.utc)


# -------------------- Clients --------------------
class Client(db.Model):
    __tablename__ = "client"
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(255), nullable=False)
    ein = db.Column(db.String(64))
    address = db.Column(db.String(255))
    legal_representative = db.Column(db.String(255))
    contact_email = db.Column(db.String(255))
    account_manager_email = db.Column(db.String(255))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)


# -------------------- Contracts --------------------
class Contract(db.Model):
    __tablename__ = "contract"
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("client.id"))
    signer_name = db.Column(db.String(255))
    signer_email = db.Column(db.String(255))
    signed_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    signer_ip = db.Column(db.String(64))
    user_agent = db.Column(db.Text)

    # LEGADO (local): continua funcionando
    signature_path = db.Column(db.String(255))

    # NOVO (Blob): usado quando Azure estiver configurado
    signature_blob = db.Column(db.String(512))  # ex.: 'signatures/uuid.png'

    contract_text = db.Column(db.Text)

    client = relationship("Client", backref="contracts")


# -------------------- Access Request --------------------
class AccessRequest(db.Model):
    __tablename__ = "access_request"
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("client.id"))

    instagram_user = db.Column(db.String(255))
    facebook_page = db.Column(db.String(255))
    meta_bm_id = db.Column(db.String(255))
    meta_ads_account_id = db.Column(db.String(255))
    google_ads_id = db.Column(db.String(32))

    analytics = db.Column(db.Boolean, default=False)
    tag_manager = db.Column(db.Boolean, default=False)
    search_console = db.Column(db.Boolean, default=False)

    website_url = db.Column(db.String(255))
    hosting = db.Column(db.String(255))
    hosting_login = db.Column(db.String(255))
    hosting_password = db.Column(db.String(255))
    domain_registrar = db.Column(db.String(255))
    domain_login = db.Column(db.String(255))
    domain_password = db.Column(db.String(255))

    brand_notes = db.Column(db.Text)

    submitted_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    signer_name = db.Column(db.String(255))
    signer_email = db.Column(db.String(255))
    signer_ip = db.Column(db.String(64))
    user_agent = db.Column(db.Text)
    signature_path = db.Column(db.String(255))

    client = relationship("Client", backref="access_requests")


# -------------------- Users --------------------
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    role = db.Column(db.String(32), default="admin")  # 'admin' | 'client'
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


# -------------------- Assets (área do cliente) --------------------
class Asset(db.Model):
    __tablename__ = "asset"
    id = db.Column(db.Integer, primary_key=True)

    # vínculo
    client_id = db.Column(db.Integer, db.ForeignKey("client.id"), nullable=False)

    # metadados
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    kind = db.Column(db.String(32), default="image")        # image | video | copy | ad | other
    status = db.Column(db.String(32), default="pending")    # pending | approved | rejected | posted

    # arquivo/local
    storage_path = db.Column(db.String(255))      # ex.: uploads/assets/<uuid>.png
    thumbnail_path = db.Column(db.String(255))    # ex.: uploads/assets/thumbs/<uuid>.jpg
    external_url = db.Column(db.String(255))      # Figma/Drive/Loom/etc.
    file_mime = db.Column(db.String(128))
    file_size = db.Column(db.Integer)

    # autoria / aprovação interna
    uploaded_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    approved_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    rejection_reason = db.Column(db.Text)

    # datas internas
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    approved_at = db.Column(db.DateTime(timezone=True))

    # públicos / agenda
    public_token = db.Column(db.String(64), unique=True, index=True)  # link público /review/<token>
    scheduled_for = db.Column(db.DateTime(timezone=True))             # quando pretendemos postar
    posted_at = db.Column(db.DateTime(timezone=True))                 # quando de fato foi postado
    client_comment = db.Column(db.Text)                               # comentário do cliente

    # relationships
    client = relationship("Client", backref="assets")
    uploaded_by = relationship("User", foreign_keys=[uploaded_by_user_id])
    approved_by = relationship("User", foreign_keys=[approved_by_user_id])


# Índice útil (client_id + status)
Index("idx_asset_client_status", Asset.client_id, Asset.status)


# -------------------- Contract templates --------------------
class ContractTemplate(db.Model):
    __tablename__ = "contract_templates"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    body = db.Column(db.Text, nullable=False)
    is_default = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ClientContractPref(db.Model):
    __tablename__ = "client_contract_prefs"
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("client.id"), nullable=False)
    template_id = db.Column(db.Integer, db.ForeignKey("contract_templates.id"))
    override_text = db.Column(db.Text)  # se preenchido, tem prioridade
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    client = db.relationship("Client", backref=db.backref("contract_pref", uselist=False))
    template = db.relationship("ContractTemplate")


# -------------------- Asset Reviews (portal do cliente) --------------------
class AssetReview(db.Model):
    __tablename__ = "asset_reviews"

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("asset.id"), nullable=False, index=True)   # <- tabela correta
    client_id = db.Column(db.Integer, db.ForeignKey("client.id"), nullable=False, index=True) # <- tabela correta
    status = db.Column(db.String(32), nullable=False)  # 'approved' | 'changes_requested' | 'rejected'
    note = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    created_by_email = db.Column(db.String(255))

    asset = db.relationship("Asset", backref=db.backref("reviews", lazy="dynamic"))
    client = db.relationship("Client", lazy="joined")
