from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid
from sqlalchemy import ForeignKey # NEW IMPORT

db = SQLAlchemy()

def gen_uuid():
    return str(uuid.uuid4())

# NEW TENANT MODEL
class Tenant(db.Model):
    id = db.Column(db.String, primary_key=True, default=gen_uuid)
    name = db.Column(db.String, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# UPDATED USER MODEL (with tenant_id and unique=False for email)
class User(db.Model):
    id = db.Column(db.String, primary_key=True, default=gen_uuid)
    tenant_id = db.Column(db.String, db.ForeignKey("tenant.id"), nullable=True) # NEW
    email = db.Column(db.String, unique=False, nullable=False) # CHANGED: unique=False
    password_hash = db.Column(db.String, nullable=False)
    full_name = db.Column(db.String, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# UPDATED APP MODEL (with tenant_id)
class App(db.Model):
    id = db.Column(db.String, primary_key=True, default=gen_uuid)
    tenant_id = db.Column(db.String, db.ForeignKey("tenant.id"), nullable=True) # NEW
    name = db.Column(db.String, nullable=False)
    type = db.Column(db.String, nullable=False)  # 'saml' or 'oauth'
    config = db.Column(db.Text)  # JSON string or ACS url
    owner_id = db.Column(db.String)  # admin who created

# UPDATED USERAPP MODEL (with tenant_id)
class UserApp(db.Model):
    id = db.Column(db.String, primary_key=True, default=gen_uuid)
    tenant_id = db.Column(db.String, db.ForeignKey("tenant.id"), nullable=True) # NEW
    user_id = db.Column(db.String, db.ForeignKey("user.id"), nullable=False)
    app_id = db.Column(db.String, db.ForeignKey("app.id"), nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# UPDATED AUDITLOG MODEL (RECOMMENDED: add tenant_id)
class AuditLog(db.Model):
    id = db.Column(db.String, primary_key=True, default=gen_uuid)
    tenant_id = db.Column(db.String, db.ForeignKey("tenant.id"), nullable=True) # RECOMMENDED NEW
    user_id = db.Column(db.String, nullable=True)  # admin who did the action
    action = db.Column(db.String, nullable=False)  # e.g. 'create_app','edit_app','delete_app'
    target_type = db.Column(db.String, nullable=True)  # e.g. 'app','user','assignment'
    target_id = db.Column(db.String, nullable=True)
    details = db.Column(db.Text)  # optional JSON/text details
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# OAuth / SSO models — add these near bottom of app/models.py

class AuthorizationCode(db.Model):
    id = db.Column(db.String, primary_key=True, default=gen_uuid)  # code value
    client_id = db.Column(db.String, nullable=False)
    user_id = db.Column(db.String, db.ForeignKey("user.id"), nullable=False)
    redirect_uri = db.Column(db.String, nullable=False)
    scope = db.Column(db.String, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)

class OAuthToken(db.Model):
    id = db.Column(db.String, primary_key=True, default=gen_uuid)  # token id (refresh token or internal id)
    access_token = db.Column(db.String, nullable=False)  # JWT
    refresh_token = db.Column(db.String, nullable=True)
    client_id = db.Column(db.String, nullable=False)
    user_id = db.Column(db.String, db.ForeignKey("user.id"), nullable=False)
    expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


def init_db():
    # create tables if not exist
    db.create_all()
    # NOTE: do not auto-create a demo admin here.
    # The first real signup will become admin automatically (handled in auth.signup).

