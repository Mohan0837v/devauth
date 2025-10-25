from urllib.parse import urlparse
import bcrypt, os, datetime, jwt, json

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def current_admin_and_tenant():
    from .models import User, Tenant
    uid = session.get("user_id")
    if not uid:
        return None, None
    u = User.query.get(uid)
    tenant_id = u.tenant_id if u else None
    return u, tenant_id


# Simple JWT helpers (HMAC) for demo assertions/tokens
def sign_jwt(payload: dict, expire_minutes=10):
    secret = os.getenv("DEVAUTH_SECRET", "dev-secret-change-me")
    payload2 = payload.copy()
    payload2["exp"] = datetime.datetime.utcnow() + datetime.timedelta(minutes=expire_minutes)
    token = jwt.encode(payload2, secret, algorithm="HS256")
    return token

def verify_jwt(token: str):
    secret = os.getenv("DEVAUTH_SECRET", "dev-secret-change-me")
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except Exception:
        return None

#for the acs url and oauth config json safely

def is_valid_url(url: str) -> bool:
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False

def parse_json_safe(text: str):
    try:
        return json.loads(text) if text else None
    except Exception:
        return None

def validate_oauth_config(text: str) -> (bool, str):
    """
    For MVP: expect JSON containing at least `client_id` and `redirect_uri` (or redirect_uris list).
    Returns (valid:bool, message:str).
    """
    obj = parse_json_safe(text)
    if not obj or not isinstance(obj, dict):
        return False, "Invalid JSON for OAuth config"
    if "client_id" not in obj:
        return False, "Missing client_id"
    # check redirect_uri or redirect_uris
    if "redirect_uri" not in obj and "redirect_uris" not in obj:
        return False, "Provide redirect_uri or redirect_uris"
    # validate redirect URIs if present
    uris = []
    if "redirect_uri" in obj:
        uris = [obj["redirect_uri"]]
    else:
        uris = obj.get("redirect_uris") or []
    for u in uris:
        if not is_valid_url(u):
            return False, f"Invalid redirect URI: {u}"
    return True, "OK"

def validate_saml_config(text: str) -> (bool, str):
    """
    For MVP: expect a plain ACS URL or valid metadata URL. Validate it is a URL.
    """
    if not text or not isinstance(text, str):
        return False, "SAML ACS URL required"
    if not is_valid_url(text.strip()):
        return False, "Invalid ACS URL"
    return True, "OK"

