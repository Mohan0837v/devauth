# app/sso.py
from flask import Blueprint, session, redirect, url_for, render_template, request, flash, jsonify
from .models import App, UserApp, User, AuthorizationCode, OAuthToken, db
from .utils import sign_jwt, verify_jwt
from datetime import datetime, timedelta
import json
import uuid

sso_bp = Blueprint("sso", __name__, template_folder="templates")

# Helper to require login for launch flows
def require_login_redirect():
    if not session.get("user_id"):
        return redirect(url_for("auth.login"))
    return None

# -------------------- IdP-initiated SAML-like flow --------------------
# This will create a signed JWT containing minimal user claims and auto-post it to the ACS URL.
# Final URL will be: /sso/idp_initiate/<app_id>  (because blueprint is registered with url_prefix="/sso")
@sso_bp.route("/idp_initiate/<app_id>")
def idp_initiate(app_id):
    # guard: must be logged in
    if not session.get("user_id"):
        return redirect(url_for("auth.login"))
    uid = session.get("user_id")
    user = User.query.get(uid)
    if not user:
        return redirect(url_for("auth.login"))

    a = App.query.get(app_id)
    if not a:
        return "app not found", 404

    # require app belongs to same tenant as user (defensive)
    if getattr(user, "tenant_id", None) and getattr(a, "tenant_id", None) and user.tenant_id != a.tenant_id:
        return "app not in your tenant", 403

    # Build assertion payload (JWT). Keep minimal claims for demo.
    payload = {
        "sub": user.id,
        "email": user.email,
        "name": user.full_name,
        "iat": int(datetime.utcnow().timestamp()),
        "nbf": int(datetime.utcnow().timestamp()),
    }
    # optional: include app id and tenant info
    payload["aud"] = a.id
    payload["tenant_id"] = user.tenant_id

    token = sign_jwt(payload, expire_minutes=5)

    # If app.config is a plain ACS URL (SAML-style), post form to it with 'SAMLResponse' field
    acs_url = a.config if a.type == "saml" else None
    if acs_url:
        # Render auto-posting form template
        return render_template("saml_post.html", acs_url=acs_url, assertion=token)
    else:
        # For demo, if missing, just return the token and a link
        return jsonify({"assertion": token, "note": "No ACS URL configured for this app."})

# -------------------- OAuth2 Authorization Endpoint (minimal) --------------------
# Example request:
# GET /sso/oauth/authorize?response_type=code&client_id=<client>&redirect_uri=<uri>&state=...
@sso_bp.route("/oauth/authorize")
def oauth_authorize():
    # require login
    if not session.get("user_id"):
        # redirect to login preserving original request via next param is omitted for brevity
        return redirect(url_for("auth.login"))

    client_id = request.args.get("client_id")
    response_type = request.args.get("response_type")
    redirect_uri = request.args.get("redirect_uri")
    state = request.args.get("state", "")
    scope = request.args.get("scope", "")

    if not client_id or response_type != "code":
        return "invalid_request", 400

    # Validate client exists (app registration stores client_id in config JSON)
    # We search oauth apps and parse their config to find a matching client_id
    a = None
    oauth_apps = App.query.filter_by(type="oauth").all()
    for app_obj in oauth_apps:
        try:
            cfg = json.loads(app_obj.config or "{}")
        except Exception:
            cfg = {}
        if cfg.get("client_id") == client_id:
            a = app_obj
            break

    if not a:
        return "unknown_client", 400

    # parse config to verify redirect_uri matches
    try:
        cfg = json.loads(a.config or "{}")
    except Exception:
        cfg = {}
    valid_uris = []
    if "redirect_uri" in cfg:
        valid_uris = [cfg["redirect_uri"]]
    elif "redirect_uris" in cfg:
        valid_uris = cfg["redirect_uris"]
    if redirect_uri not in valid_uris:
        return "invalid_redirect_uri", 400

    # Auto-approve for MVP: issue auth code
    code = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(minutes=5)
    auth = AuthorizationCode(
        id=code,
        client_id=client_id,
        user_id=session.get("user_id"),
        redirect_uri=redirect_uri,
        scope=scope,
        created_at=datetime.utcnow(),
        expires_at=expires_at
    )
    db.session.add(auth)
    db.session.commit()

    # redirect back to client with code
    separator = "?" if "?" not in redirect_uri else "&"
    return redirect(f"{redirect_uri}{separator}code={code}&state={state}")

# -------------------- OAuth2 Token Endpoint (minimal) --------------------
# POST /sso/oauth/token with client_id, client_secret, code, redirect_uri, grant_type=authorization_code
@sso_bp.route("/oauth/token", methods=["POST"])
def oauth_token():
    grant_type = request.form.get("grant_type")
    if grant_type != "authorization_code":
        return jsonify({"error": "unsupported_grant_type"}), 400
    code = request.form.get("code")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")
    redirect_uri = request.form.get("redirect_uri")

    if not code or not client_id or not client_secret:
        return jsonify({"error": "invalid_request"}), 400

    # find auth code
    auth = AuthorizationCode.query.get(code)
    if not auth:
        return jsonify({"error": "invalid_grant"}), 400
    if auth.client_id != client_id or auth.redirect_uri != redirect_uri:
        return jsonify({"error": "invalid_grant"}), 400
    if auth.expires_at < datetime.utcnow():
        return jsonify({"error": "invalid_grant", "error_description": "code_expired"}), 400

    # find client app by client_id and client_secret
    app_obj = None
    apps = App.query.filter_by(type="oauth").all()
    for a in apps:
        try:
            cfg = json.loads(a.config or "{}")
        except:
            cfg = {}
        if cfg.get("client_id") == client_id and cfg.get("client_secret") == client_secret:
            app_obj = a
            break
    if not app_obj:
        return jsonify({"error": "invalid_client"}), 401

    # success: issue access_token (JWT) and refresh token
    user = User.query.get(auth.user_id)
    payload = {
        "sub": user.id,
        "email": user.email,
        "name": user.full_name,
        "aud": client_id,
        "tenant_id": user.tenant_id,
    }
    access_token = sign_jwt(payload, expire_minutes=60)
    refresh = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(hours=1)

    tok = OAuthToken(access_token=access_token, refresh_token=refresh, client_id=client_id, user_id=user.id, expires_at=expires_at)
    db.session.add(tok)
    # remove used auth code
    db.session.delete(auth)
    db.session.commit()

    return jsonify({
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 3600,
        "refresh_token": refresh
    })

#---------------------for the/oauth/userinfo-------------------------------

@sso_bp.route("/oauth/userinfo", methods=["GET","POST"])
def oauth_userinfo():
    auth = request.headers.get("Authorization", "")
    token = None
    if auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1].strip()
    if not token:
        token = request.values.get("token") or request.form.get("token")
    if not token:
        return jsonify({"error": "missing_token"}), 400

    payload = verify_jwt(token)
    if not payload:
        return jsonify({"error": "invalid_token"}), 401

    userinfo = {
        "sub": payload.get("sub"),
        "email": payload.get("email"),
        "name": payload.get("name"),
        "tenant_id": payload.get("tenant_id")
    }
    return jsonify(userinfo)


# -------------------- Token introspection (dev helper) --------------------
@sso_bp.route("/oauth/introspect", methods=["POST"])
def oauth_introspect():
    token = request.form.get("token")
    res = verify_jwt(token)
    if not res:
        return jsonify({"active": False})
    return jsonify({"active": True, "payload": res})

