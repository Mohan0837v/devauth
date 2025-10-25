# app/admin.py
from flask import Blueprint, session, request, redirect, url_for, render_template, flash, jsonify
from .models import User, App, db, UserApp, AuditLog, Tenant
from .utils import hash_password, validate_oauth_config, validate_saml_config, parse_json_safe
import json

admin_bp = Blueprint("admin", __name__, template_folder="templates")

# ---------- helpers ----------
def current_admin_and_tenant():
    """Return (User object of current admin, tenant_id) or (None, None)."""
    uid = session.get("user_id")
    if not uid:
        return None, None
    u = User.query.get(uid)
    if not u:
        return None, None
    return u, u.tenant_id

def log_action(user_id, tenant_id, action, target_type=None, target_id=None, details=None):
    """Create an audit log entry. Safe: rolls back on error."""
    try:
        entry = AuditLog(
            tenant_id=tenant_id,
            user_id=user_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=json.dumps(details) if details is not None else None
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()

@admin_bp.before_request
def require_admin():
    uid = session.get("user_id")
    if not uid:
        return redirect("/auth/login")
    u = User.query.get(uid)
    if not u or not u.is_admin:
        return "admin only", 403

# ---------- App listing (tenant-scoped) ----------
@admin_bp.route("/apps")
def apps():
    admin, tenant_id = current_admin_and_tenant()
    apps = App.query.filter_by(tenant_id=tenant_id).all()
    apps_with_assignments = []
    for a in apps:
        uas = UserApp.query.filter_by(app_id=a.id).all()
        assigned_users = []
        for ua in uas:
            # ensure user belongs to same tenant (defensive)
            user = User.query.get(ua.user_id)
            if user and user.tenant_id == tenant_id:
                assigned_users.append({"ua_id": ua.id, "email": user.email, "name": user.full_name, "enabled": ua.enabled})
        apps_with_assignments.append({"app": a, "assigned": assigned_users})
    return render_template("admin_apps.html", apps=apps_with_assignments)

# ---------- Create new app ----------
@admin_bp.route("/apps/new", methods=["GET","POST"])
def new_app():
    admin, tenant_id = current_admin_and_tenant()
    if request.method == "POST":
        name = request.form.get("name","").strip()
        typ = request.form.get("type","").strip()
        metadata = request.form.get("metadata","").strip()
        if not name or not typ:
            flash("name and type required"); return redirect(url_for("admin.new_app"))

        # validate config
        if typ == "oauth":
            ok, msg = validate_oauth_config(metadata)
            if not ok:
                flash(f"Invalid OAuth config: {msg}")
                return redirect(url_for("admin.new_app"))
        else:
            ok, msg = validate_saml_config(metadata)
            if not ok:
                flash(f"Invalid SAML config: {msg}")
                return redirect(url_for("admin.new_app"))

        a = App(name=name, type=typ, config=metadata, owner_id=admin.id, tenant_id=tenant_id)
        db.session.add(a); db.session.commit()
        log_action(admin.id, tenant_id, "create_app", target_type="app", target_id=a.id, details={"name":name,"type":typ})
        flash("app created")
        return redirect(url_for("admin.apps"))
    return render_template("admin_new_app.html")

# ---------- Edit app ----------
@admin_bp.route("/apps/edit/<app_id>", methods=["GET","POST"])
def edit_app(app_id):
    admin, tenant_id = current_admin_and_tenant()
    a = App.query.get(app_id)
    if not a or a.tenant_id != tenant_id:
        flash("app not found"); return redirect(url_for("admin.apps"))

    if request.method == "POST":
        old = {"name": a.name, "type": a.type, "config": a.config}
        new_name = request.form.get("name", a.name).strip()
        new_type = request.form.get("type", a.type).strip()
        new_config = request.form.get("metadata", a.config).strip()

        # validate new config
        if new_type == "oauth":
            ok, msg = validate_oauth_config(new_config)
            if not ok:
                flash(f"Invalid OAuth config: {msg}")
                return redirect(url_for("admin.edit_app", app_id=app_id))
        else:
            ok, msg = validate_saml_config(new_config)
            if not ok:
                flash(f"Invalid SAML config: {msg}")
                return redirect(url_for("admin.edit_app", app_id=app_id))

        a.name = new_name
        a.type = new_type
        a.config = new_config
        db.session.commit()
        log_action(admin.id, tenant_id, "edit_app", target_type="app", target_id=a.id, details={"before":old, "after":{"name":a.name,"type":a.type}})
        flash("app updated")
        return redirect(url_for("admin.apps"))

    return render_template("admin_edit_app.html", app=a)

# ---------- Delete app ----------
@admin_bp.route("/apps/delete", methods=["POST"])
def delete_app():
    admin, tenant_id = current_admin_and_tenant()
    app_id = request.form.get("app_id")
    a = App.query.get(app_id)
    if not a or a.tenant_id != tenant_id:
        flash("app not found"); return redirect(url_for("admin.apps"))
    details = {"name": a.name, "type": a.type, "config": a.config}
    # delete assignments and app
    UserApp.query.filter_by(app_id=a.id).delete()
    db.session.delete(a)
    db.session.commit()
    log_action(admin.id, tenant_id, "delete_app", target_type="app", target_id=app_id, details=details)
    flash("app deleted and assignments removed")
    return redirect(url_for("admin.apps"))

# ---------- App detail ----------
@admin_bp.route("/apps/<app_id>/detail")
def app_detail(app_id):
    admin, tenant_id = current_admin_and_tenant()
    a = App.query.get(app_id)
    if not a or a.tenant_id != tenant_id:
        flash("app not found"); return redirect(url_for("admin.apps"))
    parsed = parse_json_safe(a.config) if a.type == "oauth" else {"acs": a.config}
    uas = UserApp.query.filter_by(app_id=a.id).all()
    assigned = []
    for ua in uas:
        u = User.query.get(ua.user_id)
        if u and u.tenant_id == tenant_id:
            assigned.append({"ua_id": ua.id, "email": u.email, "name": u.full_name, "enabled": ua.enabled})
    return render_template("admin_app_detail.html", app=a, parsed=parsed, assigned=assigned)

# ---------- Assign app to user ----------
@admin_bp.route("/apps/assign", methods=["GET","POST"])
def assign_app():
    admin, tenant_id = current_admin_and_tenant()
    if request.method == "POST":
        user_email = request.form.get("user_email","").strip().lower()
        app_id = request.form.get("app_id")
        user = User.query.filter_by(email=user_email).first()
        if not user or user.tenant_id != tenant_id:
            flash("user not found in your tenant"); return redirect(url_for("admin.assign_app"))
        app_obj = App.query.get(app_id)
        if not app_obj or app_obj.tenant_id != tenant_id:
            flash("app not found in your tenant"); return redirect(url_for("admin.assign_app"))
        ua = UserApp.query.filter_by(user_id=user.id, app_id=app_id).first()
        if not ua:
            ua = UserApp(user_id=user.id, app_id=app_id, enabled=True, tenant_id=tenant_id)
            db.session.add(ua); db.session.commit()
            log_action(admin.id, tenant_id, "assign_app", target_type="assignment", target_id=ua.id, details={"user_email":user_email,"app_id":app_id})
        flash("assigned")
        return redirect(url_for("admin.apps"))
    apps = App.query.filter_by(tenant_id=tenant_id).all()
    return render_template("admin_assign.html", apps=apps)

# ---------- Remove assignment ----------
@admin_bp.route("/apps/remove_assignment", methods=["POST"])
def remove_assignment():
    admin, tenant_id = current_admin_and_tenant()
    ua_id = request.form.get("ua_id")
    ua = UserApp.query.get(ua_id)
    if not ua or ua.tenant_id != tenant_id:
        flash("assignment not found"); return redirect(url_for("admin.apps"))
    details = {"user_id": ua.user_id, "app_id": ua.app_id}
    db.session.delete(ua); db.session.commit()
    log_action(admin.id, tenant_id, "remove_assignment", target_type="assignment", target_id=ua_id, details=details)
    flash("assignment removed")
    return redirect(url_for("admin.apps"))

# ---------- Users: list/create ----------
@admin_bp.route("/users")
def users_list():
    admin, tenant_id = current_admin_and_tenant()
    users = User.query.filter_by(tenant_id=tenant_id).order_by(User.created_at.desc()).all()
    return render_template("admin_users.html", users=users)

@admin_bp.route("/users/new", methods=["GET","POST"])
def new_user():
    admin, tenant_id = current_admin_and_tenant()
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        full_name = request.form.get("full_name","").strip()
        pwd = request.form.get("password","")
        make_admin = request.form.get("make_admin") == "on"
        if not email or not pwd:
            flash("email and password required"); return redirect(url_for("admin.new_user"))
        # GLOBAL uniqueness: block if email already exists in ANY tenant
        if User.query.filter_by(email=email).first():
            flash("An account with this email already exists (globally). Choose a different email.")
            return redirect(url_for("admin.new_user"))
        u = User(email=email, full_name=full_name, password_hash=hash_password(pwd), is_admin=make_admin, tenant_id=tenant_id)
        db.session.add(u); db.session.commit()
        log_action(admin.id, tenant_id, "create_user", target_type="user", target_id=u.id, details={"email": email, "is_admin": make_admin})
        flash("user created")
        return redirect(url_for("admin.users_list"))
    return render_template("admin_new_user.html")


# ---------- Promote / toggle admin ----------
@admin_bp.route("/users/promote", methods=["POST"])
def promote_user():
    admin, tenant_id = current_admin_and_tenant()
    user_id = request.form.get("user_id")
    if not user_id:
        flash("missing user id"); return redirect(url_for("admin.users_list"))
    u = User.query.get(user_id)
    if not u or u.tenant_id != tenant_id:
        flash("user not found"); return redirect(url_for("admin.users_list"))
    u.is_admin = not bool(u.is_admin)
    db.session.commit()
    log_action(admin.id, tenant_id, "toggle_admin", target_type="user", target_id=u.id, details={"new_is_admin": u.is_admin})
    flash(f"User {u.email} admin status set to {u.is_admin}")
    return redirect(url_for("admin.users_list"))

# ---------- Delete user ----------
@admin_bp.route("/users/delete", methods=["POST"])
def delete_user():
    admin, tenant_id = current_admin_and_tenant()
    user_id = request.form.get("user_id")
    u = User.query.get(user_id)
    if not u or u.tenant_id != tenant_id:
        flash("user not found"); return redirect(url_for("admin.users_list"))
    details = {"email": u.email}
    UserApp.query.filter_by(user_id=u.id).delete()
    db.session.delete(u)
    db.session.commit()
    log_action(admin.id, tenant_id, "delete_user", target_type="user", target_id=user_id, details=details)
    flash("user deleted and assignments removed")
    return redirect(url_for("admin.users_list"))

# ---------- Audit view (tenant-scoped) ----------
@admin_bp.route("/audit")
def audit():
    admin, tenant_id = current_admin_and_tenant()
    # get recent logs for this tenant
    logs = AuditLog.query.filter_by(tenant_id=tenant_id).order_by(AuditLog.created_at.desc()).limit(200).all()
    enriched = []
    for l in logs:
        user = User.query.get(l.user_id) if l.user_id else None
        try:
            details = json.loads(l.details) if l.details else None
        except Exception:
            details = l.details
        enriched.append({"log": l, "user_email": user.email if user else None, "details": details})
    return render_template("admin_audit.html", logs=enriched)

# ---------- Admin JSON APIs ----------
@admin_bp.route("/api/apps")
def api_apps():
    admin, tenant_id = current_admin_and_tenant()
    apps = App.query.filter_by(tenant_id=tenant_id).all()
    out = []
    for a in apps:
        out.append({"id": a.id, "name": a.name, "type": a.type, "config_preview": (a.config[:200] if a.config else None)})
    return jsonify({"ok": True, "apps": out})

@admin_bp.route("/api/apps/<app_id>")
def api_app_detail(app_id):
    admin, tenant_id = current_admin_and_tenant()
    a = App.query.get(app_id)
    if not a or a.tenant_id != tenant_id:
        return jsonify({"ok": False, "error": "not_found"}), 404
    parsed = parse_json_safe(a.config) if a.type == "oauth" else {"acs": a.config}
    return jsonify({"ok": True, "app": {"id": a.id, "name": a.name, "type": a.type, "config": parsed}})

