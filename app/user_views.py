from flask import Blueprint, session, redirect, url_for, render_template, request, flash
from .models import User, App, UserApp, db
from .utils import hash_password, check_password

user_bp = Blueprint("user", __name__, template_folder="templates")

@user_bp.before_request
def require_login():
    if not session.get("user_id"):
        return redirect("/auth/login")

@user_bp.route("/workplace")
def workplace():
    uid = session.get("user_id")
    user = User.query.get(uid)
    if not user:
        return redirect("/auth/login")
    # fetch assigned apps for this user only
    user_apps = UserApp.query.filter_by(user_id=uid, tenant_id=user.tenant_id).all()
    apps = []
    for ua in user_apps:
        a = App.query.get(ua.app_id)
        if a and a.tenant_id == user.tenant_id:
            apps.append({"ua_id": ua.id, "name": a.name, "type": a.type, "enabled": ua.enabled, "app_id": a.id})
    # find admin(s) for this tenant (exclude current user if they are admin)
    admins = User.query.filter_by(tenant_id=user.tenant_id, is_admin=True).all()
    admin_list = [{"email": a.email, "full_name": a.full_name} for a in admins]
    return render_template("workplace.html", apps=apps, is_admin=bool(user and user.is_admin), tenant_admins=admin_list)


@user_bp.route("/toggle/<ua_id>", methods=["POST"])
def toggle(ua_id):
    ua = UserApp.query.get(ua_id)
    if not ua or ua.user_id != session.get("user_id"):
        return "not allowed", 403
    ua.enabled = not ua.enabled
    db.session.commit()
    return redirect(url_for("user.workplace"))

@user_bp.route("/launch/<app_id>")
def launch(app_id):
    # guard: ensure assigned and enabled
    uid = session.get("user_id")
    ua = UserApp.query.filter_by(user_id=uid, app_id=app_id).first()
    if not ua or not ua.enabled:
        return "app not assigned or disabled", 403
    a = App.query.get(app_id)
    if not a:
        return "no app", 404
    # forward to SSO endpoints (implemented later)
    if a.type == "saml":
        return redirect(url_for("sso.idp_initiate", app_id=app_id))
    else:
        import json
        md = json.loads(a.config or "{}")
        client_id = md.get("client_id")
        redirect_uri = md.get("redirect_uri")
        return redirect(f"/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}")

# Profile edit
@user_bp.route("/profile", methods=["GET","POST"])
def profile():
    uid = session.get("user_id")
    user = User.query.get(uid)
    if request.method == "POST":
        full_name = request.form.get("full_name","").strip()
        current_pwd = request.form.get("current_password","")
        new_pwd = request.form.get("new_password","")
        # update full name
        user.full_name = full_name
        # change password only if current password matches and new is provided
        if new_pwd:
            if not check_password(current_pwd, user.password_hash):
                flash("Current password is incorrect. Password not changed.")
                return redirect(url_for("user.profile"))
            user.password_hash = hash_password(new_pwd)
            flash("Password changed.")
        db.session.commit()
        flash("Profile updated.")
        return redirect(url_for("user.profile"))
    return render_template("profile.html", user=user)

