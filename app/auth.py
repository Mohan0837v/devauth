from flask import Blueprint, request, session, redirect, url_for, render_template, flash
from .models import db, User
from .utils import hash_password, check_password

auth_bp = Blueprint("auth", __name__, template_folder="templates", static_folder="static")

@auth_bp.route("/auth/signup", methods=["GET","POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        pwd = request.form.get("password","")
        full_name = request.form.get("full_name","").strip()
        if not email or not pwd:
            flash("email and password required")
            return redirect(url_for("auth.signup"))

        # BLOCK if email already exists anywhere (global uniqueness)
        if User.query.filter_by(email=email).first():
            flash("An account with this email already exists. Please login or use a different email.")
            return redirect(url_for("auth.login"))

        # Create a new tenant for this signer-up person (demo flow: each new sign-up creates a new tenant)
        from .models import Tenant
        tenant_name = full_name or email.split("@")[0]
        tenant = Tenant(name=f"{tenant_name}-org")
        db.session.add(tenant)
        db.session.flush()  # get tenant.id

        # create user in this tenant
        is_admin_flag = True  # first user for this tenant becomes admin
        u = User(email=email, password_hash=hash_password(pwd), full_name=full_name, is_admin=is_admin_flag, tenant_id=tenant.id)
        db.session.add(u)
        db.session.commit()
        session["user_id"] = u.id
        flash("Tenant created and you are admin for your tenant.")
        return redirect(url_for("user.workplace"))
    return render_template("signup.html")

@auth_bp.route("/auth/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        pwd = request.form.get("password","")
        # exact match — expect at most one due to global uniqueness enforcement
        u = User.query.filter_by(email=email).first()
        if not u or not check_password(pwd, u.password_hash):
            flash("invalid credentials")
            return redirect(url_for("auth.login"))
        session["user_id"] = u.id
        return redirect(url_for("user.workplace"))
    return render_template("login.html")


@auth_bp.route("/auth/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("auth.login"))

