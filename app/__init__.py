import os
from flask import Flask, session, render_template
from .models import db, init_db
from .auth import auth_bp
from .user_views import user_bp
from .admin import admin_bp
from .sso import sso_bp

def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.update(
        SECRET_KEY=os.getenv("DEVAUTH_SECRET", "dev-secret-change-me"),
        SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///devauth.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    db.init_app(app)
    with app.app_context():
        init_db()

    # inject helper to templates
    @app.context_processor
    def inject_user():
        uid = None
        try:
            uid = session.get("user_id")
        except Exception:
            uid = None
        is_admin_flag = False
        if uid:
            from .models import User
            u = User.query.get(uid)
            if u and u.is_admin:
                is_admin_flag = True
        return dict(is_admin=is_admin_flag, session=session)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp, url_prefix="/user")
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(sso_bp, url_prefix="/sso")

    @app.route("/")
    def index():
        # Render a landing page with CTA
        return render_template("index.html")


    return app

