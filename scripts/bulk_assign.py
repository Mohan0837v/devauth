#!/usr/bin/env python3
import csv, sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))  # project root
from app import create_app
from app.models import db, User, App, UserApp

if len(sys.argv) < 2:
    print("Usage: python scripts/bulk_assign.py assignments.csv")
    sys.exit(1)

csvfile = sys.argv[1]
app = create_app()
with app.app_context():
    with open(csvfile, newline='') as f:
        rdr = csv.DictReader(f)
        for row in rdr:
            email = row.get("user_email","").strip().lower()
            app_name = row.get("app_name","").strip()
            if not email or not app_name:
                print("skip invalid row", row); continue
            user = User.query.filter_by(email=email).first()
            a = App.query.filter_by(name=app_name).first()
            if not user:
                print("user not found:", email); continue
            if not a:
                print("app not found:", app_name); continue
            ua = UserApp.query.filter_by(user_id=user.id, app_id=a.id).first()
            if ua:
                print("already assigned:", email, app_name)
                continue
            ua = UserApp(user_id=user.id, app_id=a.id, enabled=True)
            db.session.add(ua); db.session.commit()
            print("assigned", email, "->", app_name)

