from flask import Blueprint, flash, g, redirect, render_template, request, url_for
from werkzeug.exceptions import abort

from cheonma.auth import login_required, admin_required
from cheonma.db import get_db

bp = Blueprint("dashboard", __name__)


@bp.route("/")
@login_required
def index():
    db = get_db()

    profile_picture = db.execute(
        "SELECT profile_picture FROM user u JOIN info i ON u.info_id = i.id WHERE u.id = ?",
        (g.user["id"],),
    ).fetchone()[0]
    
    user = db.execute(
        "SELECT u.id, username, first_name, last_name, email, profile_picture, type FROM user u JOIN info i ON u.info_id = i.id WHERE u.id = ?",
        (g.user["id"],),
    ).fetchone()
    
    return render_template("dashboard/index.html", user=user, profile_picture=profile_picture)


@bp.route("/users")
@login_required
@admin_required
def users():
    db = get_db()
    users = db.execute(
        "SELECT u.id, username, first_name, last_name, email, profile_picture, type FROM user u JOIN info i ON u.info_id = i.id WHERE u.id <> ?",
        (g.user["id"],),
    ).fetchall()

    profile_picture = db.execute(
        "SELECT profile_picture FROM user u JOIN info i ON u.info_id = i.id WHERE u.id = ?",
        (g.user["id"],),
    ).fetchone()[0]
    
    user = db.execute(
        "SELECT u.id, first_name, last_name FROM user u JOIN info i ON u.info_id = i.id WHERE u.id = ?",
        (g.user["id"],),
    ).fetchone()

    return render_template(
        "dashboard/users.html", profile_picture=profile_picture, user=user, users=users
    )
