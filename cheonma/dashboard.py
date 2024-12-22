from flask import Blueprint, flash, g, redirect, render_template, request, url_for
from werkzeug.exceptions import abort

from cheonma.auth import login_required
from cheonma.db import get_db

bp = Blueprint("dashboard", __name__)


@bp.route("/")
@login_required
def index():
    if g.user["type"] == "admin":
        db = get_db()

        users = db.execute(
            "SELECT u.id, first_name, last_name, email, username, type FROM user u JOIN info i ON u.info_id = i.id WHERE u.id <> ?",
            (g.user["id"],),
        ).fetchall()
    else:
        users = None

    return render_template("dashboard/index.html", users=users)
