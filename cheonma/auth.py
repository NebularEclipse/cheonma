import click
import functools
import getpass

from flask import (
    Blueprint,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import abort

from cheonma.db import get_db

bp = Blueprint("auth", __name__, url_prefix="/auth")


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))

        return view(**kwargs)

    return wrapped_view


def admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user["type"] != "admin":
            abort(403)

        return view(**kwargs)

    return wrapped_view


@bp.route("/register", methods=("GET", "POST"))
@login_required
@admin_required
def register():
    if request.method == "POST":
        username = request.form["username"]
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        type = request.form["type"]
        db = get_db()
        error = None

        if not username:
            error = "Username is required."
        elif not password:
            error = "Password is required."
        elif not confirm_password:
            error = "Please confirm password."
        elif password != confirm_password:
            error = "Passwords don't match."
        elif not first_name:
            error = "First Name is required."
        elif not last_name:
            error = "Last Name is required."
        elif not email:
            error = "Email is required."

        if error is None:
            try:
                db.execute("BEGIN TRANSACTION")
                db.execute(
                    "INSERT INTO info (first_name, last_name, email)"
                    " VALUES (?, ?, ?)",
                    (first_name, last_name, email),
                )
                info_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                db.execute(
                    "INSERT INTO user (info_id, username, password, type)"
                    " VALUES (?, ?, ?, ?)",
                    (info_id, username, generate_password_hash(password), type),
                )
                db.commit()
                db.rollback()
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("index"))

        flash(error)

    return render_template("auth/register.html")


def get_user(id, check_type=True):
    user = (
        get_db()
        .execute(
            "SELECT u.id, info_id, first_name, last_name, email, username, password, type"
            " FROM user u JOIN info i ON u.info_id = i.id"
            " WHERE u.id = ?",
            (id,),
        )
        .fetchone()
    )

    if user is None:
        abort(404, f"User id {id} doesn't exist.")

    if check_type and user['id'] != g.user["id"]:
        abort(403)

    return user


@bp.route("/<int:id>/update_user", methods=("GET", "POST"))
@login_required
def update_user(id):
    user = get_user(id)

    if request.method == "POST":
        username = request.form["username"]
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        type = request.form["type"]
        error = None

        if not username:
            error = "Username is required."
        elif not password:
            error = "Password is required."
        elif not confirm_password:
            error = "Please confirm password."
        elif password != confirm_password:
            error = "Passwords don't match."
        elif not first_name:
            error = "First Name is required."
        elif not last_name:
            error = "Last Name is required."
        elif not email:
            error = "Email is required."

        if error is not None:
            flash(error)
        else:
            try:
                db = get_db()
                db.execute("BEGIN TRANSACTION")
                db.execute(
                    "UPDATE info SET first_name = ?, last_name = ?, email = ?"
                    " WHERE id = ?",
                    (first_name, last_name, email, user["info_id"]),
                )
                db.execute(
                    "UPDATE user SET username = ?, password = ?, type = ?"
                    " WHERE id = ?",
                    (username, password, type, id),
                )
                db.commit()
                db.rollback()
            except:
                pass
            return redirect(url_for("dashboard.index"))

    return render_template("auth/update_user.html", user=user)


@bp.route("/<int:id>/delete_user", methods=("GET", "POST"))
@login_required
@admin_required
def delete_user(id):
    user = get_user(id)
    try:
        db = get_db()
        db.execute("DELETE FROM info WHERE id = ?", (user["info_id"],))
        db.execute("DELETE FROM user WHERE id = ?", (id,))
        db.commit()
        db.rollback()
    except:
        pass
    return redirect(url_for("dashboard.index"))


@bp.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        error = None
        user = db.execute(
            "SELECT * FROM user WHERE username = ?", (username,)
        ).fetchone()

        if user is None:
            error = "Incorrect username."
        elif not check_password_hash(user["password"], password):
            error = "Incorrect password."

        if error is None:
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("index"))

        flash(error)

    return render_template("auth/login.html")


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get("user_id")

    if user_id is None:
        g.user = None
    else:
        g.user = (
            get_db().execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()
        )


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


def init_admin():
    db = get_db()
    error = None

    admin = db.execute("SELECT * FROM user WHERE type = ?", ("admin",)).fetchone()

    if not admin:
        username = input("Username: ")
        first_name = input("First Name: ")
        last_name = input("Last Name: ")
        email = input("Email: ")
        password = getpass.getpass("Password: ")
        confirm_password = getpass.getpass("Confirm Password: ")

        if not username:
            error = "Username is required."
        elif not password:
            error = "Password is required."
        elif not confirm_password:
            error = "Please confirm password."
        elif password != confirm_password:
            error = "Passwords don't match."
        elif not first_name:
            error = "First Name is required."
        elif not last_name:
            error = "Last Name is required."
        elif not email:
            error = "Email is required."

        if error is None:
            try:
                db.execute("BEGIN TRANSACTION")
                db.execute(
                    "INSERT INTO info (first_name, last_name, email)"
                    " VALUES (?, ?, ?)",
                    (first_name, last_name, email),
                )
                info_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                db.execute(
                    "INSERT INTO user (info_id, username, password, type)"
                    " VALUES (?, ?, ?, ?)",
                    (info_id, username, generate_password_hash(password), "admin"),
                )
                db.commit()
                db.rollback()
            except db.IntegrityError:
                error = f"User {username} is already registered."
    else:
        error = "Admin already in the database."

    print(error if error else "Created the admin.")


@click.command("init-admin")
def init_admin_command():
    init_admin()


def init_app(app):
    app.cli.add_command(init_admin_command)
