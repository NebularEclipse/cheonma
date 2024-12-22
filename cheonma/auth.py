import click
import functools
import getpass
import os

from flask import (
    Blueprint,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
    current_app
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import abort
from werkzeug.utils import secure_filename

import uuid

from cheonma.db import get_db
from cheonma.forms import RegisterForm, LoginForm, UpdateUserForm

bp = Blueprint("auth", __name__, url_prefix="/auth")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

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
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        email = form.email.data
        password = form.password.data
        confirm_password = form.confirm_password.data
        type = form.type.data
        db = get_db()

        if password != confirm_password:
            flash("Passwords don't match.")
            return redirect(url_for("auth.register"))

        try:
            db.execute("BEGIN TRANSACTION")
            db.execute(
                "INSERT INTO info (first_name, last_name, email)" " VALUES (?, ?, ?)",
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

    return render_template("auth/register.html", form=form)


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

    if check_type and user["id"] != g.user["id"]:
        abort(403)

    return user


@bp.route("/<int:id>/update_user", methods=("GET", "POST"))
@login_required
def update_user(id):
    user = get_user(id)

    form = UpdateUserForm(obj=user)

    if form.validate_on_submit():
        username = form.username.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        email = form.email.data
        password = form.password.data
        confirm_password = form.confirm_password.data
        type = form.type.data
        profile_picture = form.profile_picture.data
        db = get_db()

        if password != confirm_password:
            flash("Passwords don't match.")
            return redirect(url_for("auth.register"))

        try:
            db = get_db()
            db.execute("BEGIN TRANSACTION")
            db.execute(
                "UPDATE info SET first_name = ?, last_name = ?, email = ?"
                " WHERE id = ?",
                (first_name, last_name, email, user["info_id"]),
            )
            if profile_picture:
                if allowed_file(profile_picture.filename):
                    filename = secure_filename(profile_picture.filename)
                    # Prepend uuid to filename to avoid filename conflicts
                    filename = str(uuid.uuid1()) + "_" + filename
                    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)

                    # Save the uploaded profile picture
                    profile_picture.save(file_path)

                    # Update the database with the new profile picture filename
                    db.execute(
                        "UPDATE info SET profile_picture = ? WHERE id = ?",
                        (filename, user['info_id'])
                    )
                else:
                    flash("Invalid file type. Only JPG, JPEG, and PNG are allowed.")
            db.execute(
                "UPDATE user SET username = ?, password = ?, type = ?" " WHERE id = ?",
                (username, generate_password_hash(password), type, id),
            )
            db.commit()
        except:
            db.rollback()
        return redirect(url_for("dashboard.index"))

    return render_template("auth/update_user.html", user=user, form=form)


@bp.route("/<int:id>/delete_user", methods=("GET", "POST"))
@login_required
@admin_required
def delete_user(id):
    if g.user['type'] == "admin":
        check_type = False
    else:
        check_type = True

    user = get_user(id, check_type)
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
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

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

    return render_template("auth/login.html", form=form)


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
