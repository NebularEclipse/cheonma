import os

from flask import Flask, send_from_directory
from flask_wtf.csrf import CSRFProtect


def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY="dev",
        DATABASE=os.path.join(app.instance_path, "cheonma.sqlite"),
        UPLOAD_FOLDER=os.path.join(
            app.instance_path, "uploads"
        ),  # Directory to store uploads
        ALLOWED_EXTENSIONS={"png", "jpg", "jpeg", "gif"},  # Allowed file extensions
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16 MB max size for uploads
    )

    csrf = CSRFProtect(app)

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile("config.py", silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Ensure the uploads folder exists
    uploads_path = os.path.join(app.instance_path, "uploads")
    if not os.path.exists(uploads_path):
        os.makedirs(uploads_path)

    app.add_url_rule(
        "/uploads/<filename>",
        endpoint="uploaded_file",
        view_func=lambda filename: send_from_directory(app.config["UPLOAD_FOLDER"], filename),
    )

    # Cache control header: prevents caching sensitive pages
    @app.after_request
    def add_cache_control(response):
        response.cache_control.no_store = True  # Prevents caching of sensitive pages
        return response

    # a simple page that says hello
    @app.route("/hello")
    def hello():
        return "Hello, World!"

    from . import db

    db.init_app(app)

    from . import auth

    app.register_blueprint(auth.bp)
    auth.init_app(app)

    from . import dashboard

    app.register_blueprint(dashboard.bp)
    app.add_url_rule("/", endpoint="index")

    return app
