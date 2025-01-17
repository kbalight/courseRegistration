# __init__.py

from flask import Flask
from flask_login import LoginManager
from config import Config
from models import db


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)

    login = LoginManager(app)
    login.login_view ='login'

    with app.app_context():
        db.create_all()

    return app
