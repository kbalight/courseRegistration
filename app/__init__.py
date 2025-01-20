# __init__.py

import os
from flask import Flask
from flask_login import LoginManager
from werkzeug.security import check_password_hash
from config import Config
from app.models import db, User

def create_app():
    app = Flask(__name__, template_folder=os.path.join(os.getcwd(), 'templates'))
    app.config.from_object(Config)

    db.init_app(app)

    login = LoginManager(app)
    login.login_view ='login'

    @login.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @login.request_loader
    def load_user_from_request(request):
        token = request.headers.get('Authorization')
        if token:
            user_id = check_password_hash(token, User.password)
            if user_id:
                return User.query.get(user_id)
        return None

    with app.app_context():
        db.create_all()

    # Print the template folder path
    print(f"Template folder path: {app.template_folder}")

    return app
