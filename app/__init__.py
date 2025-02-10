from flask import Flask
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from config import Config

bcrypt = Bcrypt()
jwt = JWTManager()

def create_app(config_class=Config):
    """Initialize Flask app and configure authentication"""

    flask_app = Flask(__name__, template_folder="templates")

    # Load configuration from config.py
    flask_app.config.from_object(config_class)

    # Initialize Bcrypt inside the app context
    bcrypt.init_app(flask_app)

    # Initialize JWT authentication
    JWTManager(flask_app)

    # Import and register blueprints
    from app.routes import routes
    flask_app.register_blueprint(routes)

    return flask_app

# Create the Flask app instance
app = create_app()
