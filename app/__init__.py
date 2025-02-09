# __init__.py

from flask import Flask
from flask_jwt_extended import JWTManager
from config import Config
from app.routes import auth



def create_app(config_class=Config):
    """Initialize Flask app and configure authentication"""

    # Ensure Flask knows where to find templates
    flask_app = Flask(__name__, template_folder="templates")

    # Load configuration from config.py
    flask_app.config.from_object(config_class)

    # Initialize JWT authentication
    JWTManager(flask_app)  # No need to assign to a variable

    # Register authentication routes
    flask_app.register_blueprint(auth)

    return flask_app


# Create the Flask app instance
app = create_app()
