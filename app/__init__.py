# __init__.py


from flask import Flask
from flask_jwt_extended import JWTManager
from config import Config
from app.routes import auth

def create_app():
    """Initialize Flask app and configure authentication"""

    # Ensure Flask knows where to find templates
    app = Flask(__name__, template_folder="templates")
    
    # Load configuration from config.py
    app.config.from_object(Config)

    # Initialize JWT authentication
    jwt = JWTManager(app)

    # Register authentication routes
    app.register_blueprint(auth)

    return app

# Create the Flask app instance
app = create_app()
