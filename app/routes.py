from flask import Blueprint, request, jsonify
import boto3
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, JWTManager
from app import app, Config  # Import the Flask app instance and Config
from app.models import generate_user_id

auth = Blueprint('auth', __name__)
bcrypt = Bcrypt(app)  # Initialize Bcrypt with the Flask app
jwt = JWTManager(app)  # Initialize JWTManager with the Flask app

# Set up AWS DynamoDB connection
dynamodb = boto3.resource(
    'dynamodb',
    region_name=Config.AWS_REGION,
    aws_access_key_id=Config.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=Config.AWS_SECRET_ACCESS_KEY
)

# Define tables
users_table = dynamodb.Table(Config.USERS_TABLE)
courses_table = dynamodb.Table(Config.COURSES_TABLE)
registrations_table = dynamodb.Table(Config.REGISTRATIONS_TABLE)
faculty_table = dynamodb.Table(Config.FACULTY_TABLE)

@auth.route('/')
def home():
    return jsonify('Welcome to the Art Course Registration System!')

@auth.route('/api/register', methods=['POST'])
def register():
    """Handles user registration and stores user data in DynamoDB."""
    data = request.get_json()
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    password = data.get('password')
    role = data.get('role')  # "Student", "Faculty", or "Admin"

    if not first_name or not last_name or not password or not role:
        return jsonify({'error': 'All fields are required'}), 400

    user_id = generate_user_id(first_name, last_name)

    # Check if user exists
    response = users_table.get_item(Key={'user_id': user_id})
    if 'Item' in response:
        return jsonify({'error': 'User already exists'}), 400

    # Hash password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Save user to DynamoDB
    users_table.put_item(
        Item={
            'user_id': user_id,
            'first_name': first_name,
            'last_name': last_name,
            'password': hashed_password,
            'role': role
        }
    )

    return jsonify({'message': 'Registration successful!', 'user_id': user_id}), 201

@auth.route('/api/login', methods=['POST'])
def login():
    """Handles user authentication and returns a JWT token upon successful login."""
    data = request.get_json()
    user_id = data.get('user_id')
    password = data.get('password')

    response = users_table.get_item(Key={'user_id': user_id})

    if 'Item' not in response:
        return jsonify({'error': 'Invalid user ID or password'}), 401

    user = response['Item']

    if not bcrypt.check_password_hash(user['password'], password):
        return jsonify({'error': 'Invalid user ID or password'}), 401

    access_token = create_access_token(identity={'user_id': user['user_id'], 'role': user['role']})

    return jsonify({
        'message': f'Welcome {user["first_name"]} {user["last_name"]}!',
        'access_token': access_token,
        'role': user['role']
    }), 200

@auth.route('/api/auth-check', methods=['GET'])
@jwt_required()
def auth_check():
    """Endpoint to verify if a user is authenticated."""
    current_user = request.get_json()
    return jsonify({'message': 'User is authenticated', 'user': current_user}), 200

@auth.route('/api/courses', methods=['GET'])
@jwt_required()
def get_courses():
    """Fetch all available courses from DynamoDB."""
    response = courses_table.scan()
    courses = response.get('Items', [])

    return jsonify({'courses': courses}), 200

@auth.route('/api/register-course', methods=['POST'])
@jwt_required()
def register_for_course():
    """Registers a user for a course."""
    data = request.get_json()
    user_id = data.get('user_id')
    course_id = data.get('course_id')

    # Check if user exists
    user = users_table.get_item(Key={'user_id': user_id}).get('Item')
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Check if course exists
    course = courses_table.get_item(Key={'course_id': course_id}).get('Item')
    if not course:
        return jsonify({'error': 'Course not found'}), 404

    # Register the user for the course
    registrations_table.put_item(
        Item={
            'registration_id': f"{user_id}_{course_id}",
            'user_id': user_id,
            'course_id': course_id
        }
    )
    return jsonify({'message': 'User registered for course successfully'}, 201)
