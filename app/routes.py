from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
import boto3
from flask_jwt_extended import create_access_token, jwt_required, JWTManager
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Email
from app import bcrypt
from config import Config
from app.models import generate_user_id

routes = Blueprint('routes', __name__)

# Define the LoginForm class
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Log In')

# Define the RegistrationForm class
class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm Password')
    role = StringField('Role', validators=[DataRequired()])
    submit = SubmitField('Register')

# Function to generate a username
def generate_username(first_name, last_name):
    return f"{first_name.lower()}.{last_name.lower()}"

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

# Serve Frontend Pages
@routes.route('/')
def home():
    return render_template('index.html')

@routes.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Handle form submission logic here
        flash('Login successful!', 'success')
        return redirect(url_for('routes.home'))
    return render_template('login.html', form=form)

@routes.route('/register', methods=['GET', 'POST'])
def register_page():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Handle form submission logic here
        first_name = form.first_name.data
        last_name = form.last_name.data
        email = form.email.data
        password = form.password.data
        role = form.role.data

        user_id = generate_user_id(first_name, last_name)
        username = generate_username(first_name, last_name)

        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Save user to DynamoDB
        users_table.put_item(
            Item={
                'user_id': user_id,
                'username': username,
                'first_name': first_name,
                'last_name': last_name,
                'email': email,
                'password': hashed_password,
                'role': role
            }
        )

        flash(f'Registration successful! Your user ID is {user_id} and your username is {username}', 'success')
        return redirect(url_for('routes.home'))
    return render_template('register.html', form=form)

@routes.route('/courses')
def courses_page():
    response = courses_table.scan()
    courses = response.get('Items', [])
    return render_template('courses.html', courses=courses)

# API Endpoints

@routes.route('/api/register', methods=['POST'])
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
    username = generate_username(first_name, last_name)

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
            'username': username,
            'first_name': first_name,
            'last_name': last_name,
            'password': hashed_password,
            'role': role
        }
    )
    return jsonify({'message': 'User registered successfully', 'user_id': user_id, 'username': username}), 201

@routes.route('/api/login', methods=['POST'])
def login_user():
    """Handles user login and generates JWT token."""
    data = request.get_json()
    user_id = data.get('user_id')
    password = data.get('password')

    response = users_table.get_item(Key={'user_id': user_id})
    user = response.get('Item')

    if not user or not bcrypt.check_password_hash(user['password'], password):
        return jsonify({'error': 'Invalid credentials'}), 401

    access_token = create_access_token(identity=user_id)

    # Retrieve first_name and last_name from user data
    first_name = user.get('first_name', 'User')
    last_name = user.get('last_name', '')

    # Construct the welcome message
    welcome_message = f"Welcome {first_name} {last_name}".strip()

    return jsonify({
        'access_token': access_token,
        'message': welcome_message
    }), 200

@routes.route('/api/courses', methods=['GET'])
def get_courses():
    """Fetch all courses from the Courses table."""
    response = courses_table.scan()
    return jsonify(response.get('Items', []))

@routes.route('/api/register-course', methods=['POST'])
@jwt_required()
def register_course():
    """Registers a user for a course."""
    data = request.get_json()
    user_id = data.get('user_id')
    course_id = data.get('course_id')

    registrations_table.put_item(
        Item={'registration_id': f'{user_id}_{course_id}', 'user_id': user_id, 'course_id': course_id}
    )
    return jsonify({'message': 'Registration successful'}), 201

@routes.route('/api/faculty', methods=['GET'])
def get_faculty():
    """Fetch all faculty members."""
    response = faculty_table.scan()
    return jsonify(response.get('Items', []))
