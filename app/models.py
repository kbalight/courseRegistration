# models.py

import boto3
from config import Config

# Set up AWS DynamoDB connection
# AWS credentials are required if IAM roles are not being used
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

def generate_user_id(first_name, last_name):
    """Generate a user ID by combining first and last name."""
    return (first_name + last_name).replace(" ", "").lower()

def create_user(first_name, last_name, password, role):
    """Registers a new user in DynamoDB."""
    user_id = generate_user_id(first_name, last_name)
    
    # Check if user already exists
    response = users_table.get_item(Key={'user_id': user_id})
    if 'Item' in response:
        return {"error": "User already exists"}, 400

    # Store hashed password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Insert user into DynamoDB
    users_table.put_item(
        Item={
            'user_id': user_id,
            'first_name': first_name,
            'last_name': last_name,
            'password': hashed_password,
            'role': role
        }
    )
    return {"message": "User registered successfully", "user_id": user_id}, 201

def get_user_by_id(user_id):
    """Retrieve a user from DynamoDB."""
    response = users_table.get_item(Key={'user_id': user_id})
    return response.get('Item')

def get_course_by_id(course_id):
    """Retrieve a course from DynamoDB."""
    response = courses_table.get_item(Key={'course_id': course_id})
    return response.get('Item')

def register_user_for_course(user_id, course_id):
    """Registers a user for a course in DynamoDB."""
    # Check if user exists
    user = get_user_by_id(user_id)
    if not user:
        return {"error": "User not found"}, 404

    # Check if course exists
    course = get_course_by_id(course_id)
    if not course:
        return {"error": "Course not found"}, 404

    # Register the user for the course
    registrations_table.put_item(
        Item={
            'registration_id': f"{user_id}_{course_id}",  # Unique registration ID
            'user_id': user_id,
            'course_id': course_id
        }
    )
    return {"message": "User registered for course successfully"}, 201
