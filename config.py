# config.py

import os

class Config:
    # Secret Key for JWT Authentication
    SECRET_KEY = os.environ.get('SECRET_KEY', 'you-will-never-guess')

    # AWS DynamoDB Configuration
    AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
    AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID') or os.environ.get('AWS_ACCESS_KEY')
    AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY') or os.environ.get('AWS_SECRET_KEY')

    # DynamoDB Table Names
    USERS_TABLE = 'Users'
    COURSES_TABLE = 'Courses'
    REGISTRATIONS_TABLE = 'Registration'
    FACULTY_TABLE = 'Faculty'

class TestConfig(Config):
    TESTING = True
    # Provide dummy credentials for testing so that Moto does not get confused
    AWS_ACCESS_KEY_ID = "testing"
    AWS_SECRET_ACCESS_KEY = "testing"


