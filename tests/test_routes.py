import unittest
import boto3
from moto import mock_aws
from app import create_app
from config import TestConfig
from flask_bcrypt import Bcrypt
from app.models import generate_user_id
from flask_jwt_extended import create_access_token

@mock_aws
class RoutesTestCase(unittest.TestCase):

    def setUp(self):
        # Create the app using TestConfig
        self.app = create_app(TestConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.client = self.app.test_client()
        self.bcrypt = Bcrypt(self.app)

        # Generate a user_id (for example "johndoe")
        self.user_id = generate_user_id("John", "Doe")

        # Create DynamoDB resources using the dummy credentials from TestConfig
        self.dynamodb = boto3.resource(
            'dynamodb',
            region_name=TestConfig.AWS_REGION,
            aws_access_key_id=TestConfig.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=TestConfig.AWS_SECRET_ACCESS_KEY
        )

        # Create the Users table (matching the expected schema)
        self.users_table = self.dynamodb.create_table(
            TableName=TestConfig.USERS_TABLE,
            KeySchema=[
                {
                    'AttributeName': 'user_id',
                    'KeyType': 'HASH'  # Partition key
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'user_id',
                    'AttributeType': 'S'
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )
        self.users_table.wait_until_exists()

        # Create a JWT token for testing protected routes.
        # Use the role "Student" (capitalized) to match the expected role in your registration.
        self.access_token = create_access_token(identity={"user_id": self.user_id, "role": "Student"})
        self.headers = {"Authorization": f"Bearer {self.access_token}"}

    def tearDown(self):
        # Delete the table inside the mock context
        self.users_table.delete()
        self.users_table.wait_until_not_exists()
        self.app_context.pop()

    def test_home_page(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Welcome to the Art Course Registration System', response.data)

    def test_register_user(self):
        # Use unique data so that registration is not blocked by a duplicate check.
        response = self.client.post('/api/register', json={
            'first_name': 'Alice',
            'last_name': 'Smith',
            'password': 'password123',
            'role': 'Student'
        })
        self.assertEqual(response.status_code, 201)
        self.assertIn(b'Registration successful', response.data)

    def test_login_user(self):
        # First, register the user
        self.client.post('/api/register', json={
            'first_name': 'John',
            'last_name': 'Doe',
            'password': 'password123',
            'role': 'Student'
        })
        # Then, log in
        response = self.client.post('/api/login', json={
            'user_id': self.user_id,
            'password': 'password123'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Welcome John Doe', response.data)

    def test_get_courses(self):
        # For a protected route, pass the JWT header
        response = self.client.get('/api/courses', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'courses', response.data)

if __name__ == '__main__':
    unittest.main()
