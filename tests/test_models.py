from moto import mock_aws
import unittest
import boto3
from config import TestConfig


@mock_aws
class UserModelTestCase(unittest.TestCase):
    def setUp(self):
        # With mock_aws active, any boto3 calls should be intercepted.
        self.dynamodb = boto3.resource('dynamodb', region_name=TestConfig.AWS_REGION)
        # Create the Users table as expected by your application.
        self.dynamodb.create_table(
            TableName=TestConfig.USERS_TABLE,
            KeySchema=[{'AttributeName': 'user_id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'user_id', 'AttributeType': 'S'}],
            ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
        )
        # If you require other tables (Courses, Registrations, etc.), create them here.
        from app import models  # Now import your module that uses boto3.
        self.models = models

    def tearDown(self):
        pass

    def test_create_user(self):
        first_name = "John"
        last_name = "Doe"
        password = "secret"
        role = "Student"

        response, status = self.models.create_user(first_name, last_name, password, role)
        self.assertEqual(status, 201)
        self.assertIn("user_id", response)

        user = self.models.get_user_by_id(response["user_id"])
        self.assertIsNotNone(user)


if __name__ == '__main__':
    unittest.main()
