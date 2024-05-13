from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from django.db import IntegrityError
from rest_framework import status
from django.test import TestCase

User = get_user_model()

SIGNUP_URL = '/api/auth/signup'
LOGIN_URL = '/api/auth/login'


class TestSignUp(TestCase):
    """
    Tests for user registration
    """
    def setUp(self):
        self.client = APIClient()
        self.data = {
            'email': 'test@example.com',
            'password': 'Strongpassword!23',
            'repeat_password': 'Strongpassword!23',
            'first_name': 'John',
            'last_name': 'Doe'
        }

    def tearDown(self):
        self.client.logout()
        User.objects.all().delete()

    def test_register_user_success(self):
        """
        Test to register a new user
        """
        response = self.client.post(SIGNUP_URL, self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('email', response.data)
        self.assertEqual(response.data['email'], 'test@example.com')

    def test_missing_email(self):
        """
        Test to register a new user with missing email
        """
        self.data.pop('email')
        response = self.client.post(SIGNUP_URL, self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)
        self.assertEqual(response.data['email'][0], 'This field is required.')

    def test_missing_first_name(self):
        """
        Test to register a new user with missing first name
        """
        self.data.pop('first_name')
        response = self.client.post(SIGNUP_URL, self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('first_name', response.data)
        self.assertEqual(response.data['first_name'][0], 'This field is required.')

    def test_missing_last_name(self):
        """
        Test to register a new user with missing last name
        """
        self.data.pop('last_name')
        response = self.client.post(SIGNUP_URL, self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('last_name', response.data)
        self.assertEqual(response.data['last_name'][0], 'This field is required.')

    def test_missing_password(self):
        """
        Test to register a new user with missing password
        """
        self.data.pop('password')
        response = self.client.post(SIGNUP_URL, self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)
        self.assertEqual(response.data['password'][0], 'This field is required.')

    def test_missing_repeat_password(self):
        """
        Test to register a new user with missing repeat password
        """
        self.data.pop('repeat_password')
        response = self.client.post(SIGNUP_URL, self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('repeat_password', response.data)
        self.assertEqual(response.data['repeat_password'][0], 'This field is required.')

    def test_register_user_invalid_password(self):
        """
        Test to register a new user with invalid password
        """
        invalid_passwords = [
            'password',
            'alllowercase',
            'ALLUPPERCASE',
            'nouppercase123!',
            'NoSpecialCharacter123',
        ]

        for i, password in enumerate(invalid_passwords):
            self.data['password'] = password
            self.data['repeat_password'] = password
            # Send a request to the API with invalid password
            response = self.client.post(SIGNUP_URL, self.data, format='json')
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertIn('password', response.data)

    def test_signup_same_email(self):
        response = self.client.post(SIGNUP_URL, self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Attempting to register with the same email should fail
        with self.assertRaises(IntegrityError):
            self.client.post(SIGNUP_URL, self.data, format='json')


class LoginUserAPIViewTests(TestCase):
    """
    Tests for user login
    """
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(email='test@example.com', password='password123')

    def test_login_user_success(self):
        data = {'username': 'testuser', 'password': 'password123'}
        response = self.client.post(LOGIN_URL, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('user', response.data)

    def test_login_user_invalid_credentials(self):
        data = {'username': 'testuser', 'password': 'invalidpassword'}
        response = self.client.post(LOGIN_URL, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_user_missing_fields(self):
        data = {'username': 'testuser'}
        response = self.client.post(LOGIN_URL, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
