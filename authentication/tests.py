from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from django.db import IntegrityError
from rest_framework import status
from django.test import TestCase

User = get_user_model()

SIGNUP_URL = '/api/auth/signup'
LOGIN_URL = '/api/auth/login'
SEND_RESET_PASSWORD_URL = '/api/auth/password-reset'
SET_PASSWORD_URL = '/api/auth/password-set'

INVALID_PASSWORDS = [
    'password',
    'alllowercase',
    'ALLUPPERCASE',
    'nouppercase123!',
    'NoSpecialCharacter123',
]

ERRORS_PASSWORDS = [
]


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

        for i, password in enumerate(INVALID_PASSWORDS):
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
        self.data = {'email': self.user.email, 'password': 'password123'}

    def test_login_user_success(self):
        """
        Test to log in a user successfully
        """
        response = self.client.post(LOGIN_URL, self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('user', response.data)

    def test_login_user_invalid_credentials(self):
        """
        Test to log in a user with invalid password
        """
        self.data['password'] = 'invalidpassword'
        response = self.client.post(LOGIN_URL, self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('detail', response.data)
        self.assertRaisesMessage(response.data['detail'][0], 'No active account found with the given credentials.')

    def test_login_user_missing_password(self):
        """
        Test to log in a user with missing password
        """
        self.data.pop('password')
        response = self.client.post(LOGIN_URL, self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)
        self.assertEqual(response.data['password'][0], 'This field is required.')

    def test_login_user_missing_email(self):
        """
        Test to log in a user with missing email
        """
        self.data.pop('email')
        response = self.client.post(LOGIN_URL, self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)
        self.assertEqual(response.data['email'][0], 'This field is required.')


class TestResetPassword(TestCase):
    """
    Tests for sending reset password link
    """

    def setUp(self):
        self.client = APIClient()
        self.new_password = 'Newpassword!23'
        self.user = User.objects.create_user(email='test@example.com', password='password123')
        self.data_reset = {'email': self.user.email, 'url': 'http://localhost'}
        self.data_set = {'password': self.new_password, 'confirm_password': self.new_password}

    def test_send_reset_password_success(self):
        """
        Test to send reset password link successfully
        """
        response = self.client.post(SEND_RESET_PASSWORD_URL, self.data_reset, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertIn('data', response.data)

    def helper_send_request(self):
        response = self.client.post(SEND_RESET_PASSWORD_URL, self.data_reset, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        return response.data['data']

    def test_send_reset_password_invalid_email(self):
        """
        Test to send reset password link with invalid email
        """
        self.data_reset['email'] = 'example@test.com'
        response = self.client.post(SEND_RESET_PASSWORD_URL, self.data_reset, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('detail', response.data)
        self.assertRaisesMessage(response.data['detail'][0], 'Email does not exist.')

    def test_send_reset_password_without_email(self):
        """
        Test to send reset password link without email
        """
        self.data_reset['email'] = ''
        response = self.client.post(SEND_RESET_PASSWORD_URL, self.data_reset, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertRaisesMessage(response.data['email'][0], 'This field may not be blank.')

    def test_send_password_without_back_url(self):
        """
        Test to send reset password link without url
        """
        self.data_reset['url'] = ''
        response = self.client.post(SEND_RESET_PASSWORD_URL, self.data_reset, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('url', response.data)
        self.assertRaisesMessage(response.data['url'][0], 'This field may not be blank.')

    def test_set_new_password_success(self):
        """
        Test to set new password
        """
        response_data = self.helper_send_request()

        self.data_set['uidb64'] = response_data['link'].split('/')[3]
        self.data_set['token'] = response_data['link'].split('/')[4]

        response = self.client.patch(SET_PASSWORD_URL, self.data_set, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client.post(LOGIN_URL, {'email': self.user.email, 'password': self.new_password}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('user', response.data)

    def test_set_new_password_with_invalid_token(self):
        """
        Test to set new password with invalid token
        """
        response_data = self.helper_send_request()

        self.data_set['uidb64'] = response_data['link'].split('/')[3]
        self.data_set['token'] = 'invalid'

        response = self.client.patch(SET_PASSWORD_URL, self.data_set, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertRaisesMessage(response.data['detail'], 'Reset link is invalid or has expired')

    def test_set_new_password_with_invalid_uidb64(self):
        """
        Test to set new password with invalid uidb64
        """
        response_data = self.helper_send_request()

        self.data_set['uidb64'] = 'invaliduidb64'
        self.data_set['token'] = response_data['link'].split('/')[4]

        response = self.client.patch(SET_PASSWORD_URL, self.data_set, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertRaisesMessage(response.data['detail'], 'Reset link is invalid or has expired')

    def test_set_password_without_tokens(self):
        """
        Test to set new password without tokens
        """
        response = self.client.patch(SET_PASSWORD_URL, self.data_set, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertRaisesMessage(response.data['uidb64'][0], 'This field is required.')
        self.assertRaisesMessage(response.data['token'][0], 'This field is required.')

    def test_set_password_without_uidb64(self):
        """
        Test to set new password without uidb64
        """
        response_data = self.helper_send_request()

        self.data_set['token'] = response_data['link'].split('/')[4]

        response = self.client.patch(SET_PASSWORD_URL, self.data_set, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_set_password_without_token(self):
        """
        Test to set new password without token
        """
        response_data = self.helper_send_request()

        self.data_set['uidb64'] = response_data['link'].split('/')[3]

        response = self.client.patch(SET_PASSWORD_URL, self.data_set, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_set_with_invalid_new_password(self):
        """
        Test to set new password with invalid passwords
        """
        response_data = self.helper_send_request()

        self.data_set['uidb64'] = response_data['link'].split('/')[3]
        self.data_set['token'] = response_data['link'].split('/')[4]

        for i, password in enumerate(INVALID_PASSWORDS):
            self.data_set['password'] = password
            self.data_set['confirm_password'] = password
            # Send a request to the API with invalid password
            response = self.client.post(SIGNUP_URL, self.data_set, format='json')
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertIn('password', response.data)

    def test_set_with_not_same_passwords(self):
        """
        Test to set new password with not same passwords
        """
        response_data = self.helper_send_request()

        self.data_set['uidb64'] = response_data['link'].split('/')[3]
        self.data_set['token'] = response_data['link'].split('/')[4]
        self.data_set['confirm_password'] = 'newpassword'

        response = self.client.patch(SET_PASSWORD_URL, self.data_set, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertRaisesMessage(response.data['detail'], 'Passwords do not match.')
