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
LOGOUT_URL = '/api/auth/logout'
USER_URL = '/api/auth/profile'

INVALID_PASSWORDS = [
    'password',
    'nodigit!@#',
    'nouppercase123!',
    'NoSpecialCharacter123',
]

ERRORS_PASSWORDS = [
    'This password is too common',
    'Password must contain at least one digit.',
    'Password must contain at least one uppercase letter.',
    'Password must contain at least one special character.',
]


class TestsSignUp(TestCase):
    """
    Tests for user registration
    """

    def setUp(self):
        """
        Set up method to initialize test data and client.
        """
        self.client = APIClient()
        self.data = {
            'email': 'test@example.com',
            'password': 'Strongpassword!23',
            'repeat_password': 'Strongpassword!23',
            'first_name': 'John',
            'last_name': 'Doe'
        }

    def tearDown(self):
        """
        Tear down method to clean up after each test.
        """
        # Log out the client and delete all users created during tests
        self.client.logout()
        User.objects.all().delete()

    def test_register_user_success(self):
        """
        Test to register a new user successfully.
        """
        # Send a POST request to the signup URL with valid data
        response = self.client.post(SIGNUP_URL, self.data, format='json')
        # Check if the response status code is 201 (created)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # Check if the returned data contains the email provided
        self.assertIn('email', response.data)
        self.assertEqual(response.data['email'], 'test@example.com')

    def test_missing_email(self):
        """
        Test to register a new user with missing email.
        """
        # Remove the email key from the data
        self.data.pop('email')
        # Send a POST request to the signup URL with missing email
        response = self.client.post(SIGNUP_URL, self.data, format='json')
        # Check if the response status code is 400 (bad request)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Check if the response data contains an error message for missing email field
        self.assertIn('email', response.data)
        self.assertEqual(response.data['email'][0], 'This field is required.')

    def test_missing_first_name(self):
        """
        Test to register a new user with missing first name.
        """
        # Remove the first name from the data
        self.data.pop('first_name')
        # Send a POST request to the signup URL with missing first name
        response = self.client.post(SIGNUP_URL, self.data, format='json')
        # Check if the response status code is 400 (bad request)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Check if the response data contains an error message for missing first name field
        self.assertIn('first_name', response.data)
        self.assertEqual(response.data['first_name'][0], 'This field is required.')

    def test_missing_last_name(self):
        """
        Test to register a new user with missing last name.
        """
        # Remove the last name from the data
        self.data.pop('last_name')
        # Send a POST request to the signup URL with missing last name
        response = self.client.post(SIGNUP_URL, self.data, format='json')
        # Check if the response status code is 400 (bad request)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Check if the response data contains an error message for missing last name field
        self.assertIn('last_name', response.data)
        self.assertEqual(response.data['last_name'][0], 'This field is required.')

    def test_missing_password(self):
        """
        Test to register a new user with missing password.
        """
        # Remove the password from the data
        self.data.pop('password')
        # Send a POST request to the signup URL with missing password
        response = self.client.post(SIGNUP_URL, self.data, format='json')
        # Check if the response status code is 400 (bad request)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Check if the response data contains an error message for missing password field
        self.assertIn('password', response.data)
        self.assertEqual(response.data['password'][0], 'This field is required.')

    def test_missing_repeat_password(self):
        """
        Test to register a new user with missing repeat password.
        """
        # Remove the repeat password from the data
        self.data.pop('repeat_password')
        # Send a POST request to the signup URL with missing repeat password
        response = self.client.post(SIGNUP_URL, self.data, format='json')
        # Check if the response status code is 400 (bad request)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Check if the response data contains an error message for missing repeat password field
        self.assertIn('repeat_password', response.data)
        self.assertEqual(response.data['repeat_password'][0], 'This field is required.')

    def test_register_user_invalid_password(self):
        """
        Test to register a new user with invalid password.
        """
        # Iterate through each invalid password and test registration
        for i, password in enumerate(INVALID_PASSWORDS):
            self.data['password'] = password
            self.data['repeat_password'] = password
            # Send a POST request to the signup URL with invalid password
            response = self.client.post(SIGNUP_URL, self.data, format='json')
            # Check if the response status code is 400 (bad request)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            # Check if the response data contains an error message for invalid password
            self.assertIn('password', response.data)
            self.assertRaisesMessage(response.data['password']['password'][0], ERRORS_PASSWORDS[i])

    def test_signup_same_email(self):
        """
        Test attempting to register a user with an already existing email.
        """
        # Register a user with the provided data
        response = self.client.post(SIGNUP_URL, self.data, format='json')
        # Check if the registration was successful
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # Attempting to register with the same email should fail
        with self.assertRaises(IntegrityError):
            self.client.post(SIGNUP_URL, self.data, format='json')


class TestsLoginUserAPIView(TestCase):
    """
    Tests for user login
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(email='test@example.com', password='password123')
        self.data = {'email': self.user.email, 'password': 'password123'}

    def test_login_user_success(self):
        """
        Test to log in a user successfully.
        """
        # Send a POST request to the login URL with valid credentials
        response = self.client.post(LOGIN_URL, self.data, format='json')
        # Check if the response status code is 200 (OK)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check if the response data contains 'access', 'refresh', and 'user' tokens
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('user', response.data)

    def test_login_user_invalid_credentials(self):
        """
        Test to log in a user with invalid password.
        """
        # Modify the password to an invalid one
        self.data['password'] = 'invalidpassword'
        # Send a POST request to the login URL with invalid credentials
        response = self.client.post(LOGIN_URL, self.data, format='json')
        # Check if the response status code is 401 (UNAUTHORIZED)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        # Check if the response data contains the expected error message
        self.assertIn('detail', response.data)
        self.assertRaisesMessage(response.data['detail'][0], 'No active account found with the given credentials.')

    def test_login_user_missing_password(self):
        """
        Test to log in a user with missing password.
        """
        # Remove the password from the data
        self.data.pop('password')
        # Send a POST request to the login URL with missing password
        response = self.client.post(LOGIN_URL, self.data, format='json')
        # Check if the response status code is 400 (BAD REQUEST)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Check if the response data contains an error message for missing password field
        self.assertIn('password', response.data)
        self.assertEqual(response.data['password'][0], 'This field is required.')

    def test_login_user_missing_email(self):
        """
        Test to log in a user with missing email.
        """
        # Remove the email from the data
        self.data.pop('email')
        # Send a POST request to the login URL with missing email
        response = self.client.post(LOGIN_URL, self.data, format='json')
        # Check if the response status code is 400 (BAD REQUEST)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Check if the response data contains an error message for missing email field
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
        Test to send reset password link successfully.
        """
        # Send a POST request to the reset password URL with valid data
        response = self.client.post(SEND_RESET_PASSWORD_URL, self.data_reset, format='json')
        # Check if the response status code is 200 (OK)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check if the response data contains the expected keys
        self.assertIn('message', response.data)
        self.assertIn('data', response.data)

    def helper_send_request(self):
        # Helper method to send a reset password request and return the response data
        response = self.client.post(SEND_RESET_PASSWORD_URL, self.data_reset, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        return response.data['data']

    def test_send_reset_password_invalid_email(self):
        """
        Test to send reset password link with invalid email.
        """
        # Modify the email to an invalid one
        self.data_reset['email'] = 'example@test.com'
        # Send a POST request to the reset password URL with invalid email
        response = self.client.post(SEND_RESET_PASSWORD_URL, self.data_reset, format='json')
        # Check if the response status code is 401 (UNAUTHORIZED)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        # Check if the response data contains the expected error message
        self.assertIn('detail', response.data)
        self.assertRaisesMessage(response.data['detail'][0], 'Email does not exist.')

    def test_send_reset_password_without_email(self):
        """
        Test to send reset password link without email.
        """
        # Remove the email from the data
        self.data_reset['email'] = ''
        # Send a POST request to the reset password URL without email
        response = self.client.post(SEND_RESET_PASSWORD_URL, self.data_reset, format='json')
        # Check if the response status code is 400 (BAD REQUEST)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Check if the response data contains the expected error message
        self.assertRaisesMessage(response.data['email'][0], 'This field may not be blank.')

    def test_send_password_without_back_url(self):
        """
        Test to send reset password link without URL.
        """
        # Remove the URL from the data
        self.data_reset['url'] = ''
        # Send a POST request to the reset password URL without URL
        response = self.client.post(SEND_RESET_PASSWORD_URL, self.data_reset, format='json')
        # Check if the response status code is 400 (BAD REQUEST)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Check if the response data contains the expected error message
        self.assertIn('url', response.data)
        self.assertRaisesMessage(response.data['url'][0], 'This field may not be blank.')

    def test_set_new_password_success(self):
        """
        Test to set a new password.
        """
        # Send a reset password request and get the response data
        response_data = self.helper_send_request()
        # Extract the UIDB64 and token from the response data
        self.data_set['uidb64'] = response_data['link'].split('/')[3]
        self.data_set['token'] = response_data['link'].split('/')[4]
        # Send a PATCH request to set the new password
        response = self.client.patch(SET_PASSWORD_URL, self.data_set, format='json')
        # Check if the response status code is 200 (OK)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check if the user can log in with the new password
        response = self.client.post(LOGIN_URL, {'email': self.user.email, 'password': self.new_password}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('user', response.data)

    def test_set_new_password_with_invalid_token(self):
        """
        Test to set a new password with an invalid token.
        """
        # Send a reset password request and get the response data
        response_data = self.helper_send_request()
        # Extract the UIDB64 from the response data
        self.data_set['uidb64'] = response_data['link'].split('/')[3]
        # Use an invalid token
        self.data_set['token'] = 'invalid'
        # Send a PATCH request to set the new password with an invalid token
        response = self.client.patch(SET_PASSWORD_URL, self.data_set, format='json')
        # Check if the response status code is 401 (UNAUTHORIZED)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        # Check if the response data contains the expected error message
        self.assertRaisesMessage(response.data['detail'], 'Reset link is invalid or has expired')

    def test_set_new_password_with_invalid_uidb64(self):
        """
        Test to set a new password with an invalid UIDB64.
        """
        # Send a reset password request and get the response data
        response_data = self.helper_send_request()
        # Use an invalid UIDB64
        self.data_set['uidb64'] = 'invaliduidb64'
        self.data_set['token'] = response_data['link'].split('/')[4]
        # Send a PATCH request to set the new password with an invalid UIDB64
        response = self.client.patch(SET_PASSWORD_URL, self.data_set, format='json')
        # Check if the response status code is 401 (UNAUTHORIZED)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        # Check if the response data contains the expected error message
        self.assertRaisesMessage(response.data['detail'], 'Reset link is invalid or has expired')

    def test_set_password_without_tokens(self):
        """
        Test to set a new password without tokens.
        """
        # Send a PATCH request to set the new password without tokens
        response = self.client.patch(SET_PASSWORD_URL, self.data_set, format='json')
        # Check if the response status code is 400 (BAD REQUEST)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Check if the response data contains the expected error messages
        self.assertRaisesMessage(response.data['uidb64'][0], 'This field is required.')
        self.assertRaisesMessage(response.data['token'][0], 'This field is required.')

    def test_set_password_without_uidb64(self):
        """
        Test to set a new password without UIDB64.
        """
        # Send a reset password request and get the response data
        response_data = self.helper_send_request()
        # Remove the UIDB64 from the data
        self.data_set['token'] = response_data['link'].split('/')[4]
        # Send a PATCH request to set the new password without UIDB64
        response = self.client.patch(SET_PASSWORD_URL, self.data_set, format='json')
        # Check if the response status code is 400 (BAD REQUEST)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_set_password_without_token(self):
        """
        Test to set a new password without token.
        """
        # Send a reset password request and get the response data
        response_data = self.helper_send_request()
        # Remove the token from the data
        self.data_set['uidb64'] = response_data['link'].split('/')[3]
        # Send a PATCH request to set the new password without token
        response = self.client.patch(SET_PASSWORD_URL, self.data_set, format='json')
        # Check if the response status code is 400 (BAD REQUEST)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_set_with_invalid_new_password(self):
        """
        Test to set a new password with invalid passwords.
        """
        # Send a reset password request and get the response data
        response_data = self.helper_send_request()
        # Set UIDB64 and token in the data
        self.data_set['uidb64'] = response_data['link'].split('/')[3]
        self.data_set['token'] = response_data['link'].split('/')[4]
        # Iterate over invalid passwords and test each one
        for i, password in enumerate(INVALID_PASSWORDS):
            self.data_set['password'] = password
            self.data_set['confirm_password'] = password
            # Send a request to set the new password with invalid password
            response = self.client.post(SIGNUP_URL, self.data_set, format='json')
            # Check if the response status code is 400 (BAD REQUEST)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            # Check if the response data contains the expected error message
            self.assertIn('password', response.data)
            self.assertRaisesMessage(response.data['password']['password'][0], ERRORS_PASSWORDS[i])

    def test_set_with_not_same_passwords(self):
        """
        Test to set a new password with passwords that do not match.
        """
        # Send a reset password request and get the response data
        response_data = self.helper_send_request()
        # Set UIDB64 and token in the data
        self.data_set['uidb64'] = response_data['link'].split('/')[3]
        self.data_set['token'] = response_data['link'].split('/')[4]
        # Set confirm_password to a different value
        self.data_set['confirm_password'] = 'newpassword'
        # Send a PATCH request to set the new password with passwords that do not match
        response = self.client.patch(SET_PASSWORD_URL, self.data_set, format='json')
        # Check if the response status code is 401 (UNAUTHORIZED)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        # Check if the response data contains the expected error message
        self.assertRaisesMessage(response.data['detail'], 'Passwords do not match.')


class TestsLogoutUserAPIView(TestCase):
    """
    Tests for user logout
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(email='test@example.com', password='Strongpassword!23',
                                             first_name='John', last_name='Doe'
                                             )

        self.client.force_authenticate(user=self.user)

    def test_successful_logout(self):
        """
        Test to log out a user successfully.
        """
        # Load the refresh token into the client cookies
        self.client.cookies.load({'refresh': self.user.tokens()['refresh']})
        # Send a POST request to log out the user
        response = self.client.post(LOGOUT_URL)
        # Check if the response status code is 200 (OK)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_logout_without_token(self):
        """
        Test to log out a user without a token.
        """
        # Send a POST request to log out the user without a token
        response = self.client.post(LOGOUT_URL)
        # Check if the response status code is 400 (BAD REQUEST)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Check if the response data contains the expected error message
        self.assertRaisesMessage(response.data['refresh_token'], 'This field may not be null.')


class TestsUserViewSet(TestCase):
    def setUp(self):
        """
        Set up the test environment by creating users and authenticating the client.
        """
        # Create APIClient instance
        self.client = APIClient()
        # Set password for user
        self.password = 'Admin!23'
        # Create two users
        self.user = User.objects.create_user(email='test@example.com', password=self.password)
        self.user2 = User.objects.create_user(email=self.email2, password=self.password)
        # Force authenticate the client with the first user
        self.client.force_authenticate(user=self.user)
        # Define the URL for the user profile
        self.url = f'{USER_URL}/{self.user.id}'

    def test_update_user_profile_first_name(self):
        """
        Test updating user profile's first name.
        """
        # Define new first name
        first_name = 'Updated First Name'
        # Prepare data to update user profile
        data = {'first_name': first_name}
        # Send PATCH request to update user profile
        response = self.client.patch(self.url, data, format='json')
        # Check if response is successful (status code 200)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check if first name is updated in response data
        self.assertEqual(response.data['first_name'], first_name)
        # Check if first name is updated in the database
        self.assertTrue(User.objects.get(email=self.user.email).first_name, first_name)

    def test_update_user_profile_last_name(self):
        """
        Test updating user profile's last name.
        """
        # Define new last name
        last_name = 'Updated Last Name'
        # Prepare data to update user profile
        data = {'last_name': last_name}
        # Send PATCH request to update user profile
        response = self.client.patch(self.url, data, format='json')
        # Check if response is successful (status code 200)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check if last name is updated in response data
        self.assertEqual(response.data['last_name'], last_name)
        # Check if last name is updated in the database
        self.assertTrue(User.objects.get(email=self.user.email).last_name, last_name)

    def test_update_user_profile_avatar(self):
        """
        Test updating user profile's avatar.
        """
        # Define new avatar URL
        avatar = 'https://example.com/avatar.jpg'
        # Prepare data to update user profile
        data = {'avatar': avatar}
        # Send PATCH request to update user profile
        response = self.client.patch(self.url, data, format='json')
        # Check if response is successful (status code 200)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check if avatar URL is updated in response data
        self.assertEqual(response.data['avatar'], avatar)
        # Check if avatar URL is updated in the database
        self.assertTrue(User.objects.get(email=self.user.email).avatar, avatar)

    def test_update_user_profile_email(self):
        """
        Test updating user profile's email.
        """
        # Define new email address
        email = 'example@test.com'
        # Prepare data to update user profile
        data = {'email': email}
        # Send PATCH request to update user profile
        response = self.client.patch(self.url, data, format='json')
        # Check if response is successful (status code 200)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check if email address is updated in response data
        self.assertEqual(response.data['email'], email)

    def test_update_user_password_successfully(self):
        """
        Test updating user password successfully.
        """
        # Define a new password
        password = 'Newtest!23'
        # Prepare data to update user password
        data = {'new_password': password, 'repeat_new_password': password}
        # Send PATCH request to update user password
        response = self.client.patch(self.url, data, format='json')
        # Check if response is successful (status code 200)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check if password is updated in the database and matches the new password
        self.assertTrue(User.objects.get(email=self.user.email).check_password(password))

    def test_update_user_password_with_invalid_passwords(self):
        """
        Test updating user password with invalid passwords.
        """
        # Iterate over a list of invalid passwords
        for i, password in enumerate(INVALID_PASSWORDS):
            # Prepare data with an invalid password
            data = {'new_password': password, 'repeat_new_password': password}
            # Send PATCH request to update user password
            response = self.client.patch(self.url, data, format='json')
            # Check if response indicates bad request (status code 400)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            # Check if response contains error message for password field
            self.assertIn('password', response.data)
            # Check if the error message matches the expected error for the corresponding invalid password
            self.assertRaisesMessage(response.data['password'][0], ERRORS_PASSWORDS[i])

    def test_update_user_password_with_existing_passwords(self):
        """
        Test updating user password with an existing password.
        """
        # Prepare data with the existing password
        data = {'new_password': self.password, 'repeat_new_password': self.password}
        # Send PATCH request to update user password
        response = self.client.patch(self.url, data, format='json')
        # Check if response indicates bad request (status code 400)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Check if response contains an error message indicating that the new password must be different
        self.assertRaisesMessage(response.data[0], 'New password must be different from the old password.')

    def test_change_email_to_existing_email(self):
        """
        Test attempting to change email to an existing email.
        """
        # Attempt to change the email to an existing email address
        response = self.client.patch(self.url, {'email': self.email2}, format='json')
        # Check if response indicates bad request (status code 400)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Check if response contains an error message related to the email field
        self.assertIn('email', response.data)

    def test_update_others_user_profile(self):
        """
        Test attempting to update another user's profile.
        """
        # Attempt to update another user's profile
        response = self.client.patch(f'{USER_URL}/{self.user2.id}', {'first_name': 'Updated First Name'}, format='json')
        # Check if response indicates forbidden action (status code 403)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_other_user(self):
        """
        Test attempting to delete another user.
        """
        # Attempt to delete another user
        response = self.client.delete(f'{USER_URL}/{self.user2.id}')
        # Check if response indicates forbidden action (status code 403)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_update_user_groups(self):
        """
        Test updating user groups.
        """
        # TODO: Implement this test (Provide a brief description of what this test aims to achieve)
        response = self.client.patch(self.url, {'groups': [1, 2]}, format='json')

    def test_delete_own_user(self):
        """
        Test attempting to delete own user.
        """
        # Attempt to delete own user
        response = self.client.delete(self.url)
        # Check if response indicates successful deletion (status code 204)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        # Check if the user has been deleted from the database
        self.assertFalse(User.objects.filter(email=self.user.email).exists())


class TestsOwnUserAPIView(TestCase):
    """
    Tests for own user profile
    """

    def setUp(self):
        """
        Method to set up the test environment.
        """
        # Initialize the test client
        self.client = APIClient()
        # Create a user for testing
        self.user = User.objects.create_user(email='test@example.com', password='Strongpassword!23',
                                             first_name='John', last_name='Doe')

    def test_get_profile(self):
        """
        Test to retrieve user profile.
        """
        # Authenticate the client with the created user
        self.client.force_authenticate(user=self.user)
        # Send a request to retrieve user profile
        response = self.client.get(USER_URL)
        # Check if the response indicates success status code 200
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check if the returned data matches the user's profile
        self.assertEqual(response.data[0]['email'], self.user.email)
        self.assertEqual(response.data[0]['first_name'], self.user.first_name)
        self.assertEqual(response.data[0]['last_name'], self.user.last_name)
        self.assertEqual(response.data[0]['id'], self.user.id)

    def test_get_profile_unauthenticated(self):
        """
        Test to retrieve user profile without authentication.
        """
        # Send a request to retrieve user profile without authentication
        response = self.client.get(USER_URL)
        # Check if the response indicates unauthorized access (status code 401)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        # Check if the response contains a detail message indicating lack of authentication
        self.assertIn('detail', response.data)
        self.assertRaisesMessage(response.data['detail'], 'Authentication credentials were not provided.')
