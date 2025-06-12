from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse
from django.contrib.auth import get_user_model

User = get_user_model()

class UserFlowTests(APITestCase):

    def setUp(self):
        self.register_url = reverse('register')
        self.login_url = reverse('login')
        self.refresh_url = reverse('token-refresh')
        self.user_profile_url = reverse('user-profile')
        self.seller_profile_url = reverse('seller-profile')
        self.profile_status_url = reverse('profile-status')

        self.user_data = {
            'email': 'testuser@example.com',
            'full_name': 'Test User',
            'phone_number': '1234567890',
            'password': 'strongpassword123',
            'confirm_password': 'strongpassword123'
        }

        self.seller_data = {
            'shop_name': 'Test Shop',
            'shop_description': 'We sell books',
            'shop_address': '123 Test St, Test City',
            'shop_contact_number': '0987654321',
        }

        self.profile_data = {
            'shipping_address': '456 Another St, Test City',
        }

    def authenticated(self):
        # Register and login a user to get access token
        self.client.post(self.register_url, self.user_data)
        login_response = self.client.post(self.login_url, {
            'email': self.user_data['email'],
            'password': self.user_data['password']
        })
        access = login_response.data['access']
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + access)

    def test_user_registration(self):
        response = self.client.post(self.register_url, self.user_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

        # Login
        login_data = {
            'email': self.user_data['email'],
            'password': self.user_data['password']
        }

        login_response = self.client.post(self.login_url, login_data)
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        self.assertIn('access', login_response.data)
        self.assertIn('refresh', login_response.data)

        # Use access token for authenticated requests
        access_token = login_response.data['access']
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + access_token)
        profile_status_response = self.client.get(self.profile_status_url)
        self.assertEqual(profile_status_response.status_code, status.HTTP_200_OK)
        self.assertIn('has_profile', profile_status_response.data)
        self.assertIn('has_seller_profile', profile_status_response.data)
        self.assertFalse(profile_status_response.data['has_profile'])
        self.assertFalse(profile_status_response.data['has_seller_profile'])

    def test_token_refresh(self):
        # Register and get tokens
        self.client.post(self.register_url, self.user_data)
        login_response = self.client.post(self.login_url, {
            "email": self.user_data['email'],
            "password": self.user_data['password']
        })
        refresh_token = login_response.data['refresh']

        # Refresh token
        refresh_response = self.client.post(self.refresh_url, {'refresh': refresh_token})
        self.assertEqual(refresh_response.status_code, status.HTTP_200_OK)
        self.assertIn("access", refresh_response.data)

    # User Profile flow

    def test_user_registration_password_mismatch(self):
        bad_data = self.user_data.copy()
        bad_data['confirm_password'] = 'differentpassword'
        response = self.client.post(self.register_url, bad_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Passwords do not match.', str(response.data))

    def test_create_user_profile(self):
        self.authenticated()
        response = self.client.post(self.user_profile_url, self.profile_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('profile', response.data)

    def test_prevent_duplicate_user_profile(self):
        self.authenticated()
        self.client.post(self.user_profile_url, self.profile_data)
        response = self.client.post(self.user_profile_url, self.profile_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_get_user_profile(self):
        self.authenticated()
        self.client.post(self.user_profile_url, self.profile_data)
        response = self.client.get(self.user_profile_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('shipping_address', response.data)

    def test_update_user_profile(self):
        self.authenticated()
        self.client.post(self.user_profile_url, self.profile_data)
        updated_data = {'shipping_address': '789 Updated St, Test City'}
        response = self.client.put(self.user_profile_url, updated_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['shipping_address'], updated_data['shipping_address'])

    # Seller Profile flow
    def test_create_seller_profile(self):
        self.authenticated()
        response = self.client.post(self.seller_profile_url, self.seller_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('profile', response.data)

    def test_prevent_duplicate_seller_profile(self):
        self.authenticated()
        self.client.post(self.seller_profile_url, self.seller_data)
        response = self.client.post(self.seller_profile_url, self.seller_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_get_unverified_seller_profile_forbidden(self):
        self.authenticated()
        self.client.post(self.seller_profile_url, self.seller_data)
        response = self.client.get(self.seller_profile_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_update_seller_profile(self):
        self.authenticated()
        self.client.post(self.seller_profile_url, self.seller_data)
        updated_data = {'shop_description': 'Updated shop info'}
        response = self.client.put(self.seller_profile_url, updated_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['shop_description'], updated_data['shop_description'])

    def test_profile_status_view(self):
        self.authenticated()
        response = self.client.get(self.profile_status_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('has_profile', response.data)
        self.assertIn('has_seller_profile', response.data)