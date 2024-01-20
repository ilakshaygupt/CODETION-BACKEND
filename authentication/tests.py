from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from authentication.models import User, OneTimePassword

class RegisterViewTest(TestCase):
    def test_register_view(self):
        url = reverse('register')  
        data = {'email': 'test@example.com', 'username': 'testuser', 'password': 'Test@123'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(OneTimePassword.objects.count(), 1)

    def test_register_invalid_view(self):
        url = reverse('register')  
        data = {'email': 'test@example.com', 'username': 'testuser', 'password': 'herenothere'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(User.objects.count(), 0)
        self.assertEqual(OneTimePassword.objects.count(), 0)

    def test_user_already_exists_email(self):
        User.objects.create_user(email='test@example.com', username='testuser', password='Test@123', is_verified=True)
        url = reverse('register')
        data = {'email': 'test@example.com', 'username': 'testuser2', 'password': 'Test@123'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['message'], 'email already exists')
        self.assertFalse(response.data['success'])

    def test_user_already_exists_username(self):
        User.objects.create_user(email='test@example.com', username='testuser', password='Test@123', is_verified=True)
        url = reverse('register')
        data = {'email': 'test2@example.com', 'username': 'testuser', 'password': 'Test@123'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['message'], 'username already exists')
        self.assertFalse(response.data['success'])
