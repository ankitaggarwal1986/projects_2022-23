from django.urls import path
from account.views import SendPasswordResetEmailView, UserChangePasswordView, UserPasswordResetView, UserProfileView, UserRegisterationView, UserLoginView

urlpatterns = [
    path('register/', UserRegisterationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('change_password/', UserChangePasswordView.as_view(), name='change_password'),
    path('passwordresetemail/', SendPasswordResetEmailView.as_view(), name='passwordresetemail'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
]
