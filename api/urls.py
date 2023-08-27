from django.urls import path
from . import views

urlpatterns = [
    path('',views.home),
    path('auth',views.authorize),
    path('getoauthuri',views.getAuthURI),
]