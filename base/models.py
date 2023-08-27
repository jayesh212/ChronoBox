from django.db import models

# Create your models here.

class User(models.Model):
    name = models.CharField(max_length=50)
    email = models.CharField(max_length=200)
    created = models.DateTimeField(auto_now_add=True)
    accessToken = models.CharField(max_length=1000)
    refreshToken = models.CharField(max_length=1000)