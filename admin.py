from django.contrib import admin

# Register your models here.
from .models import UserRegistrationModel,TokenCountModel

admin.site.register(UserRegistrationModel)

admin.site.register(TokenCountModel)