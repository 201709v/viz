import uuid
from django.db import models

import uuid
from django.db import models

class UserRegistrationModel(models.Model):
    name = models.CharField(max_length=100)
    loginid = models.CharField(unique=True, max_length=100)
    password = models.CharField(max_length=100)
    mobile = models.CharField(unique=True, max_length=100)
    email = models.CharField(unique=True, max_length=100)
    locality = models.CharField(max_length=100)
    address = models.CharField(max_length=1000)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    status = models.CharField(max_length=100, default='waiting')
    key = models.CharField(unique=True, max_length=255, blank=True, editable=False)

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = f"{self.loginid}_{self.mobile}_{uuid.uuid4().hex[:8]}"
        super().save(*args, **kwargs)
        print(f"Generated Key: {self.key}")  # Print the key in original format

    def __str__(self):
        return self.key  # This will return the key instead of an object reference

    class Meta:
        db_table = 'UserRegistrations'

class TokenCountModel(models.Model):
    loginid = models.CharField(unique=True, max_length=100)
    count = models.IntegerField()

    def __str__(self):
        return self.loginid

    class Meta:
        db_table = 'TokenCountTable'

