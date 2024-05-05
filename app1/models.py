from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser

# Create your models here.

class MyUserManager(BaseUserManager):
    def create_user(self, email, name, user_type, is_superuser, password=None):
        if not email:
            raise ValueError("Email should be given.")
        user = self.model(
            email = self.normalize_email(email),
            user_type = user_type,
            name = name,
            is_active = True,
            is_superuser = is_superuser,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password):
        return self.create_user(email, "admin", "0", True, password)
    
class MyUser(AbstractBaseUser):
    name = models.CharField(max_length=50)
    email = models.EmailField(verbose_name="Email Address", max_length=255, unique=True)
    type_choices = (("0", "Sellers and Lessers"), ("1", "Buyers and Lessees"), ("2", "Aggregator"))
    user_type = models.CharField(max_length=2, choices=type_choices, default="0")
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)
    admin_auth = models.BooleanField(default=False)
    reported = models.BooleanField(default=False)
    

    objects = MyUserManager()

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS = []

class property(models.Model):
    sellor_lessor = models.ForeignKey(MyUser, on_delete=models.CASCADE, db_column='seller')
    contract_choices = (("0", "Rent"), ("1", "Sell"))
    contract_type = models.CharField(max_length=2, choices=contract_choices)
    type_choices = (("0", "Land"), ("1", "Flat"), ("2", "House"), ("3", "Farm"))
    prop_type = models.CharField(max_length=2, choices=type_choices)
    price = models.IntegerField()
    location = models.CharField(max_length=50)
    close_metro = models.BooleanField()
    close_NH = models.BooleanField()
    close_ap = models.BooleanField()
    date_avail = models.DateField()

class blockchain(models.Model):
    genesis_str = models.CharField(max_length=50)
    chain = models.JSONField()
    