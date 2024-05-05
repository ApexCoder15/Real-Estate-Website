from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from app1.models import MyUser, property
from django import forms

class customAuthenticationForm(AuthenticationForm):
    class Meta():
        model = MyUser

class upload_key(forms.Form):
    file = forms.FileField()

class create_user_form(UserCreationForm):
    class Meta:
        model = MyUser
        fields = ["email", "name", "user_type"]

class add_prop_form(forms.ModelForm):
    class Meta:
        model = property
        exclude = ["sellor_lessor"]
