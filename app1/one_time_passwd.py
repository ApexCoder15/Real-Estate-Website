from django.core.mail import send_mail
from django.http import JsonResponse
import random

def send_otp(email_id):
    otp = str(random.randint(100000, 999999))
    subject = 'OTP Verification'
    message = f'Your OTP for verification is: {otp}'
    from_email = 'vatsal.ch15@gmail.com'  # Replace with your email address
    send_mail(subject, message, from_email, [email_id], fail_silently=False)
    return otp