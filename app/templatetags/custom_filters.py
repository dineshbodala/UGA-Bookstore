from django import template
from app.views import PaymentView  # Import PaymentView to access the decrypt method

register = template.Library()

@register.filter
def decrypt_value(encrypted_value):
    # Access the decrypt method from PaymentView and use it to decrypt the value
    return PaymentView().decrypt(encrypted_value)
