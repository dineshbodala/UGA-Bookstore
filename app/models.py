import random
from django.db import models
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import UserManager
from datetime import date


# Create your models here.


def random_number_generator():
    return random.randint(100000, 999999)


def random_id():
    return random.randint(10000, 99999)


CATEGORY_CHOICES = (
    ('BIO', 'Biography'),
    ('FIC', 'Fiction'),
    ('HIS', 'History'),
    ('HOR', 'Horror'),
    ('MYS', 'Mystery'),
    ('NOF', 'NonFiction'),
    ('ROM', 'Romance'),
    ('SCI', 'SciFi'),
    ('THR', 'Thriller'),
)


class Book(models.Model):
    ISBN = models.CharField(max_length=100)
    category = models.CharField(choices=CATEGORY_CHOICES, max_length=5)
    author = models.CharField(max_length=100)
    title = models.CharField(max_length=100)
    cover = models.ImageField(upload_to='book')
    edition = models.CharField(max_length=100)
    publisher = models.CharField(max_length=100)
    publication_year = models.IntegerField()
    quantity = models.IntegerField()
    minimum_threshold = models.IntegerField()
    buying_price = models.FloatField()
    selling_price = models.FloatField()
    rating = models.IntegerField()
    featured = models.BooleanField(default=False)
    topSeller = models.BooleanField(default=False)
    newReleases = models.BooleanField(default=False)
    description = models.TextField(default='null')

    def __str__(self):
        return self.title

    @property
    def coverURL(self):
        try:
            url = self.cover.url
        except:
            url = ''
        return url


class User(models.Model):
    account_id = models.IntegerField(unique=True, default=random_number_generator)
    firstname = models.CharField(max_length=100)
    lastname = models.CharField(max_length=100)
    phonenumber = models.CharField(max_length=100)
    email = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    accept_terms = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_loggedin = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    activation_token = models.CharField(max_length=255, blank=True, null=True)
    reset_token = models.CharField(max_length=255, blank=True, null=True)

    # def save(self, *args, **kwargs):
    #     if not self.pk:
    #         # New user, hash the password
    #         self.password = make_password(self.password)
    #     super().save(*args, **kwargs)

    def check_password(self, password):
        return check_password(password, self.password)

    def __str__(self):
        return self.firstname



class Promotion(models.Model):
    promocode = models.CharField(max_length=100)
    percentage = models.IntegerField()
    startdate = models.DateTimeField()
    enddate = models.DateTimeField()

    def __str__(self):
        return self.promocode


class Address(models.Model):
    address_id = models.IntegerField(unique=True, primary_key=True, default=random_id)
    account_id = models.IntegerField()
    street_address = models.CharField(max_length=50, default=' ', blank=True)
    apartment_suite = models.CharField(max_length=50, default=' ', blank=True)
    city = models.CharField(max_length=30, default=' ', blank=True)
    state = models.CharField(max_length=30, default=' ', blank=True)
    zip_code = models.CharField(max_length=30, default=' ', blank=True)
    contact_phone = models.CharField(max_length=30, default=' ', blank=True)
    contact_email = models.CharField(max_length=30, default=' ', blank=True)

    def __str__(self):
        return self.city


class PaymentDetails(models.Model):
    payment_id = models.IntegerField(unique=True, primary_key=True, default=random_id)
    account_id = models.IntegerField()
    card_number = models.CharField(max_length=80, default=' ')
    expiration_date = models.CharField(max_length=5, default=' ', blank=True)
    security_code = models.CharField(max_length=80, default=' ', blank=True)

    def __str__(self):
        return self.card_number

class Order(models.Model):
    customer = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    date_ordered = models.DateTimeField(auto_now_add=True)
    complete = models.BooleanField(default=False)
    transaction_id = models.CharField(max_length=100, null=True)
    cart_total = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    shipping_address = models.ForeignKey(Address, on_delete=models.SET_NULL, null=True, blank=True)
    credit_card = models.ForeignKey(PaymentDetails, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return str(self.id)

    @property
    def get_cart_total(self):
        orderitems = self.orderitem_set.all()
        total = sum([item.get_total for item in orderitems])
        return total

    @property
    def get_cart_items(self):
        orderitems = self.orderitem_set.all()
        total = sum([item.quantity for item in orderitems])
        return total
    
class OrderItem(models.Model):
    product = models.ForeignKey(Book, on_delete=models.SET_NULL, null=True)
    order = models.ForeignKey(Order, on_delete=models.SET_NULL, null=True)
    quantity = models.IntegerField(default=0, null=True, blank=True)
    date_added = models.DateTimeField(auto_now_add=True)

    @property
    def get_total(self):
        total = self.product.selling_price * self.quantity
        return total
