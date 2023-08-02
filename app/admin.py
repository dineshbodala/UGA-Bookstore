from django.contrib import admin
from . models import *

# Register your models here.

@admin.register(Book)
class BookModelAdmin(admin.ModelAdmin):
    list_display = ['ISBN', 'category', 'title', 'featured', 'topSeller', 'newReleases', 'buying_price', 'selling_price']

@admin.register(User)
class UserModelAdmin(admin.ModelAdmin):
    list_display = ['account_id', 'firstname', 'lastname']

@admin.register(Promotion)
class PromotionModelAdmin(admin.ModelAdmin):
    list_display = ['promocode', 'percentage']

@admin.register(Order)
class OrderModelAdmin(admin.ModelAdmin):
    list_display = ['customer', 'complete', 'transaction_id']

@admin.register(OrderItem)
class OrderModelAdmin(admin.ModelAdmin):
    list_display = ['product', 'order', 'quantity']


@admin.register(Address)
class AddressModelAdmin(admin.ModelAdmin):
    list_display = ['address_id', 'account_id', 'street_address', 'apartment_suite', 'city', 'state', 'zip_code', ]

@admin.register(PaymentDetails)
class PaymentModelAdmin(admin.ModelAdmin):
    list_display = ['payment_id', 'account_id']