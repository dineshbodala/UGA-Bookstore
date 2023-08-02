import random
import string
from decimal import Decimal
from django.shortcuts import render, redirect
from django.shortcuts import render, get_object_or_404
from django.views import View
from .models import Book, User, OrderItem, Order, Address, PaymentDetails
from django.utils.html import strip_tags
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_str
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.core.signing import TimestampSigner
from django.urls import reverse
from django.contrib.auth import login
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from django.core import signing
from django.contrib.auth import authenticate, login
from django.http import HttpResponseRedirect, JsonResponse
from .utils import cookieCart, cartData
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponseRedirect
from django.core.exceptions import ObjectDoesNotExist
import re, json
import datetime


# custom methods

def is_six_digit_number(string):
    pattern = r'^\d{6}$'  # Matches a string consisting of exactly 6 digits
    return bool(re.match(pattern, string))


# Create your views here.
def home(request):
    if request.session.get('user_id'):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        order, created = Order.objects.get_or_create(customer=user, complete=False)
        items = order.orderitem_set.all()
        featuredBooks = Book.objects.filter(featured=True)
        topSellers = Book.objects.filter(topSeller=True)
        context = {'items': items, 'user': user, 'order': order, 'featuredBooks': featuredBooks,
                   'topSellers': topSellers}
    else:
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        featuredBooks = Book.objects.filter(featured=True)
        topSellers = Book.objects.filter(topSeller=True)
        context = {'user': user, 'featuredBooks': featuredBooks, 'topSellers': topSellers}
    return render(request, "app/home.html", context)


class CategoryView(View):
    def get(self, request, val):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        book = Book.objects.filter(category=val)
        order, created = Order.objects.get_or_create(customer=user, complete=False)
        title = Book.objects.filter(category=val).values('title')
        category_name = Book.objects.filter(category=val).values('category')
        return render(request, "app/category.html", locals())


class NewreleasesView(View):
    def get(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        book = Book.objects.filter(newReleases=True)
        order, created = Order.objects.get_or_create(customer=user, complete=False)
        title = Book.objects.filter(newReleases=True).values('title')
        category_name = Book.objects.filter(newReleases=True).values('category')
        return render(request, "app/newReleases.html", locals())


class TopsellersView(View):
    def get(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        book = Book.objects.filter(topSeller=True)
        order, created = Order.objects.get_or_create(customer=user, complete=False)
        title = Book.objects.filter(topSeller=True).values('title')
        category_name = Book.objects.filter(topSeller=True).values('category')
        return render(request, "app/topSellers.html", locals())


class SearchView(View):
    def get(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        order, created = Order.objects.get_or_create(customer=user, complete=False)
        return render(request, "app/search.html", locals())


class SignupView(View):

    @staticmethod
    def encrypt(value):
        encrypted_value = signing.dumps(value)
        return encrypted_value

    def get(self, request):
        return render(request, "app/signup/signup.html", locals())

    def post(self, request):
        # Retrieve the form data from the POST request
        firstname = request.POST.get('firstname')
        lastname = request.POST.get('lastname')
        phonenumber = request.POST.get('phonenumber')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        card_number = self.encrypt(request.POST.get('card_number'))
        expiration_date = request.POST.get('expiration_date')
        security_code = self.encrypt(request.POST.get('security_code'))
        street_address = request.POST.get('street_address')
        apartment_suite = request.POST.get('apartment_suite')
        city = request.POST.get('city')
        state = request.POST.get('state')
        zip_code = request.POST.get('zip_code')
        contact_phone = request.POST.get('contact_phone')
        contact_email = request.POST.get('contact_email')
        accept_terms = request.POST.get('accept_terms')

        # Check if passwords match
        if password != confirm_password:
            # Render the signup page with an error message
            return render(request, "app/signup/signup.html", {'password_mismatch': True})

        try:
            existing_user = User.objects.get(email=email)
        except User.DoesNotExist:
            existing_user = None

        if existing_user:
            print(1)
            return render(request, "app/signup/signup.html", {'email_exists': True})

        hashed_password = make_password(password)

        user = User(firstname=firstname,
                    lastname=lastname,
                    phonenumber=phonenumber,
                    email=email,
                    password=hashed_password,
                    accept_terms=accept_terms,
                    is_active=False
                    )

        signer = TimestampSigner()
        activation_token = signer.sign(email)  # Use the email as the token
        user.activation_token = activation_token
        user.save()

        account_id = user.account_id

        add_address(account_id, street_address, apartment_suite, city, state, zip_code, contact_phone, contact_email)
        add_payment_details(account_id, card_number, expiration_date, security_code)

        # Prepare activation email
        activation_link = request.build_absolute_uri(
            reverse('activate_account', kwargs={'token': activation_token})
        )
        mail_subject = 'Activate your account'
        context = {
            'user': user,
            'activation_link': activation_link,
            'token': activation_token,  # Add the token variable to the context
        }
        message = render_to_string('app/signup/activation_email.html', context)

        # Send activation email
        send_mail(mail_subject, strip_tags(message), settings.DEFAULT_FROM_EMAIL, [email], html_message=message)

        # Redirect to the signup success page
        return render(request, "app/signup/signupSuccess.html", locals())


class SignupSuccessView(View):
    def get(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        return render(request, "app/signup/signupSuccess.html", locals())


class SigninView(View):
    def get(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        return render(request, "app/signin/signin.html", locals())

    def post(self, request):
        # Retrieve the form data from the POST request
        email_accountid = request.POST.get('email_accountid')
        password = request.POST.get('password')
        remember_me = request.POST.get('remember_me')

        try:
            if '@' in email_accountid:
                # If the provided value contains '@', treat it as an email
                user = User.objects.get(email=email_accountid)
            elif is_six_digit_number(str(email_accountid)):
                # Otherwise, treat it as an account ID
                user = User.objects.get(account_id=email_accountid)
            else:
                user = User.objects.get(firstname=email_accountid)
        except ObjectDoesNotExist:
            return render(request, "app/signin/signin.html", {'user_not_found': True})



        if user is not None and user.check_password(password):
            if not user.is_active:
                print("done1")
                return render(request, "app/signin/accountSuspended.html", locals())
            elif user.is_admin:
                # Log in the user as an admin
                admin_user = authenticate(request, username=user.firstname, password=password)
                if admin_user is not None:
                    login(request, admin_user)
                    return HttpResponseRedirect(reverse('admin:index'))
                print("done2")
            else:
                print("loggedin")
                user.is_loggedin = True
                # Create a new session

                session = SessionStore()
                session['user_id'] = user.id
                if remember_me:
                    # Set the session expiry to a longer duration
                    session_expiry = session.set_expiry(604800)  # 7 days
                else:
                    # Set the session expiry to the default duration (using SESSION_COOKIE_AGE)
                    session_expiry = session.set_expiry(0)
                session.save()

                # Set the session ID in the response cookies
                response = render(request, "app/signin/loginSuccess.html", locals())
                response.set_cookie('sessionid', session.session_key, session_expiry)

                # Redirect to the home page or any other desired page
                return response
        elif user is None:
            return render(request, "app/signin/signin.html")

        else:
            return render(request, "app/signin/signin.html", {'auth_failed': True, 'login_failed': True})



class LogoutView(View):
    def get(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        order, created = Order.objects.get_or_create(customer=user, complete=False)
        # Get the user's session key
        session_key = request.COOKIES.get('sessionid')

        # Clear the session data
        Session.objects.filter(session_key=session_key).delete()

        # Update the is_loggedin field to False
        try:
            user = User.objects.get(id=request.user.id)
            user.is_loggedin = False
            user.save()
        except User.DoesNotExist:
            pass

        # Redirect to the desired page after logout
        return render(request, "app/signout/logoutSuccess.html", locals())


class ProfileView(View):
    @staticmethod
    def encrypt(value):
        encrypted_value = signing.dumps(value)
        return encrypted_value

    def decrypt(self, encrypted_value):
        decrypted_value = signing.loads(encrypted_value)
        return decrypted_value

    def get(self, request):
        user_id = request.session.get('user_id')
        user = User.objects.get(id=user_id) if user_id else None
        # user.card_number = self.decrypt(user.card_number)
        # user.security_code = self.decrypt(user.security_code)
        order, created = Order.objects.get_or_create(customer=user, complete=False)
        return render(request, "app/profile/profile.html", {'user': user, 'order': order})

    def post(self, request):
        user_id = request.session.get('user_id')
        user = User.objects.get(id=user_id) if user_id else None
        order, created = Order.objects.get_or_create(customer=user, complete=False)

        if user:
            # Update the user's information based on the submitted form data
            user.firstname = request.POST.get('firstname')
            user.lastname = request.POST.get('lastname')
            user.phonenumber = request.POST.get('phonenumber')
            user.email = request.POST.get('email')
            # user.card_number = self.encrypt(request.POST.get('card_number'))
            # user.expiration_date = request.POST.get('expiration_date')
            # user.security_code = self.encrypt(request.POST.get('security_code'))
            # user.street_address = request.POST.get('street_address')
            # user.apartment_suite = request.POST.get('apartment_suite')
            # user.city = request.POST.get('city')
            # user.state = request.POST.get('state')
            # user.zip_code = request.POST.get('zip_code')
            # user.contact_phone = request.POST.get('contact_phone')

            # Save the updated user object
            user.save()
            mail_subject = 'Profile Updated'
            context = {
                'user': user,
            }
            message = render_to_string('app/profile/profile_update_success.html', context)

            # Send the email with the user_id
            send_mail(mail_subject, strip_tags(message), settings.DEFAULT_FROM_EMAIL, [user.email])

        return render(request, "app/profile/edit_profile_success.html", {'user': user})


class ChangePwdView(View):
    def get(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        order, created = Order.objects.get_or_create(customer=user, complete=False)
        return render(request, "app/change_password/changePwd.html", locals())

    def post(self, request):
        old_password = request.POST.get('oldPassword')
        new_password1 = request.POST.get('newPassword1')
        new_password2 = request.POST.get('newPassword2')

        # Retrieve the user based on the session ID
        user_id = request.session.get('user_id')
        user = User.objects.get(id=user_id) if user_id else None
        print(user)

        if user:
            # Check if the old password matches the user's current password
            if user.check_password(old_password):
                # Validate the new password
                if new_password1 == new_password2:
                    # Set the user's new password
                    user.password = make_password(new_password1)
                    user.save()
                    print("changed")

                    return render(request, "app/change_password/chgPwdSuccess.html",
                                  locals())  # Redirect to the profile page or any other desired page
                else:
                    return render(request, "app/change_password/changePwd.html", {'match_failed': True})
            else:
                print('old wrong pwd')
        else:
            print('user nf')

        return render(request, "app/change_password/changePwd.html", {'check_failed': True})


class BookDetailsView(View):
    def get(self, request, book_isbn):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        order, created = Order.objects.get_or_create(customer=user, complete=False)
        items = order.orderitem_set.all()
        book = get_object_or_404(Book, ISBN=book_isbn)
        return render(request, "app/bookDetails.html", locals())


def updateItem(request):
    data = json.loads(request.body)
    bookId = data['bookId']
    action = data['action']
    print(bookId, action)
    customer = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
    product = Book.objects.get(id=bookId)
    order, created = Order.objects.get_or_create(customer=customer, complete=False)
    orderItem, created = OrderItem.objects.get_or_create(order=order, product=product)

    if action == 'add':
        orderItem.quantity = (orderItem.quantity + 1)
    elif action == 'remove':
        orderItem.quantity = (orderItem.quantity - 1)
        if orderItem.quantity <= 0:
            orderItem.delete()

    elif action == 'remove_item':
        orderItem.quantity = 0
    orderItem.save()

    if orderItem.quantity <= 0:
        orderItem.delete()

    return JsonResponse('Book was added', safe=False)
    # return HttpResponseRedirect(request.path_info)


def decrypt(self, encrypted_value):
    decrypted_value = signing.loads(encrypted_value)
    return decrypted_value


def cart(request):
    if request.session.get('user_id'):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        order, created = Order.objects.get_or_create(customer=user, complete=False)
        items = order.orderitem_set.all()
        tax = order.get_cart_total * 0.05
        context = {'items': items, 'user': user, 'order': order, 'tax': tax}
    else:
        items = []
        context = {'items': items}
    print(len(items))
    return render(request, 'app/order/cart.html', context, )


class CheckoutView(View):
    def get(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        order, created = Order.objects.get_or_create(customer=user, complete=False)

        # Fetch addresses and cards associated with the current user
        user_addresses = Address.objects.filter(account_id=user.account_id)
        user_cards = PaymentDetails.objects.filter(account_id=user.account_id)

        return render(request, "app/order/checkout.html", {
            'user': user,
            'user_addresses': user_addresses,
            'user_cards': user_cards,
        })
    
    def post(self, request):
        # Get the selected address and card IDs from the POST data
        selected_address_id = request.POST.get('address_radio')
        selected_card_id = request.POST.get('card_radio')

        # Get the user and the order associated with the user
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        order, created = Order.objects.get_or_create(customer=user, complete=False)

        # Update the order with the selected address and card IDs
        if selected_address_id:
            address = Address.objects.get(address_id=selected_address_id)
            order.shipping_address = address

        if selected_card_id:
            card = PaymentDetails.objects.get(payment_id=selected_card_id)
            order.credit_card = card

        # Save the changes to the order and redirect to the order summary page
        order.save()
        return redirect('orderSummary')


class OrderSummaryView(View):
    def get(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        order, created = Order.objects.get_or_create(customer=user, complete=False)
        items = order.orderitem_set.all()
        tax = round(order.get_cart_total * 0.05, 2)
        total = round(order.get_cart_total + tax, 2)
        context = {'items': items, 'user': user, 'order': order, 'tax': tax, 'total': total}
        return render(request, "app/order/orderSummary.html", context)


@csrf_exempt
def process_order(request):
    user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
    order, created = Order.objects.get_or_create(customer=user, complete=False)

    if user:
        order, created = Order.objects.get_or_create(customer=user, complete=False)

        order.complete = True

        # Calculate the cart total
        order.cart_total = Decimal(order.get_cart_total)

        # Generate a 5-digit transaction ID
        transaction_id = ''.join(random.choices(string.digits, k=5))
        order.transaction_id = transaction_id

        order.save()

        

        order_items = order.orderitem_set.all()
        print(order.cart_total, order.transaction_id)
        # order_items.update(quantity=0)

        for item in order_items:
                book = item.product
                book.quantity -= item.quantity
                book.save()

        # Generate a list of dictionaries containing order_items details
        order_items_details = []
        for item in order_items:
            order_items_details.append({
                'product_title': item.product.title,
                'quantity_ordered': item.quantity,
            })
        print(order_items_details)
        mail_subject = 'Order Confirmed!! - Transaction_id:' + str(order.transaction_id)
        message = render_to_string('app/order/orderConfirmationEmail.html', {
            'user_id': user.firstname,
            'order_items': order_items_details,
            'cart_total': "{:.2f}".format(order.cart_total),
            'transaction_id': order.transaction_id,
        })

        # Send the email with the user_id
        # send_mail(mail_subject, strip_tags(message), settings.DEFAULT_FROM_EMAIL, [user.email])
        send_mail(mail_subject, "", settings.DEFAULT_FROM_EMAIL, [user.email], html_message=message)

        return JsonResponse({'message': 'Order processed successfully.', 'transaction_id': transaction_id})
    else:
        return JsonResponse({'message': 'User not logged in.'})


class OrderSuccessView(View):
    def get(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        return render(request, "app/order/orderSuccess.html", locals())


class OrderHistoryView(View):
    def get(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        order, created = Order.objects.get_or_create(customer=user, complete=False)
        items = order.orderitem_set.all()
        orders = Order.objects.filter(customer=user, complete=True)
        for ordered in orders:
            ordered, created = Order.objects.get_or_create(customer=user, complete=False)

            order_items = ordered.orderitem_set.all()

            print(f"Order ID: {ordered.id}")
            for item in order_items:
                product_title = item.product.title
                quantity_ordered = item.quantity
                print(f"Book Title: {product_title}, Quantity Ordered: {quantity_ordered}")
        return render(request, "app/order/orderHistory.html", locals())


def view_order(request, transaction_id):
    # Retrieve the order based on the transaction_id
    user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
    ordered = get_object_or_404(Order, transaction_id=transaction_id)
    order, created = Order.objects.get_or_create(customer=user, complete=False)
    used_card = ordered.credit_card.card_number if ordered.credit_card else None
    # Retrieve all order items for the order
    order_items = ordered.orderitem_set.all()
    tax = round(ordered.get_cart_total * 0.05, 2)
    total = round(tax + ordered.get_cart_total, 2)

    return render(request, 'app/order/vieworder.html',
                  {'user': user, 'ordered': ordered, 'order_items': order_items, 'tax': tax, 'total': total,
                   'order': order, 'used_card':used_card })


class ReOrderSuccessView(View):
    def get(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        order, created = Order.objects.get_or_create(customer=user, complete=False)
        return render(request, "app/order/reorderSuccess.html", locals())
    
def reorder(request, transaction_id):
    ordered = get_object_or_404(Order, transaction_id=transaction_id)
    user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
    order, created = Order.objects.get_or_create(customer=user, complete=False)
    order_items = ordered.orderitem_set.all()
    order.orderitem_set.all().delete()
    for item in order_items:
        OrderItem.objects.create(order=order, product=item.product, quantity=item.quantity)
    order.cart_total = Decimal(order.get_cart_total)
    new_transaction_id = ''.join(random.choices(string.digits, k=5))
    order.transaction_id = new_transaction_id
    order.save()

    return JsonResponse({'message': 'Reorder processed successfully.', 'transaction_id': new_transaction_id})


def activate_account(request, token):
    try:
        user = User.objects.get(activation_token=token)
    except User.DoesNotExist:
        user = None

    if user is not None:
        user.is_active = True
        user.activation_token = None
        user.save()

        # Prepare the email with the user_id
        mail_subject = 'Your Account ID'
        message = render_to_string('app/profile/user_id_email.html', {
            'account_id': user.account_id,
        })

        # Send the email with the user_id
        send_mail(mail_subject, strip_tags(message), settings.DEFAULT_FROM_EMAIL, [user.email])

        return render(request, 'app/signup/account_activated.html')

    return render(request, "app/signup/activation_error.html")


class FpEnterEmailView(View):
    def get(self, request):
        return render(request, "app/forgot_password/Fp_Enter_Email.html", locals())

    def post(self, request):
        # Retrieve the form data from the POST request
        email = request.POST.get('reset_email')

        # OTP Generator
        reset_token = random.randint(100000, 999999)

        user = User.objects.get(email=email)
        print(user)
        user.reset_token = reset_token
        print(user.reset_token)
        user.save()

        mail_subject = 'Reset your password'
        context = {
            'user': user,
            'token': reset_token,  # Add the token variable to the context
        }
        message = render_to_string('app/forgot_password/Reset_Link_email.html', context)

        # Send activation email
        send_mail(mail_subject, strip_tags(message), settings.DEFAULT_FROM_EMAIL, [email], html_message=message)

        # Redirect to the signup success page
        return redirect('ResetPassword')


class reset_account(View):
    def get(self, request):
        return render(request, "app/forgot_password/reset_password.html", locals())

    def post(self, request):
        validate_token = request.POST.get('otp')
        new_password1 = request.POST.get('password1')
        new_password2 = request.POST.get('password2')
        try:
            user = User.objects.get(reset_token=validate_token)
        except User.DoesNotExist:
            user = None

        if user is not None and new_password1 == new_password2:
            user.reset_token = None
            user.password = make_password(new_password1)
            user.save()

            # Prepare the email with the user_id
            mail_subject = 'Password Changed'
            message = render_to_string('app/forgot_password/password_reset_success.html')

            # Send the email with the user_id
            send_mail(mail_subject, strip_tags(message), settings.DEFAULT_FROM_EMAIL, [user.email])

            return render(request, 'app/forgot_password/reset_password_success.html')

        return render(request, "app/forgot_password/reset_password_error.html")


def add_address(account_id, street_address, apartment_suite, city, state, zip_code, contact_phone, contact_email):
    address = Address(account_id=account_id,
                      street_address=street_address,
                      apartment_suite=apartment_suite,
                      city=city,
                      state=state,
                      zip_code=zip_code,
                      contact_phone=contact_phone,
                      contact_email=contact_email)
    address.save()


def add_payment_details(account_id, card_number, expiration_date, security_code):
    payment_details = PaymentDetails(account_id=account_id,
                                     card_number=card_number,
                                     expiration_date=expiration_date,
                                     security_code=security_code)
    payment_details.save()


class SearchBooks(View):
    def post(self, request):

        if request.session.get('user_id'):
            user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
            orders = Order.objects.filter(customer=user, complete=True)
            order, created = Order.objects.get_or_create(customer=user, complete=False)
            print(user.is_active)
            search_term = request.POST.get('searched')
            filter_option = request.POST.get('filter_option', 'Title')

            # Use the appropriate field lookup based on the selected filter option
            if filter_option == 'Title':
                results = Book.objects.filter(title__icontains=search_term)
            elif filter_option == 'ISBN':
                results = Book.objects.filter(isbn__icontains=search_term)
            elif filter_option == 'Author':
                results = Book.objects.filter(author__icontains=search_term)
            elif filter_option == 'Category':
                results = Book.objects.filter(category__icontains=search_term)
            else:
                # Invalid filter option, handle the error accordingly
                results = None
            context = {'user': user, 'orders': orders, 'results': results, 'order': order}
            return render(request, 'app/search_books.html', context)
        else:
            search_term = request.POST.get('searched')
            filter_option = request.POST.get('filter_option', 'Title')

            # Use the appropriate field lookup based on the selected filter option
            if filter_option == 'Title':
                results = Book.objects.filter(title__icontains=search_term)
            elif filter_option == 'ISBN':
                results = Book.objects.filter(isbn__icontains=search_term)
            elif filter_option == 'Author':
                results = Book.objects.filter(author__icontains=search_term)
            elif filter_option == 'Category':
                results = Book.objects.filter(category__icontains=search_term)
            else:
                # Invalid filter option, handle the error accordingly
                results = None

            context = {'results': results}
            return render(request, 'app/search_books.html', context)


class AddressView(View):
    def get(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        order, created = Order.objects.get_or_create(customer=user, complete=False)
        user_addresses = Address.objects.filter(account_id=user.account_id)
        return render(request, "app/profile/address.html",
                      {'user': user, 'order': order, 'user_addresses': user_addresses})


class NewAddressView(View):
    def get(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        order, created = Order.objects.get_or_create(customer=user, complete=False)
        return render(request, "app/profile/new_address.html", {'user': user, 'order': order})

    def post(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        # Handle the form submission to add a new address
        street_address = request.POST.get('street_address')
        apartment_suite = request.POST.get('apartment_suite')
        city = request.POST.get('city')
        state = request.POST.get('state')
        zip_code = request.POST.get('zip_code')
        contact_phone = request.POST.get('contact_phone')
        contact_email = request.POST.get('contact_email')

        # Save the new address in the database
        new_address = Address(account_id=user.account_id, street_address=street_address,
                              apartment_suite=apartment_suite, city=city, state=state, zip_code=zip_code,
                              contact_phone=contact_phone, contact_email=contact_email)
        new_address.save()

        return redirect('address')
    
class ChkoutNewAddressView(View):
    def get(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        order, created = Order.objects.get_or_create(customer=user, complete=False)
        return render(request, "app/order/checkout_add_new_addr.html", {'user': user, 'order': order})

    def post(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        # Handle the form submission to add a new address
        street_address = request.POST.get('street_address')
        apartment_suite = request.POST.get('apartment_suite')
        city = request.POST.get('city')
        state = request.POST.get('state')
        zip_code = request.POST.get('zip_code')
        contact_phone = request.POST.get('contact_phone')
        contact_email = request.POST.get('contact_email')

        # Save the new address in the database
        new_address = Address(account_id=user.account_id, street_address=street_address,
                              apartment_suite=apartment_suite, city=city, state=state, zip_code=zip_code,
                              contact_phone=contact_phone, contact_email=contact_email)
        new_address.save()

        return redirect('checkout')


class EditAddressView(View):
    def get(self, request, address_id):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        address = get_object_or_404(Address, address_id=address_id)
        order, created = Order.objects.get_or_create(customer=user, complete=False)
        return render(request, 'app/profile/edit_address.html', {'user': user, 'address': address, 'order': order})

    def post(self, request, address_id):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        address = get_object_or_404(Address, address_id=address_id)
        if request.method == 'POST':
            address.street_address = request.POST.get('street_address')
            address.apartment_suite = request.POST.get('apartment_suite')
            address.city = request.POST.get('city')
            address.state = request.POST.get('state')
            address.zip_code = request.POST.get('zip_code')
            address.contact_phone = request.POST.get('contact_phone')
            address.save()
            return redirect('address')
        return render(request, 'app/profile/edit_address.html', {'user': user, 'address': address})


class DeleteAddressView(View):
    def get(self, request, address_id):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        address = get_object_or_404(Address, address_id=address_id)
        return render(request, 'app/profile/delete_address.html', {'user': user, 'address': address})

    def post(self, request, address_id):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        address = get_object_or_404(Address, address_id=address_id)
        if request.method == 'POST':
            # Delete the address
            address.delete()
            return redirect('address')
        return render(request, 'app/profile/delete_address.html', {'user': user, 'address': address})


class PaymentView(View):
    def decrypt(self, encrypted_value):
        decrypted_value = signing.loads(encrypted_value)
        return decrypted_value

    def get(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        user_cards = PaymentDetails.objects.filter(account_id=user.account_id)
        order, created = Order.objects.get_or_create(customer=user, complete=False)
        return render(request, "app/profile/payment.html", {'user': user, 'user_cards': user_cards, 'order': order})

    def post(self, request):
        return redirect('add_card')


class AddCardView(View):
    @staticmethod
    def encrypt(value):
        encrypted_value = signing.dumps(value)
        return encrypted_value

    def get(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        orders = Order.objects.filter(customer=user, complete=True)
        order, created = Order.objects.get_or_create(customer=user, complete=False)
        return render(request, 'app/profile/add_card.html', {'user': user, 'orders': orders, 'order': order})

    def post(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        card_number = self.encrypt(request.POST.get('card_number'))
        expiration_date = request.POST.get('expiration_date')
        security_code = self.encrypt(request.POST.get('security_code'))

        payment_details = PaymentDetails(account_id=user.account_id, card_number=card_number,
                                         expiration_date=expiration_date, security_code=security_code)
        payment_details.save()

        return redirect('payment')
    
class ChkoutAddCardView(View):
    @staticmethod
    def encrypt(value):
        encrypted_value = signing.dumps(value)
        return encrypted_value

    def get(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        orders = Order.objects.filter(customer=user, complete=True)
        order, created = Order.objects.get_or_create(customer=user, complete=False)
        return render(request, 'app/order/checkout_add_new_card.html', {'user': user, 'orders': orders, 'order': order})

    def post(self, request):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        card_number = self.encrypt(request.POST.get('card_number'))
        expiration_date = request.POST.get('expiration_date')
        security_code = self.encrypt(request.POST.get('security_code'))

        payment_details = PaymentDetails(account_id=user.account_id, card_number=card_number,
                                         expiration_date=expiration_date, security_code=security_code)
        payment_details.save()

        return redirect('checkout')


class EditCardView(View):
    @staticmethod
    def encrypt(value):
        encrypted_value = signing.dumps(value)
        return encrypted_value

    def get(self, request, payment_id):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        card = get_object_or_404(PaymentDetails, payment_id=payment_id)
        orders = Order.objects.filter(customer=user, complete=True)
        order, created = Order.objects.get_or_create(customer=user, complete=False)
        return render(request, 'app/profile/edit_card.html',
                      {'user': user, 'card': card, 'orders': orders, 'order': order, })

    def post(self, request, payment_id):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        card = get_object_or_404(PaymentDetails, payment_id=payment_id)
        card_number = self.encrypt(request.POST.get('card_number'))
        expiration_date = request.POST.get('expiration_date')
        security_code = self.encrypt(request.POST.get('security_code'))

        card.card_number = card_number
        card.expiration_date = expiration_date
        card.security_code = security_code
        card.save()

        return redirect('payment')


class DeleteCardView(View):
    def get(self, request, payment_id):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        card = get_object_or_404(PaymentDetails, payment_id=payment_id)
        return render(request, 'app/profile/delete_card.html', {'user': user, 'card': card})

    def post(self, request, payment_id):
        user = User.objects.get(id=request.session.get('user_id')) if request.session.get('user_id') else None
        card = get_object_or_404(PaymentDetails, payment_id=payment_id)
        # Delete the card
        card.delete()
        return redirect('payment')
