from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.home, name="home"),
    path('category/<slug:val>', views.CategoryView.as_view(), name="category"),
    path('search', views.SearchView.as_view(), name="search"),
    path('new-releases', views.NewreleasesView.as_view(), name="new-releases"),
    path('top-sellers', views.TopsellersView.as_view(), name="top-sellers"),
    path('search_books/', views.SearchBooks.as_view(), name='searchBooks'),
    path('signup', views.SignupView.as_view(), name="signup"),
    path('fPEnterEmail', views.FpEnterEmailView.as_view(), name="fPEnterEmail"),
    path('ResetPassword', views.reset_account.as_view(), name='ResetPassword'),
    path('activate/<str:token>/', views.activate_account, name='activate_account'),
    path('signupSuccess', views.SignupSuccessView.as_view(), name="signupSuccess"),
    path('signin', views.SigninView.as_view(), name="signin"),
    path('profile', views.ProfileView.as_view(), name="profile"),
    path('address', views.AddressView.as_view(), name="address"),
    path('edit-address/<int:address_id>/', views.EditAddressView.as_view(), name='edit_address'),
    path('delete-address/<int:address_id>/', views.DeleteAddressView.as_view(), name='delete_address'),
    path('new_address', views.NewAddressView.as_view(), name="new_address"),
    path('chkoutaddress', views.ChkoutNewAddressView.as_view(), name="chkoutaddress"),
    path('payment', views.PaymentView.as_view(), name="payment"),
    path('add_card', views.AddCardView.as_view(), name="add_card"),
    path('chkoutcard', views.ChkoutAddCardView.as_view(), name="chkoutcard"),
    path('edit_card/<int:payment_id>/', views.EditCardView.as_view(), name='edit_card'),
    path('delete_card/<int:payment_id>/', views.DeleteCardView.as_view(), name='delete_card'),
    path('checkout', views.CheckoutView.as_view(), name="checkout"),
    path('orderSummary', views.OrderSummaryView.as_view(), name="orderSummary"),
    path('orderSuccess', views.OrderSuccessView.as_view(), name="orderSuccess"),
    path('orderHistory', views.OrderHistoryView.as_view(), name="orderHistory"),
    path('changePwd', views.ChangePwdView.as_view(), name='change_password'),
    path('bookDetails/<slug:book_isbn>', views.BookDetailsView.as_view(), name="bookDetails"),
    path('cart', views.cart, name="cart"),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('update_item/', views.updateItem, name='update_item'),
    path('process_order/', views.process_order, name='process_order'),
    path('reorder/<str:transaction_id>/', views.reorder, name='reorder'),
    path('order/<str:transaction_id>/', views.view_order, name='view_order'),
    path('ReorderSuccess', views.ReOrderSuccessView.as_view(), name="ReorderSuccess"),

]+static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)