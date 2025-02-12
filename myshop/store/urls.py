from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("login/", views.user_login, name="login"),
    path("logout/", views.user_logout, name="logout"),
    path("add-product/", views.add_product, name="add_product"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path('callback/', views.angel_one_callback, name='angel-callback'),
    path('profile/', views.get_angel_profile, name='get-angel-profile'),
]
