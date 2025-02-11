from django.urls import path
from .views import user_login
from .views import user_login, add_product, home, dashboard

urlpatterns = [
    path("", home, name="home"),
    path("login/", user_login, name="login"),
    path("add-product/", add_product, name="add_product"),
    path("dashboard/", dashboard, name="dashboard"),
]
