from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from .forms import LoginForm
from django.contrib.auth.decorators import login_required
from .models import Product
from .forms import ProductForm

def user_login(request):
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data["username"]
            password = form.cleaned_data["password"]
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)
                return redirect("dashboard")
    else:
        form = LoginForm()
    return render(request, "store/login.html", {"form": form})

@login_required
def add_product(request):
    if request.method == "POST":
        form = ProductForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("dashboard")
    else:
        form = ProductForm()
    return render(request, "store/add_product.html", {"form": form})

def home(request):
    return render(request, "store/home.html")

@login_required
def dashboard(request):
    return render(request, "store/dashboard.html")