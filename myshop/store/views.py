from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from .forms import LoginForm
from django.contrib.auth.decorators import login_required
from .models import Product
from .forms import ProductForm
import requests
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

def user_login(request):
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data["username"]
            password = form.cleaned_data["password"]
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)
                
                # Log successful login
                logger.debug(f"User '{username}' authenticated successfully.")
                
                # Prepare the new auth URL for Angel Broking login flow
                state = "statevariable"  # Replace this with a dynamic value if needed
                auth_url = f"https://smartapi.angelone.in/publisher-login?api_key={settings.ANGEL_API_KEY}&state={state}"
                
                # Redirect to Angel Broking login screen
                return redirect(auth_url)
            else:
                logger.error("Invalid credentials, user authentication failed.")
                return render(request, "store/login.html", {"form": form, "error": "Invalid credentials"})
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
    access_token = request.session.get("angel_access_token")
    
    if not access_token:
        return redirect("home")  # If no access token is available, redirect to home
    
    # Fetch user data from Angel Broking API
    user_data_url = "https://smartapi.angelbroking.com/rest/secure/angelbroking/user/v1/getProfile"
    headers = {
        "Authorization": f"Bearer {access_token}",
    }
    
    response = requests.get(user_data_url, headers=headers)
    
    if response.status_code == 200:
        user_data = response.json()  # Parse the JSON response
    else:
        user_data = None  # If the request fails, no user data
    
    return render(request, "store/dashboard.html", {"user_data": user_data})

def angel_callback(request):
    """Handles the OAuth callback and exchanges the authorization code for an access token."""
    # Get the authorization code from the request URL
    code = request.GET.get("code")
    if not code:
        return redirect("home")  # If no code is returned, go back to the home page

    # Make a POST request to exchange the code for an access token
    token_url = "https://smartapi.angelbroking.com/oauth/token"
    data = {
        "grant_type": "authorization_code",
        "client_id": settings.ANGEL_API_KEY,
        "client_secret": settings.ANGEL_API_SECRET,
        "redirect_uri": settings.ANGEL_REDIRECT_URI,
        "code": code,
    }
    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    
    # Send the request to get the access token
    response = requests.post(token_url, data=data, headers=headers)
    if response.status_code == 200:
        token_data = response.json()
        access_token = token_data.get("access_token")
        request.session["angel_access_token"] = access_token  # Store in session
        return redirect("dashboard")  # Redirect to dashboard after successful login
    else:
        return redirect("home")  # If there's an error, go back to the home page