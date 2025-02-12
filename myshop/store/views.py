import http.client
import json
import logging
import requests
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.conf import settings
from .forms import LoginForm, ProductForm
from .models import Product


logger = logging.getLogger(__name__)

ANGEL_ONE_LOGIN_URL = "https://apiconnect.angelone.in/rest/auth/angelbroking/user/v1/loginByPassword"
ANGEL_ONE_PROFILE_URL = "https://apiconnect.angelone.in/rest/secure/angelbroking/user/v1/getProfile"
ANGEL_TOKEN_URL = "/rest/auth/angelbroking/jwt/v1/generateTokens"

def angel_one_login(request):
    """Login to Angel One and obtain auth and refresh tokens."""
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        payload = json.dumps({
            "clientCode": username,
            "password": password,
            "totp": "",  # Include TOTP if required
        })

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-UserType": "USER",
            "X-SourceID": "WEB",
            "X-ClientLocalIP": "CLIENT_LOCAL_IP",
            "X-ClientPublicIP": "CLIENT_PUBLIC_IP",
            "X-MACAddress": "MAC_ADDRESS",
            "X-PrivateKey": settings.ANGEL_API_KEY,
        }

        response = requests.post(ANGEL_ONE_LOGIN_URL, data=payload, headers=headers)
        data = response.json()

        if response.status_code == 200 and "data" in data:
            request.session["angel_auth_token"] = data["data"]["jwtToken"]
            request.session["angel_refresh_token"] = data["data"]["refreshToken"]
            logger.debug("Angel One login successful, tokens stored in session.")
            return redirect("dashboard")
        else:
            logger.error("Angel One login failed.")
            return render(request, "error.html", {"message": "Login failed. Check your credentials."})

    return render(request, "store/login.html")


def generate_token(request):
    """Generate JWT token using refresh token."""
    refresh_token = request.session.get("angel_refresh_token")
    
    if not refresh_token:
        logger.error("Refresh token missing. Redirecting to login.")
        return redirect("login")

    conn = http.client.HTTPSConnection("apiconnect.angelone.in")
    payload = json.dumps({"refreshToken": refresh_token})

    headers = {
        "Authorization": f"Bearer {request.session.get('angel_auth_token')}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "X-ClientLocalIP": "CLIENT_LOCAL_IP",
        "X-ClientPublicIP": "CLIENT_PUBLIC_IP",
        "X-MACAddress": "MAC_ADDRESS",
        "X-PrivateKey": settings.ANGEL_API_KEY,
    }

    conn.request("POST", ANGEL_TOKEN_URL, payload, headers)
    res = conn.getresponse()
    data = json.loads(res.read().decode("utf-8"))

    if "data" in data and "jwtToken" in data["data"]:
        request.session["auth_token"] = data["data"]["jwtToken"]
        logger.debug("JWT Token successfully updated in session.")
        return redirect("dashboard")
    else:
        logger.error("Token generation failed.")
        return render(request, "error.html", {"message": "Token generation failed."})


def user_login(request):
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data["username"]
            password = form.cleaned_data["password"]
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)
                logger.debug(f"User '{username}' authenticated successfully.")
                callback_url = request.build_absolute_uri('/callback/')  # Adjust path as needed
                auth_url = (
                    f"https://smartapi.angelone.in/publisher-login"
                    f"?api_key={settings.ANGEL_API_KEY}"
                    f"&state=statevariable"
                    f"&redirect_uri={callback_url}"
                )
                logger.debug(f"Redirecting to Angel One login page: {auth_url}")
                return redirect(auth_url)
            else:
                logger.error("Invalid credentials, user authentication failed.")
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
    # Check if this is a callback from Angel One with tokens
    auth_token = request.GET.get('auth_token')
    refresh_token = request.GET.get('refresh_token')
    
    if auth_token and refresh_token:
        # Store tokens in session
        request.session["angel_auth_token"] = auth_token
        request.session["angel_refresh_token"] = refresh_token
        logger.debug("Received tokens from Angel One, redirecting to profile")
        return redirect('get-angel-profile')
    
    return render(request, "store/home.html")


def angel_one_callback(request):
    """Handles the login callback from Angel One."""
    print("Angel One Callback received:", request.GET)  # Debug print
    
    # Check if there's an error in the callback
    if 'error' in request.GET:
        logger.error(f"Angel One returned error: {request.GET['error']}")
        return redirect('login')
    
    auth_code = request.GET.get('code')
    if not auth_code:
        logger.error("Authentication failed. Missing authorization code.")
        return redirect('login')
    
    try:
        # Exchange the authorization code for tokens
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-UserType": "USER",
            "X-SourceID": "WEB",
            "X-ClientLocalIP": "CLIENT_LOCAL_IP",
            "X-ClientPublicIP": "CLIENT_PUBLIC_IP",
            "X-MACAddress": "MAC_ADDRESS",
            "X-PrivateKey": settings.ANGEL_API_KEY,
        }
        
        payload = json.dumps({
            "code": auth_code,
            "client_id": settings.ANGEL_API_KEY,
            "redirect_uri": settings.ANGEL_REDIRECT_URI
        })
        
        # Get tokens using the authorization code
        response = requests.post(ANGEL_ONE_LOGIN_URL, headers=headers, data=payload)
        data = response.json()
        
        if response.status_code != 200 or "data" not in data:
            logger.error(f"Failed to exchange auth code for tokens: {data}")
            return redirect('login')
        
        # Save tokens in session
        request.session["angel_auth_token"] = data["data"].get("jwtToken")
        request.session["angel_refresh_token"] = data["data"].get("refreshToken")
        
        # Add debug print
        print("Redirecting to get-angel-profile")
        return redirect('get-angel-profile')
        
    except Exception as e:
        logger.error(f"Exception in angel_one_callback: {str(e)}")
        return redirect('login')


def get_angel_profile(request):
    """Fetch user profile from Angel One API."""
    auth_token = request.session.get("angel_auth_token")
    if not auth_token:
        logger.error("No auth token found. Redirecting to login page.")
        return redirect("login")
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Accept": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "X-ClientLocalIP": "CLIENT_LOCAL_IP",
        "X-ClientPublicIP": "CLIENT_PUBLIC_IP",
        "X-MACAddress": "MAC_ADDRESS",
        "X-PrivateKey": settings.ANGEL_API_KEY
    }
    
    try:
        profile_url = "https://apiconnect.angelbroking.com/rest/secure/angelbroking/user/v1/getProfile"
        response = requests.get(profile_url, headers=headers)
        print("Profile API Response:", response.text)  # Debug print
        
        if response.status_code == 200:
            profile_data = response.json()
            if 'data' in profile_data:
                user_data = profile_data['data']
                # Convert string representations of lists to actual lists
                try:
                    exchanges = eval(user_data.get('exchanges', '[]'))
                    products = eval(user_data.get('products', '[]'))
                except:
                    exchanges = []
                    products = []

                user_profile = {
                    'client_code': user_data.get('clientcode', ''),
                    'name': user_data.get('name', ''),
                    'email': user_data.get('email', ''),  # Exact field name from API
                    'phone_number': user_data.get('mobileno', ''),  # Exact field name from API
                    'exchanges': exchanges,
                    'products': products,
                    'last_login': user_data.get('lastlogintime', ''),
                    'broker_id': user_data.get('brokerid', '')
                }
                
                print("Processed user profile:", user_profile)  # Debug print
                
                request.session['user_profile'] = user_profile
                return redirect('dashboard')
            else:
                logger.error(f"Unexpected profile data format: {profile_data}")
        else:
            logger.error(f"Failed to fetch profile. Status: {response.status_code}, Response: {response.text}")
            
        request.session['profile_error'] = 'Failed to fetch profile data. Please try logging in again.'
        return redirect('dashboard')
        
    except Exception as e:
        logger.error(f"Exception while fetching profile: {str(e)}")
        request.session['profile_error'] = 'An error occurred while fetching your profile.'
        return redirect('dashboard')



@login_required
def dashboard(request):
    """Render the dashboard with user profile."""
    user_profile = request.session.get("user_profile", {})
    if not user_profile:
        logger.error("User profile not found. Redirecting to fetch profile.")
        return redirect("fetch-profile")
    return render(request, "store/dashboard.html", {"user_profile": user_profile})


def user_logout(request):
    """Handle both Django and Angel One logout."""
    try:
        # Angel One Logout
        auth_token = request.session.get('angel_auth_token')
        if auth_token:
            headers = {
                'Authorization': f'Bearer {auth_token}',
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-UserType': 'USER',
                'X-SourceID': 'WEB',
                'X-ClientLocalIP': 'CLIENT_LOCAL_IP',
                'X-ClientPublicIP': 'CLIENT_PUBLIC_IP',
                'X-MACAddress': 'MAC_ADDRESS',
                'X-PrivateKey': settings.ANGEL_API_KEY
            }

            # Get client code from session
            user_profile = request.session.get('user_profile', {})
            client_code = user_profile.get('client_code', '')

            payload = json.dumps({
                "clientcode": client_code
            })

            conn = http.client.HTTPSConnection("apiconnect.angelone.in")
            conn.request(
                "POST",
                "/rest/secure/angelbroking/user/v1/logout",
                payload,
                headers
            )
            
            response = conn.getresponse()
            data = response.read()
            logger.info(f"Angel One logout response: {data.decode('utf-8')}")

            # Clear Angel One related session data
            request.session.pop('angel_auth_token', None)
            request.session.pop('angel_refresh_token', None)
            request.session.pop('user_profile', None)
    
    except Exception as e:
        logger.error(f"Error during Angel One logout: {str(e)}")
    
    finally:
        # Django logout
        logout(request)
        return redirect('login')


