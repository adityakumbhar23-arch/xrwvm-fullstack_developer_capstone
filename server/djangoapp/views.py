# # Uncomment the required imports before adding the code

# # from django.shortcuts import render
# # from django.http import HttpResponseRedirect, HttpResponse
# # from django.contrib.auth.models import User
# # from django.shortcuts import get_object_or_404, render, redirect
# # from django.contrib.auth import logout
# # from django.contrib import messages
# # from datetime import datetime

# from django.http import JsonResponse
# from django.contrib.auth import login, authenticate
# import logging
# import json
# from django.views.decorators.csrf import csrf_exempt
# # from .populate import initiate


# # Get an instance of a logger
# logger = logging.getLogger(__name__)


# # Create your views here.

# # Create a `login_request` view to handle sign in request
# @csrf_exempt
# def login_user(request):
#     # Get username and password from request.POST dictionary
#     data = json.loads(request.body)
#     username = data['userName']
#     password = data['password']
#     # Try to check if provide credential can be authenticated
#     user = authenticate(username=username, password=password)
#     data = {"userName": username}
#     if user is not None:
#         # If user is valid, call login method to login current user
#         login(request, user)
#         data = {"userName": username, "status": "Authenticated"}
#     return JsonResponse(data)

# # Create a `logout_request` view to handle sign out request
# # def logout_request(request):
# # ...

# # Create a `registration` view to handle sign up request
# # @csrf_exempt
# # def registration(request):
# # ...

# # # Update the `get_dealerships` view to render the index page with
# # a list of dealerships
# # def get_dealerships(request):
# # ...

# # Create a `get_dealer_reviews` view to render the reviews of a dealer
# # def get_dealer_reviews(request,dealer_id):
# # ...

# # Create a `get_dealer_details` view to render the dealer details
# # def get_dealer_details(request, dealer_id):
# # ...

# # Create a `add_review` view to submit a review
# # def add_review(request):
# # ...


from django.http import JsonResponse
from django.contrib.auth import login, authenticate, logout 
import json
from django.views.decorators.csrf import csrf_exempt
import logging
from django.contrib.auth.models import User

logger = logging.getLogger(__name__)

@csrf_exempt  # remove when you implement proper CSRF handling
def login_user(request):
    """
    Accepts POST with JSON or form data:
      JSON:    {"userName": "...", "password": "..."}
      Form:    userName=...&password=...
    Returns:
      200 -> {"userName": "...", "status": "Authenticated"}
      400 -> {"error": "message"}
      401 -> {"error": "Invalid credentials"}
    """
    if request.method != "POST":
        return JsonResponse({"error": "Only POST allowed"}, status=405)

    # parse input
    username = None
    password = None

    # prefer JSON if content-type indicates it
    content_type = request.META.get("CONTENT_TYPE", "")
    try:
        if "application/json" in content_type:
            payload = json.loads(request.body.decode("utf-8") or "{}")
            username = payload.get("userName")
            password = payload.get("password")
        else:
            # support form-encoded posting (from html forms / axios default)
            username = request.POST.get("userName")
            password = request.POST.get("password")
    except json.JSONDecodeError:
        logger.exception("Invalid JSON in login request.")
        return JsonResponse({"error": "Invalid JSON body"}, status=400)
    except Exception:
        logger.exception("Unexpected error parsing login request.")
        return JsonResponse({"error": "Invalid request"}, status=400)

    if not username or not password:
        return JsonResponse({"error": "userName and password are required"}, status=400)

    user = authenticate(request, username=username, password=password)
    if user is None:
        logger.info("Authentication failed for username=%s", username)
        return JsonResponse({"error": "Invalid credentials"}, status=401)

    login(request, user)  # creates session cookie
    logger.info("User %s authenticated successfully", username)
    return JsonResponse({"userName": username, "status": "Authenticated"})

@csrf_exempt 
def logout_user(request):
    """
    Handles user logout request.
    Terminates session and returns JSON with empty username.
    """
    if request.method == "POST":
        logout(request)  # Terminate user session
        data = {"userName": ""}  # Return empty username
        logger.info("User logged out successfully.")
        return JsonResponse(data)
    else:
        return JsonResponse({"error": "Only POST allowed"}, status=405)

@csrf_exempt  # disable CSRF for easy testing (remove in production)
def registration(request):
    """
    Handles user registration.
    Creates a new user, logs them in, and returns JSON with username and status.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Only POST allowed"}, status=405)

    try:
        # Load JSON data from the request body
        data = json.loads(request.body)
        username = data.get('userName')
        password = data.get('password')
        first_name = data.get('firstName')
        last_name = data.get('lastName')
        email = data.get('email')

        # Validate required fields
        if not username or not password:
            return JsonResponse({"error": "Missing username or password"}, status=400)

        # Check if username already exists
        if User.objects.filter(username=username).exists():
            return JsonResponse({"userName": username, "error": "Already Registered"}, status=400)

        # Create new user
        user = User.objects.create_user(
            username=username,
            first_name=first_name,
            last_name=last_name,
            password=password,
            email=email
        )

        # Log in new user immediately
        login(request, user)
        data = {"userName": username, "status": "Authenticated"}
        logger.info(f"New user registered: {username}")
        return JsonResponse(data)

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON data"}, status=400)
    except Exception as e:
        logger.exception("Error in registration")
        return JsonResponse({"error": str(e)}, status=500)


