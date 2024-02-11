from django.shortcuts import render
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import CustomUser, UserToken
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
import jwt
import datetime
import json

def signup(request):
    try:
        if request.method == 'POST':
            if 'application/json' in request.content_type:
                data = json.loads(request.body)
                username = data.get('fullName')
                email = data.get('email')
                password = data.get('password')
                phoneno = data.get('phoneNumber')
                gender = data.get('gender')
                country = data.get('country')
                state = data.get('state')
                city = data.get('city')
                address = data.get('address')
                organization = data.get('organization')

            else:
                # Assume form data if content type is not JSON
                username = request.POST.get('fullName')
                email = request.POST.get('email')
                password = request.POST.get('password')
                phoneno = request.POST.get('phoneNumber')
                gender = data.get('gender')
                country = data.get('country')
                state = data.get('state')
                city = data.get('city')
                address = data.get('address')
                organization = data.get('organization')

            # Check if required fields are present in the request
            if not username or not email or not password or not phoneno or not gender or not country or not state or not city or not address or not organization:
                return JsonResponse({'success':False,'error': 'Missing required fields'})

            # Check if the username or email already exists
            if CustomUser.objects.filter(email=email).exists():
                return JsonResponse({'success':False,'error': 'Email already exists'})

            # Hash the password
            hashed_password = make_password(password)

            # Create a new user

            user = CustomUser(username=username, email=email, password=hashed_password, phone_number=phoneno,country=country,state=state,city=city,address=address,organization=organization)
            user.save()

            # Generate JWT Token
            #token = jwt.encode({'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)}, 'gOlDenArr0Wh3Ad', algorithm='HS256')

            return JsonResponse({'success':True,'message': 'User created successfully'})
        
        else:
            return JsonResponse({'success':False,'error': 'Invalid request method'})

    except Exception as e:
        # Handle other unexpected exceptions
        return JsonResponse({'success':False,'error': f'An error occurred: {str(e)}'})


def login(request):
    try:
        if request.method == 'POST':
            # Check if the request content type is JSON
            if 'application/json' in request.content_type:
                data = json.loads(request.body)
                email = data.get('email')
                password = data.get('password')
            else:
                # Assume form data if content type is not JSON
                email = request.POST.get('email')
                password = request.POST.get('password')

            # Check for missing required fields
            if not email or not password:
                return JsonResponse({'error': 'Missing required fields'}, status=400)

            # Find the user by email
            user = CustomUser.objects.filter(email=email).first()

            # Check if the user exists and the password is correct
            if user and check_password(password, user.password):
                # Generate JWT Token
                token = jwt.encode({'email': email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)}, 'gOlDenArr0Wh3Ad', algorithm='HS256')
                user_token, created = UserToken.objects.update_or_create(
                    user=user,
                    defaults={'token': token}
                )

                return JsonResponse({'success':True,'token': token})
            else:
                return JsonResponse({'success':False,'error': 'Invalid email or password'})
        else:
            return JsonResponse({'success':False,'error': 'Invalid request method'})

    except Exception as e:
        return JsonResponse({'success':False,'error': f'An error occurred: {str(e)}'})

def information(request):
    try:
        if request.method == 'POST':
            # Check if the request content type is JSON
            if 'application/json' in request.content_type:
                data = json.loads(request.body)
                token = data.get('token')
                gender = data.get('gender')
                country = data.get('country')
                state = data.get('state')
                city = data.get('city')
                address = data.get('address')
                organization = data.get('organization')
            else:
                # Assume form data if content type is not JSON
                token = request.POST.get('token')
                gender = request.POST.get('gender')
                country = request.POST.get('country')
                state = request.POST.get('state')
                city = request.POST.get('city')
                address = request.POST.get('address')
                organization = request.POST.get('organization')

            # Verify the token
            try:
                decoded_token = jwt.decode(token, 'gOlDenArr0Wh3Ad', algorithms=['HS256'])
                email = decoded_token.get('email')
            except jwt.ExpiredSignatureError:
                return JsonResponse({'success': False, 'error': 'Token has expired'})
            except jwt.InvalidTokenError:
                return JsonResponse({'success': False, 'error': 'Invalid token'})

            # Check if the user exists
            user = CustomUser.objects.filter(email=email).first()

            if user:
                # Store information in CustomUser model
                user.gender = gender
                user.country = country
                user.state = state
                user.city = city
                user.address = address
                user.organization = organization
                user.save()

                return JsonResponse({'success': True, 'message': 'Information stored successfully'})
            else:
                return JsonResponse({'success': False, 'error': 'User not found'})

        else:
            return JsonResponse({'success': False, 'error': 'Invalid request method'})

    except Exception as e:
        return JsonResponse({'success': False, 'error': f'An error occurred: {str(e)}'})
