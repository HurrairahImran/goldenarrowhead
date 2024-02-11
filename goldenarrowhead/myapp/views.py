from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import CustomUser, UserToken
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
import jwt
import datetime
import json
import cloudinary
import cloudinary.uploader
import cloudinary.api


@csrf_exempt
def uploadprofilepicture(request):
    try:
        if request.method == 'POST':
            # Check if the request content type is JSON
            if 'application/json' in request.content_type:
                data = json.loads(request.body)
                token = data.get('token')
            else:
                token = request.POST.get('token')

            if not token:
                return JsonResponse({'success': False, 'error': 'Token missing'}, status=400)

            # Decode the token to get the user's email
            try:
                decoded_token = jwt.decode(token, 'gOlDenArr0Wh3Ad', algorithms=['HS256'])
                email = decoded_token.get('email')
            except jwt.ExpiredSignatureError:
                return JsonResponse({'success': False, 'error': 'Token has expired'}, status=401)
            except jwt.DecodeError:
                return JsonResponse({'success': False, 'error': 'Invalid token'}, status=401)

            # Find the user by email
            user = CustomUser.objects.filter(email=email).first()

            if not user:
                return JsonResponse({'success': False, 'error': 'User not found'}, status=404)

            # Check if a file is included in the request
            if 'file' not in request.FILES:
                return JsonResponse({'success': False, 'error': 'No file included in the request'}, status=400)

            uploaded_file = request.FILES['file']

            # Upload the file to Cloudinary
            cloudinary_response = cloudinary.uploader.upload(uploaded_file)

            # Get the Cloudinary URL for the uploaded image
            image_url = cloudinary_response.get('secure_url')

            # Create or update the user's profile picture in UserProfile
            user.profile_picture_url=image_url
            user.save()
            

            return JsonResponse({'success': True, 'message': 'Profile picture uploaded successfully', 'image_url': image_url})

        else:
            return JsonResponse({'success': False, 'error': 'Invalid request method'})

    except Exception as e:
        return JsonResponse({'success': False, 'error': f'An error occurred: {str(e)}'})


@csrf_exempt
def getprofilepic(request):
    try:
        if request.method == 'POST':
            # Check if the request content type is JSON
            if 'application/json' in request.content_type:
                data = json.loads(request.body)
                token = data.get('token')
            else:
                token = request.POST.get('token')

            if not token:
                return JsonResponse({'success': False, 'error': 'Token missing'})

            # Decode the token to get the user's email
            try:
                decoded_token = jwt.decode(token, 'gOlDenArr0Wh3Ad', algorithms=['HS256'])
                email = decoded_token.get('email')
            except jwt.ExpiredSignatureError:
                return JsonResponse({'success': False, 'error': 'Token has expired'})
            except jwt.DecodeError:
                return JsonResponse({'success': False, 'error': 'Invalid token'})

            # Find the user by email
            user = CustomUser.objects.filter(email=email).first()

            if not user:
                return JsonResponse({'success': False, 'error': 'User not found'})

            return JsonResponse({'success': True, 'email': user.email, 'profile_picture_url':user.profile_picture_url})

        else:
            return JsonResponse({'success': False, 'error': 'Invalid request method'})

    except Exception as e:
        return JsonResponse({'success': False, 'error': f'An error occurred: {str(e)}'})

