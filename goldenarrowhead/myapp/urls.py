from django.urls import path
from . import views
from . import auth

urlpatterns = [
    # Other URL patterns...
    path('signup', auth.signup, name='signup'),
    path('login', auth.login, name='login'),
    path('information', auth.information, name='information'),
    path('uploadprofilepicture', views.uploadprofilepicture, name='uploadprofilepicture'),
    path('getprofilepic', views.getprofilepic, name='getprofilepic'),

]

