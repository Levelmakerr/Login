from django.urls import path
from .import views

urlpatterns = [
    path('', views.home, name='home'),
    path('signup', views.signup, name='signup'),
    path('signin', views.signin, name='signin'),
    path('signout', views.signout, name='signout'), 
    path('activate/<str:uid64>/<str:token>/', views.activate, name='activate')
    
    
       
]