from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from Email import settings
from django.core.mail import send_mail,EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import force_bytes 
from .tokens import generate_token



def home(request):
    return render(request, 'login/index.html')

def signup(request):
    if request.method == 'POST':
        username = request.POST['username']
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']
        
        if User.objects.filter(username=username):
            messages.error(request,"Username already exists")
            return redirect('signup')
            
        if User.objects.filter(email=email):
            messages.error(request,"Email already registered")   
            return redirect('login/signup') 

        
        if pass1 != pass2:
            messages.error(request, "Passwords do not match!")
            return redirect('login/signup')
        
        if not username.isalnum():
            messages.error(request,"Username must be alpha numeric")
            return redirect('signup')
        
        
        
        myuser = User.objects.create_user(username=username, email=email, password=pass1)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active = True
        myuser.save()
        
        messages.success(request, "Account created successfully!. \n We have sent you a confirmation email, please confirm your email in order to activate your account.")
        
        
        if myuser:
            uid = urlsafe_base64_encode(force_bytes(myuser.pk))
            token_generator = generate_token()  
            token = token_generator.make_token(myuser) 

        
        # Welcome Email
        
        subject = "Welcome to MY APP - DJANGO LOGIN!"
        message = "Hello " + myuser.first_name +"!! \n" + "Welcome to My App!! \n Thank You fro visiting our website \n We have also sent you an confirmation email in order to activate your account. \n\n  Thanking  You\n Vishnu "
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject,message,from_email,to_list, fail_silently = False) 
        
        # Confirmation Email
        
        current_site = get_current_site(request)
        email_subject = "Confirm your email @ Myapp - Django login!!"
        message2 = render_to_string('email_confirmation.html',{
            'name': myuser.first_name,
            'domain':current_site.domain,
             'uid':urlsafe_base64_encode(force_bytes(myuser.pk)),
             'token': token
        })
        
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email],
        )
        email.fail_silently = False
        email.send()
        
        return redirect('signin')
    
    return render(request, 'login/signup.html')

def signin(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['pass1']

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            fname = user.first_name
            return render(request, 'login/index.html', {'fname': fname})
        else:
            messages.error(request, "User not found or incorrect password")
            return redirect('signin')

    return render(request, 'login/signin.html')

def signout(request):
    logout(request)
    messages.success(request, "Logged out successfully")
    return redirect('home')


def activate(request, uid64, token):
    try:
        uid = urlsafe_base64_decode(uid64)
        mysure = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        mysure = None
        
    if mysure is not None and generate_token.check_token(mysure, token):
        mysure.is_active = True
        mysure.save()
        login(request, mysure)
        return redirect('home')
    
    else:
        return render(request,'activation_failed.html')    
            
        
