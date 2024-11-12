# from django.http import HttpResponse
# from django.shortcuts import render, redirect
# from django.contrib.auth.models import User
# from django.contrib.auth import authenticate, login, logout
# from django.contrib import messages
# from Email import settings
# from django.core.mail import send_mail,EmailMessage
# from django.contrib.sites.shortcuts import get_current_site
# from django.template.loader import render_to_string
# from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
# from django.utils.encoding import force_bytes 
# from .tokens import generate_token
# from django.contrib.auth.tokens import PasswordResetTokenGenerator



# def home(request):
#     return render(request, 'login/index.html')

# def signup(request):
#     if request.method == 'POST':
#         username = request.POST['username']
#         fname = request.POST['fname']
#         lname = request.POST['lname']
#         email = request.POST['email']
#         pass1 = request.POST['pass1']
#         pass2 = request.POST['pass2']
        
#         if User.objects.filter(username=username):
#             messages.error(request,"Username already exists")
#             return redirect('signup')
            
#         if User.objects.filter(email=email):
#             messages.error(request,"Email already registered")   
#             return redirect('login/signup') 

        
#         if pass1 != pass2:
#             messages.error(request, "Passwords do not match!")
#             return redirect('login/signup')
        
#         if not username.isalnum():
#             messages.error(request,"Username must be alpha numeric")
#             return redirect('signup')
        
        
        
#         myuser = User.objects.create_user(username=username, email=email, password=pass1)
#         myuser.first_name = fname
#         myuser.last_name = lname
#         myuser.is_active = False
#         myuser.save()
        
#         messages.success(request, "Account created successfully!. \n We have sent you a confirmation email, please confirm your email in order to activate your account.")
        
        
#         if myuser:
#             uid = urlsafe_base64_encode(force_bytes(myuser.pk))
#             token_generator = generate_token()  
#             token = token_generator.make_token(myuser) 

        
#         # Welcome Email
        
#         subject = "Welcome to MY APP - DJANGO LOGIN!"
#         message = "Hello " + myuser.first_name +"!! \n" + "Welcome to My App!! \n Thank You fro visiting our website \n We have also sent you an confirmation email in order to activate your account. \n\n  Thanking  You\n Vishnu "
#         from_email = settings.EMAIL_HOST_USER
#         to_list = [myuser.email]
#         send_mail(subject,message,from_email,to_list, fail_silently = False) 
        
#         # Confirmation Email
        
#         current_site = get_current_site(request)
#         email_subject = "Confirm your email @ Myapp - Django login!!"
#         message2 = render_to_string('email_confirmation.html',{
#             'name': myuser.first_name,
#             'domain':current_site.domain,
#              'uid':urlsafe_base64_encode(force_bytes(myuser.pk)),
#              'token': token
#         })
        
#         email = EmailMessage(
#             email_subject,
#             message2,
#             settings.EMAIL_HOST_USER,
#             [myuser.email],
#         )
#         email.fail_silently = False
#         email.send()
        
#         return redirect('signin')
    
#     return render(request, 'login/signup.html')

# def signin(request):
#     if request.method == 'POST':
#         username = request.POST['username']
#         password = request.POST['pass1']

#         user = authenticate(request, username=username, password=password)

#         if user is not None:
#             login(request, user)
#             fname = user.first_name
#             return render(request, 'login/index.html', {'fname': fname})
#         else:
#             messages.error(request, "User not found or incorrect password")
#             return redirect('signin')

#     return render(request, 'login/signin.html')

# def signout(request):
#     logout(request)
#     messages.success(request, "Logged out successfully")
#     return redirect('home')


# # def activate(request, uid64, token):
# #     try:
# #         uid = urlsafe_base64_decode(uid64).decode()
# #         mysure = User.objects.get(pk=uid)
# #     except(TypeError, ValueError, OverflowError, User.DoesNotExist):
# #         mysure = None
        
# #     if mysure is not None and generate_token.check_token(mysure, token):
# #         mysure.is_active = True
# #         mysure.save()
# #         login(request, mysure)
# #         return redirect('home')
    
# #     else:
#         # return render(request,'activation_failed.html')    
            
# def activate(request, uid64, token):
#     try:
#         # Decode the uid to get the user ID
#         uid = urlsafe_base64_decode(uid64).decode()
#         mysure = User.objects.get(pk=uid)
#     except (TypeError, ValueError, OverflowError, User.DoesNotExist):
#         mysure = None
    
#     # If the user exists and the token is valid, activate the user
#     if mysure is not None and generate_token.check_token(mysure, token):
#         mysure.is_active = True
#         mysure.save()
#         login(request, mysure)
#         return redirect('home')
#     else:
#         # If user doesn't exist or the token is invalid
#         return render(request, 'activation_failed.html')  

from django.http import HttpResponse
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
from django.utils.encoding import force_str 
from .tokens import generate_token
from django.contrib.auth.tokens import PasswordResetTokenGenerator,default_token_generator


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

        # Check if username already exists
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists")
            return redirect('signup')

        # Check if email is already registered
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already registered")
            return redirect('signup')

        # Check if passwords match
        if pass1 != pass2:
            messages.error(request, "Passwords do not match!")
            return redirect('signup')

        # Check if username is alphanumeric
        if not username.isalnum():
            messages.error(request, "Username must be alphanumeric")
            return redirect('signup')

        # Create the user but keep the account inactive initially
        myuser = User.objects.create_user(username=username, email=email, password=pass1)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active = False  # Account will be inactive until confirmed
        myuser.save()

        # Generate UID and Token
        uid = urlsafe_base64_encode(force_bytes(myuser.pk))
        token = generate_token.make_token(myuser)  # Make sure this is working now

        # Log the generated activation URL (for debugging)
        current_site = get_current_site(request)
        activation_url = f"http://{current_site.domain}/activate/{uid}/{token}/"
        print(f"Activation URL: {activation_url}")  # Log the URL for verification

        # Send confirmation email
        email_subject = "Confirm your email at MyApp"
        message = render_to_string('email_confirmation.html', {
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid': uid,
            'token': token
        })

        email = EmailMessage(
            email_subject,
            message,
            settings.EMAIL_HOST_USER,
            [myuser.email],
        )
        email.fail_silently = False
        email.send()

        messages.success(request, "Account created successfully! Please confirm your email.")
        return redirect('signin')  # Redirect to sign in page after successful registration

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

# In your 'activate' view
def activate(request, uid64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uid64))
        user = User.objects.get(pk=uid)
        print(f"Decoded UID: {uid}")  # Log the UID
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    
    if user is not None:
        print(f"User found: {user.username}")  # Log the user details
        if generate_token.check_token(user, token):
            print(f"Token is valid")  # Token validation passed
            user.is_active = True
            user.save()
            messages.success(request, "Your account has been activated! You can now log in.")
            return redirect('signin')
        else:
            print(f"Token is invalid or expired")  # Log invalid or expired token
    else:
        print("User not found")  # Log if user does not exist
    
    messages.error(request, "The activation link is invalid or has expired.")
    return redirect('home')


