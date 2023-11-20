from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.shortcuts import render, redirect


# Create your views here.
def login_user(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('home')
        else:
            messages.error(request, 'Username or password is incorrect')

    return render(request, 'login.html')


# Sign up user
def signup_user(request):
    # Get all the data from the form and create the user
    context = {}
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        password_confirm = request.POST.get('password_confirm')

        if password == password_confirm:
            user = User.objects.create_user(username=username, password=password)
            user.save()
            return redirect('login')
        else:
            messages.error(request, 'Passwords do not match')
            context = {'username': username}

    return render(request, 'signup.html', context)


def home(request):
    return render(request, 'dashboard.html')
