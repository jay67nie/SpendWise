from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.db.models import Sum
from django.db.models.functions import TruncMonth
from django.shortcuts import render, redirect

from SpendWiseApp.models import Income, Expense


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
        password_confirm = request.POST.get('confirm_password')


        if password == password_confirm:
            print('Passwords are the same')
            if User.objects.filter(username=username).exists():
                messages.error(request, 'The useraname you are trying to input exists already')

            else:
                print('Username doesnt exist')
                user = User.objects.create_user(username=username, password=password)
                user.save()
                return redirect('login')

        else:
            messages.error(request, 'Passwords do not match')
            context = {'username': username}

    return render(request, 'signup.html', context)


def home(request):
    monthly_income = Income.objects.annotate(month=TruncMonth('date')).values('month').annotate(
        total_income=Sum('amount')).order_by('month')

    # Extract income_labels (months) and data points
    income_labels = [entry['month'].strftime('%b %Y') for entry in monthly_income]
    income_data_points = [str(entry['total_income']) for entry in monthly_income]

    monthly_expenses = Expense.objects.annotate(month=TruncMonth('date')).values('month').annotate(
        total_expense=Sum('amount')).order_by('month')

    # Extract income_labels (months) and data points
    expense_labels = [entry['month'].strftime('%b %Y') for entry in monthly_expenses]
    expense_data_points = [str(entry['total_expense']) for entry in monthly_expenses]

    # Group expenses by category and calculate the total amount for each category
    categorized_expenses = Expense.objects.values('category').annotate(total_amount=Sum('amount'))

    category_labels = [entry['category'] for entry in categorized_expenses]
    category_data_points = [str(entry['total_amount']) for entry in categorized_expenses]


    print(category_data_points)


    # Pass data to the template
    context = {
        'income_labels': income_labels,
        'income_data_points': income_data_points,
        'expense_labels': expense_labels,
        'expense_data_points': expense_data_points,
        'category_labels': category_labels,
        'category_data_points': category_data_points,
    }

    # print(context.get('income_labels'))
    # print(context.get('income_data_points'))
    return render(request, 'dashboard.html', context)
