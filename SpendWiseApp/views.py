from datetime import datetime

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.core.cache import cache
from django.db.models import Sum
from django.db.models.functions import TruncMonth, Lower
from django.shortcuts import render, redirect
from django.utils.html import escape

from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError
from SpendWiseApp.models import Income, Expense

import re

# Create your views here.

MAX_LOGIN_ATTEMPTS = 3
COOLING_OFF_PERIOD = 60  # in seconds


def login_user(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        # Check if the user has exceeded the maximum login attempts
        login_attempts, timestamp = cache.get(username, (0, None))

        if login_attempts >= MAX_LOGIN_ATTEMPTS:
            if timestamp is None or (datetime.now() - timestamp).seconds < COOLING_OFF_PERIOD:
                print("Login attempts exceeded. Cooling-off period in effect.")
                # Display a message indicating that the account is locked
                messages.error(request, 'Account locked. Please try again later.')
                return redirect('login')

            # Cooling-off period has expired, reset login attempts count
            cache.set(username, 1, COOLING_OFF_PERIOD)

        user = authenticate(request, username=username, password=password)

        if user is not None and login_attempts <= MAX_LOGIN_ATTEMPTS:
            print("User is valid, active and authenticated")
            # Reset login attempts on successful login
            cache.delete(username)
            login(request=request, user=user)
            return redirect('home')
        else:
            # Increment login attempts and set a cooling-off period
            cache.set(username, (login_attempts + 1, datetime.now()), COOLING_OFF_PERIOD)
            messages.error(request, 'Username or password is incorrect')

            return redirect('login')

    return render(request, 'login.html')

def validate_password_strength(password):
    # regexps to check for presence of capital, small and special characters
    if not re.search(r'[A-Z]', password):
        raise ValidationError("The password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        raise ValidationError("The password must contain at least one lowercase letter.")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValidationError("The password must contain at least one special character.")





# Sign up user
def signup_user(request):
    # Get all the data from the form and create the user
    context = {}
    if request.method == 'POST':
        full_name = request.POST.get('full_name')
        email = request.POST.get('email')
        username = request.POST.get('username')
        password = request.POST.get('password')
        password_confirm = request.POST.get('confirm_password')

        first_name,last_name = full_name.split(' ',1) if ' ' in full_name else(full_name,'')

        # Check for strong password
        try:
            password_validation.validate_password(
                password,
                user=User,
                password_validators=[
                    password_validation.MinimumLengthValidator(8),
                    password_validation.CommonPasswordValidator(),
                    password_validation.NumericPasswordValidator(),
                    validate_password_strength(password)

                ]
            )
        except ValidationError as e:
            messages.error(request, e)
            context = {'username': username}
            return render(request, 'signup.html', context)

        if password == password_confirm:
            print('Passwords are the same')
            if User.objects.filter(username=username).exists():
                messages.error(request, 'The useraname you are trying to input exists already')

            else:
                print('Username doesnt exist')
                user = User.objects.create_user(username=username, password=password, first_name=first_name, last_name=last_name, email=email);
                user.save()
                return redirect('login')

        else:
            messages.error(request, 'Passwords do not match')
            context = {'username': username}

    return render(request, 'signup.html', context)


def home(request):
    # Get logged in users Full Name
    full_name = request.user.get_full_name()

    income_columns, last_10_income_records = get_last_10_income_records_and_columns()
    expense_columns, last_10_expense_records = get_last_10_expense_records_and_columns()
    monthly_income_labels, monthly_income_data_points = get_monthly_income_and_labels()
    monthly_expense_labels, monthly_expense_data_points = get_monthly_expenses_and_labels()
    category_labels, category_data_points = get_categorized_expenses_and_labels()

    # Pass data to the template
    context = {
        'income_labels': monthly_income_labels,
        'income_data_points': monthly_income_data_points,
        'expense_labels': monthly_expense_labels,
        'expense_data_points': monthly_expense_data_points,
        'category_labels': category_labels,
        'category_data_points': category_data_points,
        'full_name': full_name,
        'last_10_income_records': last_10_income_records,
        'last_10_expense_records': last_10_expense_records,
        'income_columns': income_columns,
        'expense_columns': expense_columns
    }

    # print(context.get('income_labels'))
    # print(context.get('income_data_points'))
    return render(request, 'dashboard.html', context)


def get_last_10_income_records_and_columns():
    # Get the last 10 income records
    last_10_income_records = Income.objects.order_by('-date')[:10]
    # Get the columns of the Income table
    income_columns = [field.name.split('.')[-1] for field in Income._meta.fields]
    return income_columns, last_10_income_records


def get_last_10_expense_records_and_columns():
    # Get the last 10 expense records
    last_10_expense_records = Expense.objects.order_by('-date')[:10]
    # Get the columns of the Expense table
    expense_columns = [field.name.split('.')[-1] for field in Expense._meta.fields]
    return expense_columns, last_10_expense_records


def get_monthly_income_and_labels():
    # Get monthly income
    monthly_income = Income.objects.annotate(month=TruncMonth('date')).values('month').annotate(
        total_income=Sum('amount')).order_by('month')

    # Extract income_labels (months) and data points
    income_labels = [entry['month'].strftime('%b %Y') for entry in monthly_income]
    income_data_points = [str(entry['total_income']) for entry in monthly_income]

    return income_labels, income_data_points


def get_monthly_expenses_and_labels():
    # Get monthly expenses
    monthly_expenses = Expense.objects.annotate(month=TruncMonth('date')).values('month').annotate(
        total_expense=Sum('amount')).order_by('month')

    # Extract income_labels (months) and data points
    expense_labels = [entry['month'].strftime('%b %Y') for entry in monthly_expenses]
    expense_data_points = [str(entry['total_expense']) for entry in monthly_expenses]

    return expense_labels, expense_data_points


def get_categorized_expenses_and_labels():
    # Group expenses by category and calculate the total amount for each category
    categorized_expenses = Expense.objects.annotate(lower_category=Lower('category')).values('lower_category').annotate(
        total_amount=Sum('amount'))

    category_labels = [entry['lower_category'].capitalize() for entry in categorized_expenses]
    category_data_points = [str(entry['total_amount']) for entry in categorized_expenses]

    return category_labels, category_data_points


def log_expense(request):
    if request.method == 'POST':
        amount = request.POST.get('expense_amount').strip()
        category = request.POST.get('expense_category').strip()
        date = request.POST.get('expense_date').strip()
        description = request.POST.get('expense_description').strip()

        # Sanitize user input
        amount = escape(amount)
        category = escape(category)
        date = escape(date)
        description = escape(description)

        # This is vulnerable to SQL injection
        expense = Expense.objects.create(amount=amount, category=category, date=date, description=description)
        expense.save()

        return redirect('home')


def log_income(request):
    if request.method == 'POST':
        amount = request.POST.get('income_amount').strip()
        source = request.POST.get('income_source').strip()
        date = request.POST.get('income_date').strip()
        description = request.POST.get('income_description').strip()

        # Sanitize user input
        amount = escape(amount)
        source = escape(source)
        date = escape(date)
        description = escape(description)

        income = Income.objects.create(amount=amount, source=source, date=date, description=description)
        income.save()

        return redirect('home')
