from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class Expense(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    category = models.CharField(max_length=50)
    date = models.DateTimeField()
    description = models.TextField()

    # def __str__(self):
    #     # Return it as a json string
    #     return f"{self.amount} - {self.category} - {self.date}"


class Income(models.Model):
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    source = models.CharField(max_length=50)
    date = models.DateTimeField()
    description = models.TextField()

    # def __str__(self):
    #     return f"{self.amount} - {self.source} - {self.date}"
