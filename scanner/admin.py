from django.contrib import admin
from .models import Scan, Vulnerability

admin.site.register(Scan)
admin.site.register(Vulnerability)
