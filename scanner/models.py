from django.db import models
from django.contrib.auth.models import User

class FreeScan(models.Model):
    ip_address = models.GenericIPAddressField()
    target_url = models.URLField() 
    created_at = models.DateTimeField(auto_now_add=True)


class Scan(models.Model):
     STATUS_CHOICES = [
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]
     user = models.ForeignKey(User, on_delete=models.CASCADE)
     target_url = models.URLField()
     status = models.CharField(max_length=20, default="pending")
     scan_type = models.CharField(max_length=10, choices=[('Quick', 'Quick'), ('Deep', 'Deep')], default='Quick')
     progress = models.PositiveIntegerField(default=0) # 0 to 100
     created_at = models.DateTimeField(auto_now_add=True)

     def __str__(self):
        return self.target_url
    

class Vulnerability(models.Model):
    SEVERITY_CHOICES = [
        ("Low", "Low"),
        ("Medium", "Medium"),
        ("High", "High"),
        ("Critical", "Critical"),
    ]

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)

    # ✅ FIXED FIELDS
    description = models.TextField(blank=True, default="No description provided")
    mitigation = models.TextField(blank=True, default="No mitigation provided")

    def __str__(self):
        return f"{self.title} ({self.severity})"
