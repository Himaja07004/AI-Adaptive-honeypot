from django.urls import path
from . import views

urlpatterns = [
    path('export/excel/', views.export_logs_excel, name='export_excel'),
    path('export/txt/', views.export_logs_txt, name='export_txt'),
    path('download-secrets/', views.honeypot_trap, name='canary_trap'), # Route for the post-auth canary file
    path('login.php', views.honeypot_trap, name='login_trap'),
    path('', views.honeypot_trap, name='honeypot_trap'),
]
