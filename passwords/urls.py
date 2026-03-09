from django.urls import path
from . import views
urlpatterns = [
    path('', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile_view, name='profile'),            
    path("login/", views.login_view, name="login"),              
    path("verify-otp/", views.verify_otp, name="verify_otp"),
      # Vaults
    path('vaults/', views.vault_list, name='vault_list'),
    path('vaults/create/', views.vault_create, name='vault_create'),
    path('vaults/<int:pk>/update/', views.vault_update, name='vault_update'),
    path('vaults/<str:slug>/change-password/', views.vault_change_password, name='vault_change_password'),
    path('vaults/<str:slug>/delete/', views.vault_delete, name='vault_delete'),
    path('vaults/<str:slug>/credentials/', views.vault_credentials, name='vault_credentials'),
    path('vaults/<str:slug>/access/', views.access_vault_api, name='vault_access_api'),
    path('vaults/<slug:vault_slug>/verify-password/', views.verify_vault_password, name='verify_vault_password'),
     

    # Catégories
    path('categories/', views.category_list, name='category_list'),
    path('categories/create/', views.category_create, name='category_create'),
    path('categories/<int:pk>/edit/', views.category_update, name='category_update'),
    path('categories/<int:pk>/delete/', views.category_delete, name='category_delete'),

    # Identifiants / Credentials
    #######
    path('credentials/', views.credential_list, name='credential_list'),
    path('credentials/create/', views.credential_create, name='credential_create'),
    path('credentials/<str:slug>/update/', views.credential_update, name='credential_update'),
    path('credentials/<slug:slug>/password/', views.get_credential_password_api, name='get_credential_password_api'),
    path('credentials/<slug:slug>/delete/', views.credential_delete, name='credential_delete'),

    # Historique / Audit
    path('audit/', views.audit_log, name='audit_log'),
    # exportation
    path('vaults/<slug:vault_slug>/export-pdf/', views.export_vault_pdf, name='export_vault_pdf')
]