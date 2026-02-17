from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _
from .models import (
    CustomUser,
    Vault,
    Category,
    Credential,
    PasswordHistory,
    Tag,
    CredentialTag,
    AuditLog,
)

# ---------------------------
# Custom User Admin
# ---------------------------
@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ("email", "username", "is_staff", "is_superuser", "is_active")
    list_filter = ("is_staff", "is_superuser", "is_active")
    search_fields = ("email", "username")
    ordering = ("email",)
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (_("Personal info"), {"fields": ("username", "first_name", "last_name")}),
        (_("Permissions"), {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        (_("Important dates"), {"fields": ("last_login", "date_joined")}),
    )
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("email", "password1", "password2", "is_staff", "is_superuser", "is_active"),
        }),
    )

# ---------------------------
# Vault Admin
# ---------------------------
@admin.register(Vault)
class VaultAdmin(admin.ModelAdmin):
    list_display = ("name", "user", "created_at", "updated_at")
    search_fields = ("name", "user__email")
    list_filter = ("user",)

# ---------------------------
# Category Admin
# ---------------------------
@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ("name", "vault", "parent", "order", "created_at", "updated_at")
    search_fields = ("name", "vault__name")
    list_filter = ("vault",)

# ---------------------------
# Credential Admin
# ---------------------------
@admin.register(Credential)
class CredentialAdmin(admin.ModelAdmin):
    list_display = ("title", "vault", "category", "username", "updated_at")
    search_fields = ("title", "username", "vault__name", "category__name")
    list_filter = ("vault", "category")

# ---------------------------
# Password History Admin
# ---------------------------
@admin.register(PasswordHistory)
class PasswordHistoryAdmin(admin.ModelAdmin):
    list_display = ("credential", "changed_at")
    search_fields = ("credential__title",)
    list_filter = ("credential__vault",)

# ---------------------------
# Tags Admin
# ---------------------------
@admin.register(Tag)
class TagAdmin(admin.ModelAdmin):
    list_display = ("name",)
    search_fields = ("name",)

@admin.register(CredentialTag)
class CredentialTagAdmin(admin.ModelAdmin):
    list_display = ("credential", "tag")
    search_fields = ("credential__title", "tag__name")

# ---------------------------
# Audit Log Admin
# ---------------------------
@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("user", "vault", "action", "target_type", "target_id", "ip", "created_at")
    search_fields = ("user__email", "vault__name", "target_type", "target_id", "ip")
    list_filter = ("action", "vault")
