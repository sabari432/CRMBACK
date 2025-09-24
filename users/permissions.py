from rest_framework import permissions
from . models import UserTypeChoices

# Allowed for Admin credential creation only
class AllowedAdminCreation(permissions.BasePermission):
    message = "You Must have Super User Permissions for This"
    # authenticated user only
    def has_permission(self, request, view):
        if request.user.is_authenticated or request.user.user_type == UserTypeChoices.ADMIN:
            return request.user.is_superuser or request.user.user_type == UserTypeChoices.ADMIN

    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser or request.user.user_type == UserTypeChoices.ADMIN:
            return True
        return False

class AllowedStaffCreation(permissions.BasePermission):
    message = "You Must have At least Admin User Permissions for This"
    # Check for general permission
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            # Allow only SuperAdmin and Admin users
            return request.user.is_superuser or request.user.user_type == UserTypeChoices.ADMIN
        return False

    # Check for object-level permissions (if applicable)
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser or request.user.user_type == UserTypeChoices.ADMIN:
            return True
        return False

class StaffUserAccess(permissions.BasePermission):
    # Check for general permission
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            # Allow only SuperAdmin and Admin users
            return request.user.is_superuser or request.user.user_type == UserTypeChoices.ADMIN or request.user.user_type == UserTypeChoices.STAFF
        return False

    # Check for object-level permissions (if applicable)
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser or request.user.user_type == UserTypeChoices.ADMIN or request.user.user_type == UserTypeChoices.STAFF:
            return True
        return False




