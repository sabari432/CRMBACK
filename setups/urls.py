from django.urls import path

from . views import (SuperAdminUserCredentialView,
                     AdminUserCredentialView, UpdateDeleteAdminUserCredentials,
                     StaffUserCredentialView, UpdateDeleteStaffUserCredentials,
                     GetCreateAppsView, RetrieveUpdateDeleteAppsView,
                    GetApprovalUsers, ManageUserCredentialsView,
                     GetCreateOrganizations, RetrieveUpdateDeleteOrganizations,
                     GetCreateRolesView, RetrieveUpdateDeleteRolesView,
                     GetCreateClientsView, RetrieveUpdateDeleteClientsView,
                     GetCreateBillingSystemMappingsView, RetrieveUpdateDeleteBillingSystemMappingsView,
                     GetCreateProjectsView, RetrieveUpdateDeleteProjectsView,
                     GetCreateDepartmentView, RetrieveUpdateDeleteDepartmentView,
                     GetCreateStakesView, RetrieveUpdateDeleteStakesView,
                     GetCreateCustomBinsView, RetrieveUpdateDeleteCustomBinsView,
                     GetCreateTargetSettingsView, RetrieveUpdateDeleteTargetSettingsView, get_available_screens)

# function based views
from . views import get_billing_system_mapping_db_headers

from . import views

urlpatterns = [
    path('get_create_super_admin_user_credentials/', SuperAdminUserCredentialView.as_view(), name='get-create-super-admin-user-credentials'),
    path('retrieve_update_delete_super_admin_user_credentials/<int:pk>/', SuperAdminUserCredentialView.as_view(), name='retrieve-update-delete-super-admin-user-credentials'),
    path('get_create_admin_user_credentials/', AdminUserCredentialView.as_view(), name='get-create-admin-user-credentials'),
    path('retrieve_update_delete_admin_user_credentials/<int:pk>/', UpdateDeleteAdminUserCredentials.as_view(),name='retrieve-update-delete-admin-user-credentials'),
    path('get_create_staff_user_credentials/', StaffUserCredentialView.as_view(), name='get-create-staff-user-credentials'),
    path('retrieve_update_delete_staff_user_credentials/<int:pk>/', UpdateDeleteStaffUserCredentials.as_view(), name='retrieve-update-delete-staff-user-credentials'),
    path('get_approval_users/', GetApprovalUsers.as_view(), name='approves-user-list'),
    path('get_create_insurance/', views.get_create_insurance, name='get_create_insurance'),
    path('manage_insurance/<int:pk>/', views.manage_insurance, name='manage_insurance'),
    path('get_available_screens/', get_available_screens, name='get_available_screens'),

]

urlpatterns += [
    path('get_create_apps/', GetCreateAppsView.as_view(), name='get-create-apps'),
    path('retrieve_update_delete_apps/<int:pk>/', RetrieveUpdateDeleteAppsView.as_view(), name='retrieve-update-delete-apps'),
    path('get_create_organizations/', GetCreateOrganizations.as_view(), name='get-create-organizations'),
    path('retrieve_update_delete_organizations/<int:pk>/', RetrieveUpdateDeleteOrganizations.as_view(), name='retrieve-update-delete-organizations')
]

urlpatterns += [
    path('get_create_roles/',GetCreateRolesView.as_view(), name='get-create-roles'),
    path('retrieve_update_delete_roles/<int:pk>/', RetrieveUpdateDeleteRolesView.as_view(), name='retrieve-update-delete-roles'),
]

urlpatterns += [
    path('get_create_clients/', GetCreateClientsView.as_view(), name='get-create-clients'),
    path('retrieve_update_delete_clients/<int:pk>/', RetrieveUpdateDeleteClientsView.as_view(), name='retrieve-update-delete-clients'),
]

urlpatterns += [
    path('get_create_projects/', GetCreateProjectsView.as_view(), name='get-create-projects'),
    path('retrieve_update_delete_project/<int:pk>/', RetrieveUpdateDeleteProjectsView.as_view(), name='retrieve-update-delete-projects'),
    path('get_user_list_from_projects/', ManageUserCredentialsView.as_view(), name='get-user-list-project-lookup')
]

urlpatterns += [
    path('get_create_billing_system_mapping/', GetCreateBillingSystemMappingsView.as_view(), name='get-create-billing-system-mapping'),
    path('retrieve_update_delete_billing_system_mapping/<int:pk>/', RetrieveUpdateDeleteBillingSystemMappingsView.as_view(), name='retrieve-update-delete-billing-system-mapping'),
    path('get_billing_system_mapping_db_headers/', get_billing_system_mapping_db_headers, name='get-billing-system-mapping-db-headers'),
]

urlpatterns += [
    path('get_create_departments/', GetCreateDepartmentView.as_view(), name='get-create-departments'),
    path('retrieve_update_delete_departments/<int:pk>/', RetrieveUpdateDeleteDepartmentView.as_view(), name='retrieve-update-delete-departments'),
]

urlpatterns += [
    path('get_create_stakes/', GetCreateStakesView.as_view(), name='get-create-stakes'),
    path('retrieve_update_delete_stakes/<int:pk>/', RetrieveUpdateDeleteStakesView.as_view(), name='retrieve-update-delete-stakes'),
]

urlpatterns += [
    path('get_create_custom_bins/', GetCreateCustomBinsView.as_view(), name='get-create-custom-bins'),
    path('retrieve_update_delete_custom_bin/<int:pk>/', RetrieveUpdateDeleteCustomBinsView.as_view(), name='update-delete-custom-bins'),
]

urlpatterns += [
    path('get_create_target_settings/', GetCreateTargetSettingsView.as_view(), name='get-create-target-settings'),
    path('retrieve_update_delete_target_settings/<int:pk>/', RetrieveUpdateDeleteTargetSettingsView.as_view(), name='retrieve-update-delete-target-settings')
]