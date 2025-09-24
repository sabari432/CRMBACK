# records/urls.py

from django.urls import path
from rest_framework import routers
from .views import DownloadRecordsView, TargetCorrectionApprovalView, TargetCorrectionCreateView, TargetCorrectionDetailView, TargetCorrectionListView, TargetCorrectionStatsView, download_records_view
from . import views
from .views import (PatientRecordListView, PatientRecordDetailView, success_view, credentials_manage, upload_csv)

from .views import (department_manage, roles_manage,
                    client_manage, project_manage, sector_manage, check_auth,
                    stake_manage, app_page_manage, apps_list,
                    process_file, get_notes, add_note,
                    assign_records, create_rule, RuleViewSet, delete_rule,
                    update_rule_status, get_uploaded_records_2,
                    get_workflow_header_names, create_flowchart, update_flowchart,
                    get_flowcharts, get_flowchart, delete_flowchart, flow_chart_process,
                    create_update_status_action, view_status_actions, delete_status_action,
                    get_status_codes,get_action_codes)
from .views import upload_csv_1, get_csv_headers, get_db_headers, save_mapping
from .views import save_mapped_data

from records.views import (UserCredentialViewSet, ClientsBySector, MappingRecordListCreateView, RetriveUpdateDeleteMappingsView,
                           ProjectsByClients, UploadCsvFile, ZeroUpload, GetProjectName, StaffUserCredentialView,
                           AdminUserCredentialView, ManageCredentialsView, GetUsersView, GetUploadedRecords, GetWorkedPatientRecord, GetClientsNames,
                           ProjectGetCreateView, ProjectManageView, GetCreateDepratmentView, ManageDepartmentView, GetCreateFlowChart,
                           ManageFlowChart, Copyflowchart, GetCreateStatusCode, GetOrCreateNotesView, FlowChartProcessView, GetStatusCodesView,
                           GetActionCodesView, AssignRecordsView, SectororOrgnizationGetCreateView, SectororOrgnizationRetriveUpdateDeleteView,
                           GetorCreateAppsView, RetriveUpdateDeleteAppsView, GetCreateRolesView, RetriveUpdateDeleteRolesView, GetUploadedFileLogs,
                           GetUserAllocationAppliedUploadedRecords, ProductivityCalculationView, EmployeeWorkedRecordsListView)


from . flow_chart_headers import get_workflow_header_names as only_flowchart_headers

from . flow_chart_headers import get_workflow_header_names as only_flowchart_headers

# Add these URLs to your existing records/urls.py
from .views import ( DynamicHeadersView, add_workflow_header, remove_workflow_header, get_field_types)

from . import views

from .views import (
    TabTimingView, 
    get_current_user, 
    get_user_tab_analytics,
    get_daily_activity_summary
)

app_name = 'records'


"""
File Management
"""
urlpatterns = [
    path('upload/', UploadCsvFile.as_view(), name='upload_csv'),
    path('download_records/<int:log_id>/<str:record_type>/', DownloadRecordsView.as_view(), name='download-records'),
    path('zero-upload/', ZeroUpload.as_view(), name='zero_upload'),
    path('api/upload-csv_1', upload_csv_1, name='upload_csv'),
    path('upload2/', upload_csv, name='upload_csv'),
    path('api/csv-headers/<str:file_id>', get_csv_headers, name='get_csv_headers'),
    path('api/db-headers', get_db_headers, name='get_db_headers'),
    path('api/process-file/', process_file, name='process_file'),
    path('api/save-mapping', save_mapping, name='save_mapping'),
    path('api/save-mapped-data/', save_mapped_data, name='save_mapped_data'),
    path('get_uploaded_patient_records/', GetUploadedRecords.as_view(), name='get-all-patient-records'),
    path('get_worked_patient_records/', GetWorkedPatientRecord.as_view(), name='get-all-patient-records'),
    path('get_custom_bins_records/', GetUserAllocationAppliedUploadedRecords.as_view(), name='custom-records'),
    path('get_uploaded_file_logs/', GetUploadedFileLogs.as_view(), name='get-file-logs'),
    
]

"""
User and Credential Management
"""
urlpatterns += [
    path('get_user_credentials/', UserCredentialViewSet.as_view(), name='user-credentials'),
    path('staff_credentials/', StaffUserCredentialView.as_view(), name='manage-new-staff-credentials'),
    path('admin_credentials/', AdminUserCredentialView.as_view(), name='manage-new-admin-credentials'),
    path('get_create_credentials/', ManageCredentialsView.as_view(), name='list-create-credentials'),
    path('manage_credentials/<int:pk>/', ManageCredentialsView.as_view(), name='update-delete-credentials'),
]

"""
Data Mappings and Project Data
"""
urlpatterns += [
    path('get_mappings/', MappingRecordListCreateView.as_view(), name='get_mappings'),
    path('retrieve_update_delete_mappings/<str:pk>/', RetriveUpdateDeleteMappingsView.as_view(), name='get_mappings'),
    path('clients_by_sector/<str:sector_id>/', ClientsBySector.as_view(), name='get_clients_by_sector'),
    path('projects_by_client/<str:client_id>/', ProjectsByClients.as_view(), name='projects_by_client'),
    path('get_project_names/', GetProjectName.as_view(), name='get_project_names'),
]

"""
Rules and Status Actions
"""
urlpatterns += [
    path('create_rule/', create_rule, name='create_rule'),
    path('get_create_rules/', RuleViewSet.as_view(), name='get_rules'),
    path('delete-rule/<int:rule_id>/', delete_rule, name='delete_rule'),
    path('update-rule-status/<int:rule_id>/', update_rule_status, name='update_rule_status'),
    path('get_create_status_actions/',GetCreateStatusCode.as_view(), name='get-create-status-action'),
    path('api/status-actions/', create_update_status_action, name='create-status-action'),
    path('api/status-actions/<int:pk>/', create_update_status_action, name='update-status-action'),
    path('api/view-status-actions/', view_status_actions, name='view-status-actions'),
    path('api/status-actions/delete/<int:pk>/', delete_status_action, name='delete-status-action'),
]

"""
Workflow and Flow Logic
"""
urlpatterns += [
    path('flowchart/workflow-header-names/', only_flowchart_headers, name='workflow-header-names'),
    path('get_create_flowchart/',GetCreateFlowChart.as_view(), name='get-create-flowchart'),
    path('manage_flowchart/<str:pk>/',ManageFlowChart.as_view(), name='manage-flowchart'),
    path('copy_flowchart/', Copyflowchart.as_view(), name='copy-flowcharts'),
    path('zero-upload/', ZeroUpload.as_view(), name='zero_upload'),
    path('flowchart/get_workflow_header_names/', get_workflow_header_names, name='get-workflow-header-names'),
    path('api/flow-logic/create/', create_flowchart, name='create_flowchart'),
    path('api/flow-logic/update/<int:flow_id>/', update_flowchart, name='update_flowchart'),
    path('api/flow-logic/<int:pk>/', get_flowchart, name='get_flowchart'),
    path('api/flow-logic/delete/<int:pk>/', delete_flowchart, name='delete_flowchart'),
    path('api/flow-logic/all/', get_flowcharts, name='get_flowcharts'),
    path('flow-chart-process/', FlowChartProcessView.as_view(), name='flow_chart_process'),
    path('api/workflow-headers/add/', add_workflow_header, name='add_workflow_header'),
    path('api/workflow-headers/remove/<str:field_name>/', remove_workflow_header, name='remove_workflow_header'),
    path('api/workflow-headers/field-types/', get_field_types, name='get_field_types'),
    path('api/workflow-headers/manage/', DynamicHeadersView.as_view(), name='manage_workflow_headers'),
    path('flowcharts/project/<str:project_id>/', views.get_flowcharts_by_project, name='flowcharts_by_project'),

]

"""
General Management
"""
urlpatterns += [
    path('get_create_departments/', GetCreateDepratmentView.as_view(), name='department_manage'),
    path('handle_departments/<str:pk>/', ManageDepartmentView.as_view(), name='handle-departments'),
    path('roles/', GetCreateRolesView.as_view(), name='roles_get-create'),
    path('roles/<str:pk>/',RetriveUpdateDeleteRolesView.as_view(), name='roles-retrieve-update-delete'),
    path('clients/', client_manage, name='client_manage'),
    path('list_clients/', GetClientsNames.as_view(), name='list-clients'),
    path('get_create_projects/', ProjectGetCreateView.as_view(), name='handle-projects-get-create'),
    path('handle_projects/<str:project_id>/', ProjectManageView.as_view(), name='handle-projects-restive-update-delete'),
    path('sources/', SectororOrgnizationGetCreateView.as_view(), name='sector_get-create'),
    path('sources/<str:pk>/', SectororOrgnizationRetriveUpdateDeleteView.as_view(), name='sector-retrieve-update-delete'),
    path('stakes/', stake_manage, name='stake_manage'),
    path('app_page/', GetorCreateAppsView.as_view(), name='apps-get-create'),
    path('app_page/<str:pk>/', RetriveUpdateDeleteAppsView.as_view(), name='apps-retrieve-update-delete'),
    path('apps/', apps_list, name='apps_list'),
    path('save-tab-timing/', views.TabTimingView.as_view(), name='save_tab_timing'),
    path('get-current-user/', views.get_current_user, name='get_current_user'),
    path('get-user-tab-analytics/', views.get_user_tab_analytics, name='get_user_tab_analytics'),
    path('get-daily-activity-summary/', views.get_daily_activity_summary, name='get_daily_activity_summary'),
    
]

"""
Notes and User Management
"""
urlpatterns += [
    path('get_create_note/', GetOrCreateNotesView.as_view(), name='get-create-notes'),
    path('get-users/', GetUsersView.as_view(), name='get_users'),
    path('assign_records/', AssignRecordsView.as_view(), name='assign_records'),
]

"""
Codes and Actions
"""
urlpatterns += [
    path('get_status_codes/', GetStatusCodesView.as_view(), name='get_status_codes'),
    path('get_action_codes/', GetActionCodesView.as_view(), name='get_action_codes'),
]

"""
productivity application [just for testing]
"""
urlpatterns += [
    path('productivity/', ProductivityCalculationView.as_view(), name='get-productivity'),
    path('employee_worked_records/', EmployeeWorkedRecordsListView.as_view(), name='employee-worked-records'),
    path('target-corrections/', views.TargetCorrectionListCreateView.as_view(), name='target-corrections-list-create'),
    # Alternative endpoint if you want to keep the original create view separate
    path('target-corrections/create/', views.TargetCorrectionCreateView.as_view(), name='target-corrections-create'),
    path('target-corrections/<int:pk>/', views.TargetCorrectionDetailView.as_view(), name='target-corrections-detail'),
    path('target-corrections/<int:pk>/approval/', views.TargetCorrectionApprovalView.as_view(), name='target-corrections-approval'),
    path('target-corrections/stats/', views.TargetCorrectionStatsView.as_view(), name='target-corrections-stats'),
    
]