from django.contrib.sessions.models import Session
from django.http import JsonResponse
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView, ListAPIView
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from django.db.models import Q

from rest_framework.response import Response
from rest_framework import status

from common.views import CsrfExemptSessionAuthentication
from users.models import BaseUser
from users.permissions import AllowedStaffCreation, AllowedAdminCreation, StaffUserAccess

from . models import (
    UserCredentialsSetup, Apps, Organizations, Clients,
    Projects, BillingSystemMappingRecord, Roles, Departments,
    Stakes, CustomBins, TargetSettings)

from .serializers import (
    UserCredentialsSetupSerializers, ListApprovalUserSerializer, AppsSerializer, OrganizationSerializer,
    ClientSerializer, ProjectsSerializer, BillingSystemMappingSerializer, RolesSerializer, DepartmentsSerializer,
    StakesSerializer, GetUserSerializer, CustomBinsSerializer, TargetSettingSerializer)

from . utils import mapping_db_headers
from .models import ScreensChoices


from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authentication import BasicAuthentication
from rest_framework.permissions import IsAuthenticated
from .models import Insurance
from .serializers import InsuranceSerializer
import json

"""
User Credentials Get, Create, Update, Delete Views based on user auth
"""
class StaffUserCredentialView(ListCreateAPIView, RetrieveUpdateDestroyAPIView):
    queryset = UserCredentialsSetup.objects.all()
    serializer_class = UserCredentialsSetupSerializers
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    permission_classes = [StaffUserAccess]

    def get_user_from_session(self):
        """
        Retrieve the user from the session using the session ID.
        """
        sessionid = self.request.COOKIES.get('sessionid')

        if sessionid:
            try:
                session = Session.objects.get(session_key=sessionid)
                session_data = session.get_decoded()
                user_id = session_data.get('_auth_user_id')

                if user_id:
                    return BaseUser.objects.get(id=user_id)
            except Session.DoesNotExist:
                pass  # Session does not exist
        return None  # Return None if no user is found

    def get_queryset(self):
        """
        Optionally filters the queryset based on the user from the session.
        """
        users = self.get_user_from_session()
        if users:
            user_credentials = UserCredentialsSetup.objects.filter(email=users.email)
            if user_credentials.exists():
                user_org_ids = user_credentials.first().organizations.values_list('id', flat=True)
                return UserCredentialsSetup.objects.filter(organizations__id__in=user_org_ids)
            else:
                return []

    def get(self, request, *args, **kwargs):
        user_credentials = self.get_queryset()
        serializer = self.serializer_class(user_credentials, many=True)
        return JsonResponse(serializer.data, safe=False, status=200)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        return self.destroy(request, *args, **kwargs)

class UpdateDeleteStaffUserCredentials(RetrieveUpdateDestroyAPIView):
    queryset = UserCredentialsSetup.objects.all()
    serializer_class = UserCredentialsSetupSerializers
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    permission_classes = [StaffUserAccess]

class AdminUserCredentialView(ListCreateAPIView):
    queryset = UserCredentialsSetup.objects.all()
    serializer_class = UserCredentialsSetupSerializers
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    permission_classes = [AllowedStaffCreation, AllowedAdminCreation]

    def get_user_from_session(self):
        """
        Retrieve the user from the session using the session ID.
        """
        sessionid = self.request.COOKIES.get('sessionid')

        if sessionid:
            try:
                session = Session.objects.get(session_key=sessionid)
                session_data = session.get_decoded()
                user_id = session_data.get('_auth_user_id')

                if user_id:
                    return BaseUser.objects.get(id=user_id)
            except Session.DoesNotExist:
                pass  # Session does not exist
        return None  # Return None if no user is found

    def get_queryset(self):
        """
        Optionally filters the queryset based on the user from the session.
        """
        users = self.get_user_from_session()
        if users:
            user_credentials = UserCredentialsSetup.objects.filter(email=users.email)
            if user_credentials.exists():
                user_org_ids = user_credentials.first().organizations.values_list('id', flat=True)
                return UserCredentialsSetup.objects.filter(organizations__id__in=user_org_ids)
            else:
                return []

    def get(self, request, *args, **kwargs):
        user_credentials = self.get_queryset()
        serializer = self.serializer_class(user_credentials, many=True)
        return JsonResponse(serializer.data, safe=False, status=200)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

class UpdateDeleteAdminUserCredentials(RetrieveUpdateDestroyAPIView):
    queryset = UserCredentialsSetup.objects.all()
    serializer_class = UserCredentialsSetupSerializers
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    permission_classes = [AllowedStaffCreation, AllowedAdminCreation]

class SuperAdminUserCredentialView(ListCreateAPIView, RetrieveUpdateDestroyAPIView):
    queryset = UserCredentialsSetup.objects.all()
    serializer_class = UserCredentialsSetupSerializers
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    permission_classes = [AllowedAdminCreation, AllowedStaffCreation, StaffUserAccess]

    def get_user_from_session(self):
        """
        Retrieve the user from the session using the session ID.
        """
        sessionid = self.request.COOKIES.get('sessionid')

        if sessionid:
            try:
                session = Session.objects.get(session_key=sessionid)
                session_data = session.get_decoded()
                user_id = session_data.get('_auth_user_id')

                if user_id:
                    return BaseUser.objects.get(id=user_id)
            except Session.DoesNotExist:
                pass  # Session does not exist
        return None  # Return None if no user is found

    def get_queryset(self):
        """
        Optionally filters the queryset based on the user from the session.
        """
        users = self.get_user_from_session()
        if users:
            return UserCredentialsSetup.objects.all()
        return None

    def get(self, request, *args, **kwargs):
        user_credentials = self.get_queryset()
        serializer = self.serializer_class(user_credentials, many=True)
        return JsonResponse(serializer.data, safe=False, status=200)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        return self.destroy(request, *args, **kwargs)

"""
Approval User Get View
"""
"""
FINAL CORRECT Approval User Get View - Based on Your Actual Models
"""
class GetApprovalUsers(ListAPIView):
    serializer_class = ListApprovalUserSerializer
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    permission_classes = [AllowedAdminCreation, AllowedStaffCreation, StaffUserAccess]

    def get_queryset(self):
        project_ids_str = self.request.query_params.get('project_id', None)
        
        print(f"🔍 Received project_ids_str: {project_ids_str}")

        if not project_ids_str:
            print("❌ No project_id parameter provided")
            return UserCredentialsSetup.objects.none()

        try:
            # Handle both single ID and comma-separated IDs
            if ',' in project_ids_str:
                project_ids = [int(pid.strip()) for pid in project_ids_str.split(',') if pid.strip().isdigit()]
            else:
                project_ids = [int(project_ids_str.strip())] if project_ids_str.strip().isdigit() else []
            
            print(f"✅ Parsed project_ids: {project_ids}")
            
            if not project_ids:
                print("❌ No valid project IDs found")
                return UserCredentialsSetup.objects.none()

            # CORRECT QUERY based on your models:
            # UserCredentialsSetup -> project_assignments (related_name) -> UserProjectAssignment -> project -> Projects
            queryset = UserCredentialsSetup.objects.filter(
                project_assignments__project__id__in=project_ids
            ).distinct()
            
            print(f"📊 Queryset count: {queryset.count()}")
            
            # Debug: Print found users
            users_found = [(u.pk, f'{u.first_name} {u.last_name}', u.employee_id) for u in queryset]
            print(f"👥 Users found: {users_found}")
            
            return queryset
            
        except ValueError as e:
            print(f"❌ ValueError: {e}")
            return UserCredentialsSetup.objects.none()
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            return UserCredentialsSetup.objects.none()

    def get(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        
        print(f"🚀 Final serialized data: {serializer.data}")
        
        return JsonResponse(serializer.data, safe=False, status=200)
"""
Dynamic User Get Views
"""
class ManageUserCredentialsView(ListCreateAPIView, RetrieveUpdateDestroyAPIView):
    queryset = UserCredentialsSetup.objects.all()
    serializer_class = GetUserSerializer
    permission_classes = (IsAuthenticated,)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

    def get_queryset(self):
        # fetch and response users for rule creation action
        project_ids = self.request.query_params.get('project_ids', None)
        if project_ids and isinstance(project_ids, str): project_ids = list(map(int, project_ids.split(',')))

        if project_ids:
            # todo project related: change prefetch_related model field to use 'project_assignments' reference
            return UserCredentialsSetup.objects.filter(projects__id__in=
                                                       project_ids).distinct().prefetch_related('projects')

"""
App Get, Create, Update, Retrieve, Delete Views
"""
class GetCreateAppsView(ListCreateAPIView):
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    serializer_class = AppsSerializer
    queryset = Apps.objects.all()

    def get_queryset(self):
        """
        Optionally filters the queryset based on the 'user_id' query parameter.
        """
        try:
            employee_id = self.request.query_params.get('user_id', None)
            organization_ids = self.request.query_params.get('organization', None)
            if employee_id is not None:
                # Get the UserCredentialsSetup instance that matches the employee_id
                user_credentials = UserCredentialsSetup.objects.filter(employee_id=employee_id).first()

                # If the user exists and has associated organizations, return them
                if user_credentials:
                    return user_credentials.apps.all()

                # If no matching user found, return an empty queryset
                return Apps.objects.none()

            if organization_ids is not None:
                organization_ids = [int(id) for id in organization_ids.split(',')]
                organization = Apps.objects.filter(organization__id__in=organization_ids)
                return organization
            # If no filter is applied, return all Apps
            return Apps.objects.all()
        except RuntimeError as e:
            return JsonResponse({"error": "failed to fetch Organizations"}, status=400)

class RetrieveUpdateDeleteAppsView(RetrieveUpdateDestroyAPIView):
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    serializer_class = AppsSerializer
    queryset = Apps.objects.all()

"""
Organization Get, Create, Update, Retrieve, Delete Views
"""
class GetCreateOrganizations(ListCreateAPIView):
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    serializer_class = OrganizationSerializer
    queryset = Organizations.objects.all()

    def get_queryset(self):
        """
        Optionally filters the queryset based on the 'user_id' query parameter.
        """
        try:
            employee_id = self.request.query_params.get('user_id', None)
            if employee_id is not None:
                # Get the UserCredentialsSetup instance that matches the employee_id
                user_credentials = UserCredentialsSetup.objects.filter(employee_id=employee_id).first()

                # If the user exists and has associated organizations, return them
                if user_credentials:
                    return user_credentials.organizations.all()

                # If no matching user found, return an empty queryset
                return Organizations.objects.none()

            # If no filter is applied, return all organizations
            return Organizations.objects.all()
        except RuntimeError as e:
            return JsonResponse({"error": "failed to fetch Organizations"}, status=400)

class RetrieveUpdateDeleteOrganizations(RetrieveUpdateDeleteAppsView):
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    serializer_class = OrganizationSerializer
    queryset = Organizations.objects.all()

    def get_queryset(self):
        """
        Optionally filters the queryset based on the 'user_id' query parameter.
        """
        try:
            employee_id = self.request.query_params.get('user_id', None)
            if employee_id is not None:
                # Get the UserCredentialsSetup instance that matches the employee_id
                user_credentials = UserCredentialsSetup.objects.filter(employee_id=employee_id).first()

                # If the user exists and has associated organizations, return them
                if user_credentials:
                    return user_credentials.organizations.all()

                # If no matching user found, return an empty queryset
                return Organizations.objects.none()

            # If no filter is applied, return all organizations
            return Organizations.objects.all()
        except RuntimeError as e:
            return JsonResponse({"error": "failed to fetch Organizations"}, status=400)

"""
Roles Get, Create, Update, Retrieve, Delete Views
"""
class GetCreateRolesView(ListCreateAPIView):
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    serializer_class = RolesSerializer
    queryset = Roles.objects.all()

    def get_queryset(self):
        """
        Optionally filters the queryset based on the 'organization' query parameter.
        """
        try:
            organization_ids = self.request.query_params.get('organization', None)
            # user_id = self.request.query_params.get('user_id', None)
            if organization_ids is not None:
                organization_ids = [int(id) for id in organization_ids.split(',')]
                return Roles.objects.filter(organization_id__in=organization_ids)
            return Roles.objects.all()
        except RuntimeError as e:
            return JsonResponse({"error": "failed to fetch Roles"}, status=400)


class RetrieveUpdateDeleteRolesView(RetrieveUpdateDestroyAPIView):
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    serializer_class = RolesSerializer
    queryset = Roles.objects.all()

    def get_queryset(self):
        """
        Optionally filters the queryset based on the 'organization' query parameter.
        """
        try:
            organization_ids = self.request.query_params.get('organization', None)
            # user_id = self.request.query_params.get('user_id', None)
            if organization_ids is not None:
                organization_ids = [int(id) for id in organization_ids.split(',')]
                return Roles.objects.filter(organization_id__in=organization_ids)
            return Roles.objects.all()
        except RuntimeError as e:
            return JsonResponse({"error": "failed to fetch Roles"}, status=400)

"""
Clients Get, Create, Update, Retrieve, Delete Views
"""
class GetCreateClientsView(ListCreateAPIView):
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    serializer_class = ClientSerializer
    queryset = Clients.objects.all()

    def get_queryset(self):
        """
        Optionally filters the queryset based on the 'organization' query parameter.
        """
        try:
            organization_ids = self.request.query_params.get('organization', None)
            if organization_ids is not None:
                # Split the comma-separated string into a list of integers
                organization_ids = [int(id) for id in organization_ids.split(',')]
                return Clients.objects.filter(organization_id__in=organization_ids)
            return Clients.objects.all()
        except ValueError as e:
            # Handle invalid input (e.g., non-integer values in the organization IDs)
            return JsonResponse({"error": "Invalid organization IDs"}, status=400)
        except RuntimeError as e:
            return JsonResponse({"error": "Failed to fetch Clients"}, status=400)

class RetrieveUpdateDeleteClientsView(RetrieveUpdateDestroyAPIView):
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    serializer_class = ClientSerializer
    queryset = Clients.objects.all()

    def get_queryset(self):
        """
        Optionally filters the queryset based on the 'organization' query parameter.
        """
        try:
            organization_ids = self.request.query_params.get('organization', None)
            # user_id = self.request.query_params.get('user_id', None)
            if organization_ids is not None:
                organization_ids = [int(id) for id in organization_ids.split(',')]
                return Clients.objects.filter(organization_id__in=organization_ids)
            return Clients.objects.all()
        except RuntimeError as e:
            return JsonResponse({"error": "failed to fetch Clients"}, status=400)

"""
Projects Get, Create, Update, Retrieve, Delete Views
"""
class GetCreateProjectsView(ListCreateAPIView):
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    serializer_class = ProjectsSerializer
    queryset = Projects.objects.all()

    def get_queryset(self):
        """
        Optionally filters the queryset based on the 'organization' query parameter.
        """
        try:
            organization_ids = self.request.query_params.get('organization', None)
            client_id = self.request.query_params.get('client', None)
            employee_id = self.request.query_params.get('employee_id', None)
            
            if organization_ids and client_id and employee_id:
                credentials = UserCredentialsSetup.objects.filter(employee_id=employee_id).first()
                if credentials: 
                    return Projects.objects.filter(id=credentials.project_assignments.first().project.id)
                    
            if organization_ids and client_id and employee_id is None:
                organization_ids = [int(id) for id in organization_ids.split(',')]
                client_ids = [int(id) for id in client_id.split(',')]
                return Projects.objects.filter(Q(organization_id__in=organization_ids) &
                                               Q(clients__in=client_ids))
                                               
            if organization_ids and employee_id and client_id is None:
                return Projects.objects.all().filter(
                    user_assignments__user__employee_id=employee_id
                ).distinct()
                
            if organization_ids and not employee_id and not client_id:
                return Projects.objects.filter(organization_id__in=organization_ids)

            return Projects.objects.all()
        except RuntimeError as e:
            return JsonResponse({"error": "failed to fetch Projects"}, status=400)

    def create(self, request, *args, **kwargs):
        """
        Override create method to handle billing system mapping separately
        """
        # Remove billing_system_mapping from project data as it's handled separately
        project_data = request.data.copy()
        billing_system_id = project_data.pop('billing_system_mapping', None)
        
        # Create the project first
        serializer = self.get_serializer(data=project_data)
        serializer.is_valid(raise_exception=True)
        project = serializer.save()
        
        # If billing system is provided, handle it in the frontend
        # The frontend will make a separate call to create the billing mapping
        
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

class RetrieveUpdateDeleteProjectsView(RetrieveUpdateDestroyAPIView):
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    serializer_class = ProjectsSerializer
    queryset = Projects.objects.all()

    def get_queryset(self):
        """
        Optionally filters the queryset based on the 'organization' query parameter.
        """
        try:
            organization_ids = self.request.query_params.get('organization', None)
            client_id = self.request.query_params.get('client', None)
            employee_id = self.request.query_params.get('employee_id', None)
            if organization_ids and client_id and employee_id:
                credentials = UserCredentialsSetup.objects.filter(employee_id=employee_id).first()
                if credentials:
                    return credentials.projects.all()
            if organization_ids and client_id and employee_id is None:
                organization_ids = [int(id) for id in organization_ids.split(',')]
                return Projects.objects.filter(Q(organization_id__in=organization_ids) &
                                               Q(clients=client_id))
            if organization_ids and employee_id and client_id is None:
                credentials = UserCredentialsSetup.objects.filter(employee_id=employee_id).first()
                if credentials:
                    return credentials.projects.all()
            return Projects.objects.all()
        except RuntimeError as e:
            return JsonResponse({"error": "failed to fetch Projects"}, status=400)

"""
Billing System Get Views
"""
class GetCreateBillingSystemMappingsView(ListCreateAPIView):
    queryset = BillingSystemMappingRecord.objects.all()
    serializer_class = BillingSystemMappingSerializer
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

    def get_queryset(self):
        """
        Optionally filters the queryset based on the 'organization' query parameter.
        """
        try:
            organization_ids = self.request.query_params.get('organization', None)
            project_id = self.request.query_params.get('project', None)
            
            queryset = BillingSystemMappingRecord.objects.all()
            
            if organization_ids is not None:
                organization_ids = [int(id) for id in organization_ids.split(',')]
                queryset = queryset.filter(organization_id__in=organization_ids)
                
            if project_id is not None:
                queryset = queryset.filter(project_id=project_id)
                
            return queryset
        except RuntimeError as e:
            return JsonResponse({"error": "failed to fetch BillingSystemMappingRecord"}, status=400)

    def create(self, request, *args, **kwargs):
        """
        Create new billing system mapping record by copying ALL fields from the original
        This ensures that when a billing system is mapped to multiple projects, 
        all field configurations are preserved
        """
        try:
            print("Received data:", request.data)
            
            project_id = request.data.get('project')  # This can be None now
            billing_file_name = request.data.get('billing_system_file_name')
            organization_id = request.data.get('organization')
            
            # Validate required fields - REMOVED project_id requirement
            if not billing_file_name:
                return Response(
                    {"error": "Billing system file name is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            if not organization_id:
                return Response(
                    {"error": "Organization ID is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Only check for existing mapping if project_id is provided
            if project_id:
                existing_mapping = BillingSystemMappingRecord.objects.filter(
                    project_id=project_id,
                    billing_system_file_name=billing_file_name,
                    organization_id=organization_id
                ).first()
                
                if existing_mapping:
                    return Response(
                        {"error": "This billing system is already mapped to this project in this organization"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )

            # Find the original billing system to copy ALL configuration from
            # Look for any existing billing system with the same file name in the same organization
            original_billing_system = BillingSystemMappingRecord.objects.filter(
                billing_system_file_name=billing_file_name,
                organization_id=organization_id
            )
            
            # If project_id is provided, exclude it from the search
            if project_id:
                original_billing_system = original_billing_system.exclude(project_id=project_id)
            
            original_billing_system = original_billing_system.first()

            if original_billing_system:
                print(f"Found original billing system to copy from: {original_billing_system.id}")
                
                # Create a complete copy of the original billing system
                # Copy ALL fields from the original to preserve complete configuration
                mapping_data = {
                    'billing_system_file_name': original_billing_system.billing_system_file_name,
                    'organization': organization_id,
                    'project': project_id,  # This can be None
                    'selected_bin': original_billing_system.selected_bin,
                    
                    # Copy ALL mapping fields - this is crucial for preserving configuration
                    'input_source': original_billing_system.input_source,
                    'mrn': original_billing_system.mrn,
                    'patient_id': original_billing_system.patient_id,
                    'account_number': original_billing_system.account_number,
                    'visit_number': original_billing_system.visit_number,
                    'chart_number': original_billing_system.chart_number,
                    'facility': original_billing_system.facility,
                    'facility_type': original_billing_system.facility_type,
                    'patient_last_name': original_billing_system.patient_last_name,
                    'patient_first_name': original_billing_system.patient_first_name,
                    'patient_phone': original_billing_system.patient_phone,
                    'patient_address': original_billing_system.patient_address,
                    'patient_city': original_billing_system.patient_city,
                    'patient_state': original_billing_system.patient_state,
                    'patient_zip': original_billing_system.patient_zip,
                    'patient_birthday': original_billing_system.patient_birthday,
                    'patient_gender': original_billing_system.patient_gender,
                    'subscriber_last_name': original_billing_system.subscriber_last_name,
                    'subscriber_first_name': original_billing_system.subscriber_first_name,
                    'subscriber_relationship': original_billing_system.subscriber_relationship,
                    'subscriber_phone': original_billing_system.subscriber_phone,
                    'subscriber_address': original_billing_system.subscriber_address,
                    'subscriber_city': original_billing_system.subscriber_city,
                    'subscriber_state': original_billing_system.subscriber_state,
                    'subscriber_zip': original_billing_system.subscriber_zip,
                    'subscriber_birthday': original_billing_system.subscriber_birthday,
                    'subscriber_gender': original_billing_system.subscriber_gender,
                    'current_billed_financial_class': original_billing_system.current_billed_financial_class,
                    'current_billed_payer_name': original_billing_system.current_billed_payer_name,
                    'member_id_current_billed_payer': original_billing_system.member_id_current_billed_payer,
                    'group_number_current_billed_payer': original_billing_system.group_number_current_billed_payer,
                    'current_billed_relationship': original_billing_system.current_billed_relationship,
                    'cob': original_billing_system.cob,
                    'payer_id_current_billed_payer': original_billing_system.payer_id_current_billed_payer,
                    'timely_filing_limit': original_billing_system.timely_filing_limit,
                    'appeal_limit': original_billing_system.appeal_limit,
                    'primary_payer_financial_class': original_billing_system.primary_payer_financial_class,
                    'primary_payer_name': original_billing_system.primary_payer_name,
                    'member_id_primary_payer': original_billing_system.member_id_primary_payer,
                    'group_number_primary_payer': original_billing_system.group_number_primary_payer,
                    'relationship_primary_payer': original_billing_system.relationship_primary_payer,
                    'cob_primary': original_billing_system.cob_primary,
                    'payer_id_primary_payer': original_billing_system.payer_id_primary_payer,
                    'secondary_payer_financial_class': original_billing_system.secondary_payer_financial_class,
                    'secondary_payer_name': original_billing_system.secondary_payer_name,
                    'member_id_secondary_payer': original_billing_system.member_id_secondary_payer,
                    'group_number_secondary_payer': original_billing_system.group_number_secondary_payer,
                    'relationship_secondary_payer': original_billing_system.relationship_secondary_payer,
                    'cob_secondary': original_billing_system.cob_secondary,
                    'payer_id_secondary_payer': original_billing_system.payer_id_secondary_payer,
                    'tertiary_payer_financial_class': original_billing_system.tertiary_payer_financial_class,
                    'tertiary_payer_name': original_billing_system.tertiary_payer_name,
                    'member_id_tertiary_payer': original_billing_system.member_id_tertiary_payer,
                    'group_number_tertiary_payer': original_billing_system.group_number_tertiary_payer,
                    'relationship_tertiary_payer': original_billing_system.relationship_tertiary_payer,
                    'cob_tertiary': original_billing_system.cob_tertiary,
                    'payer_id_tertiary_payer': original_billing_system.payer_id_tertiary_payer,
                    'auth_number': original_billing_system.auth_number,
                    'claim_number': original_billing_system.claim_number,
                    'facility_code': original_billing_system.facility_code,
                    'claim_frequency_type': original_billing_system.claim_frequency_type,
                    'signature': original_billing_system.signature,
                    'assignment_code': original_billing_system.assignment_code,
                    'assign_certification': original_billing_system.assign_certification,
                    'release_info_code': original_billing_system.release_info_code,
                    'service_date': original_billing_system.service_date,
                    'van_trace_number': original_billing_system.van_trace_number,
                    'rendering_provider_id': original_billing_system.rendering_provider_id,
                    'taxonomy_code': original_billing_system.taxonomy_code,
                    'procedure_code': original_billing_system.procedure_code,
                    'amount': original_billing_system.amount,
                    'procedure_count': original_billing_system.procedure_count,
                    'tooth_code': original_billing_system.tooth_code,
                    'procedure_code2': original_billing_system.procedure_code2,
                    'amount2': original_billing_system.amount2,
                    'procedure_count2': original_billing_system.procedure_count2,
                    'tooth_code2': original_billing_system.tooth_code2,
                    'procedure_code3': original_billing_system.procedure_code3,
                    'amount3': original_billing_system.amount3,
                    'procedure_count3': original_billing_system.procedure_count3,
                    'tooth_code3': original_billing_system.tooth_code3,
                    'procedure_code4': original_billing_system.procedure_code4,
                    'amount4': original_billing_system.amount4,
                    'procedure_count4': original_billing_system.procedure_count4,
                    'tooth_code4': original_billing_system.tooth_code4,
                    'dx1': original_billing_system.dx1,
                    'dx2': original_billing_system.dx2,
                    'dx3': original_billing_system.dx3,
                    'dx4': original_billing_system.dx4,
                    'dx5': original_billing_system.dx5,
                    'dx6': original_billing_system.dx6,
                    'total_charged': original_billing_system.total_charged,
                    'check_number': original_billing_system.check_number,
                    'insurance_balance': original_billing_system.insurance_balance,
                    'patient_balance': original_billing_system.patient_balance,
                    'contract_name': original_billing_system.contract_name,
                    'division': original_billing_system.division,
                    'type_of_service': original_billing_system.type_of_service,
                    'current_queue': original_billing_system.current_queue,
                    'queue_days': original_billing_system.queue_days,
                    'latest_action_date': original_billing_system.latest_action_date,
                    'next_follow_up_before': original_billing_system.next_follow_up_before,
                    'claim_denial_date': original_billing_system.claim_denial_date,
                    'claim_denial_code': original_billing_system.claim_denial_code,
                    'claim_denial_description': original_billing_system.claim_denial_description,
                    'latest_pay_date': original_billing_system.latest_pay_date,
                    'latest_pay_amount': original_billing_system.latest_pay_amount,
                    'claim_priority': original_billing_system.claim_priority,
                    'category': original_billing_system.category,
                    'sub_category': original_billing_system.sub_category,
                    'status': original_billing_system.status,
                    'action': original_billing_system.action,
                    'provider_name': original_billing_system.provider_name,
                    'provider_npi': original_billing_system.provider_npi,
                    'provider_location': original_billing_system.provider_location,
                    'assigned_to': original_billing_system.assigned_to,
                    'last_claim_status_check_date': original_billing_system.last_claim_status_check_date,
                    'last_ev_check_date': original_billing_system.last_ev_check_date,
                    'last_ins_disc_check_date': original_billing_system.last_ins_disc_check_date,
                    'under_pay': original_billing_system.under_pay,
                }
                
                print("Copying complete configuration from existing billing system")
                
            else:
                print("No existing billing system found, using provided data")
                # If no original found, use the provided data (should include all field mappings from frontend)
                mapping_data = request.data.copy()
                
                # Ensure basic required fields are set if not provided
                if 'selected_bin' not in mapping_data:
                    mapping_data['selected_bin'] = billing_file_name

            print("Final mapping data keys:", list(mapping_data.keys()))
            print("Sample field values:", {
                'mrn': mapping_data.get('mrn'),
                'patient_id': mapping_data.get('patient_id'),
                'service_date': mapping_data.get('service_date')
            })
            
            # Create new mapping record
            serializer = self.get_serializer(data=mapping_data)
            if not serializer.is_valid():
                print("Serializer errors:", serializer.errors)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                
            billing_mapping = serializer.save()
            
            print(f"Successfully created billing mapping: {billing_mapping.id}")
            print(f"Saved mapping mrn field: {billing_mapping.mrn}")
            print(f"Saved mapping service_date field: {billing_mapping.service_date}")
            
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
            
        except Exception as e:
            print("Exception in create:", str(e))
            import traceback
            traceback.print_exc()
            return Response(
                {"error": f"Failed to create billing system mapping: {str(e)}"}, 
                status=status.HTTP_400_BAD_REQUEST
            )

class RetrieveUpdateDeleteBillingSystemMappingsView(RetrieveUpdateDestroyAPIView):
    queryset = BillingSystemMappingRecord.objects.all()
    serializer_class = BillingSystemMappingSerializer
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

    def partial_update(self, request, *args, **kwargs):
        """
        Handle partial updates for billing system mappings
        """
        kwargs['partial'] = True
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """
        Allow deletion of specific billing system mappings
        """
        try:
            instance = self.get_object()
            self.perform_destroy(instance)
            return Response(
                {"message": "Billing system mapping deleted successfully"}, 
                status=status.HTTP_204_NO_CONTENT
            )
        except Exception as e:
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_400_BAD_REQUEST
            )

"""
Billing System Mapping headers Get only
"""

def get_billing_system_mapping_db_headers(request):
    try:
        # Get the model fields from PatientRecord
        fields = [header_name for header_name in mapping_db_headers]
        return JsonResponse({'headers': fields})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

"""
Departments Get, Create, Update, Retrieve, Delete Views
"""
class GetCreateDepartmentView(ListCreateAPIView):
    queryset = Departments.objects.all()
    serializer_class = DepartmentsSerializer
    permission_classes = (IsAuthenticated, )
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

    def get_queryset(self):
        """
        Optionally filters the queryset based on the 'organization' query parameter.
        """
        try:
            organization_ids = self.request.query_params.get('organization', None)
            if organization_ids is not None:
                # Split the comma-separated string into a list of integers
                organization_ids = [int(id) for id in organization_ids.split(',')]
                return Departments.objects.filter(organization_id__in=organization_ids)
            return Departments.objects.all()
        except ValueError as e:
            # Handle invalid input (e.g., non-integer values in the organization IDs)
            return JsonResponse({"error": "Invalid organization IDs"}, status=400)
        except RuntimeError as e:
            return JsonResponse({"error": "Failed to fetch Departments"}, status=400)

class RetrieveUpdateDeleteDepartmentView(RetrieveUpdateDestroyAPIView):
    queryset = Departments.objects.all()
    serializer_class = DepartmentsSerializer
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

"""
Stakes Get, Create, Update, Retrieve, Delete Views
"""
class GetCreateStakesView(ListCreateAPIView):
    queryset = Stakes.objects.all()
    serializer_class = StakesSerializer
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

    def get_queryset(self):
        """
        Optionally filters the queryset based on the 'organization' query parameter.
        """
        try:
            organization_ids = self.request.query_params.get('organization', None)
            if organization_ids is not None:
                # Split the comma-separated string into a list of integers
                organization_ids = [int(id) for id in organization_ids.split(',')]
                return Stakes.objects.filter(organization_id__in=organization_ids)
            return Stakes.objects.all()
        except ValueError as e:
            # Handle invalid input (e.g., non-integer values in the organization IDs)
            return JsonResponse({"error": "Invalid organization IDs"}, status=400)
        except RuntimeError as e:
            return JsonResponse({"error": "Failed to fetch Stakes"}, status=400)

class RetrieveUpdateDeleteStakesView(RetrieveUpdateDestroyAPIView):
    queryset = Stakes.objects.all()
    serializer_class = StakesSerializer
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

class GetCreateCustomBinsView(ListCreateAPIView):
    queryset = CustomBins.objects.all()
    serializer_class = CustomBinsSerializer
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    # lookup_field = 'organization' # doesnt works

    def get_queryset(self):
        """
        filters the queryset based on the 'organization' query parameter.
        """
        try:
            organization_ids = self.request.query_params.get('organization', None)
            if organization_ids is not None:
                # Split the comma-separated string into a list of integers
                organization_ids = [int(id) for id in organization_ids.split(',')]
                return CustomBins.objects.filter(organization_id__in=organization_ids)
            # return CustomBins.objects.all()
        except ValueError as e:
            # Handle invalid input (e.g., non-integer values in the organization IDs)
            return JsonResponse({"error": "Invalid organization IDs"}, status=400)
        except RuntimeError as e:
            return JsonResponse({"error": "Failed to fetch CustomBins"}, status=400)


class RetrieveUpdateDeleteCustomBinsView(RetrieveUpdateDestroyAPIView):
    queryset = CustomBins.objects.all()
    serializer_class = CustomBinsSerializer
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

class GetCreateTargetSettingsView(ListCreateAPIView):
    queryset = TargetSettings.objects.all()
    serializer_class = TargetSettingSerializer
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

class RetrieveUpdateDeleteTargetSettingsView(RetrieveUpdateDestroyAPIView):
    queryset = TargetSettings.objects.all()
    serializer_class = TargetSettingSerializer
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)


# List all insurance records for a project or create a new insurance record
class InsuranceListCreateView(APIView):
    """
    List all insurance records for a project or create a new insurance record
    """
    authentication_classes = [CsrfExemptSessionAuthentication, BasicAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """
        Get all insurance records for a specific project
        """
        project_ids = request.query_params.get('project_ids')
        
        if not project_ids:
            return Response(
                {"error": "project_ids parameter is required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        insurance_records = Insurance.objects.filter(project=project_ids)
        serializer = InsuranceSerializer(insurance_records, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        """
        Create a new insurance record
        """
        serializer = InsuranceSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class InsuranceDetailView(APIView):
    """
    Retrieve, update or delete an insurance record
    """
    authentication_classes = [CsrfExemptSessionAuthentication, BasicAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get_object(self, pk):
        try:
            return Insurance.objects.get(pk=pk)
        except Insurance.DoesNotExist:
            return None
    
    def get(self, request, pk):
        """
        Retrieve an insurance record
        """
        insurance = self.get_object(pk)
        if not insurance:
            return Response(
                {"error": "Insurance record not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        serializer = InsuranceSerializer(insurance)
        return Response(serializer.data)
    
    def put(self, request, pk):
        """
        Update an insurance record
        """
        insurance = self.get_object(pk)
        if not insurance:
            return Response(
                {"error": "Insurance record not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = InsuranceSerializer(insurance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        """
        Delete an insurance record
        """
        insurance = self.get_object(pk)
        if not insurance:
            return Response(
                {"error": "Insurance record not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        insurance.delete()
        return Response(
            {"message": "Insurance record deleted successfully"}, 
            status=status.HTTP_204_NO_CONTENT
        )


# Function-based views (alternative approach)
@api_view(['GET', 'POST'])
@authentication_classes([CsrfExemptSessionAuthentication, BasicAuthentication])
@permission_classes([IsAuthenticated])
def get_create_insurance(request):
    """
    List all insurance records for a project or create a new insurance record
    """
    if request.method == 'GET':
        project_ids = request.query_params.get('project_ids')
        
        if not project_ids:
            return Response(
                {"error": "project_ids parameter is required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        insurance_records = Insurance.objects.filter(project=project_ids)
        serializer = InsuranceSerializer(insurance_records, many=True)
        return Response(serializer.data)
    
    elif request.method == 'POST':
        serializer = InsuranceSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Retrieve, update or delete an insurance record
@api_view(['GET', 'PUT', 'DELETE'])
@authentication_classes([CsrfExemptSessionAuthentication, BasicAuthentication])
@permission_classes([IsAuthenticated])
def manage_insurance(request, pk):
    """
    Retrieve, update or delete an insurance record
    """
    try:
        insurance = Insurance.objects.get(pk=pk)
    except Insurance.DoesNotExist:
        return Response(
            {"error": "Insurance record not found"}, 
            status=status.HTTP_404_NOT_FOUND
        )
    
    if request.method == 'GET':
        serializer = InsuranceSerializer(insurance)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        serializer = InsuranceSerializer(insurance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method == 'DELETE':
        insurance.delete()
        return Response(
            {"message": "Insurance record deleted successfully"}, 
            status=status.HTTP_204_NO_CONTENT
        )

# Get all available screen choices from ScreensChoices enum

@api_view(['GET'])
@authentication_classes([CsrfExemptSessionAuthentication, BasicAuthentication])
@permission_classes([IsAuthenticated])
def get_available_screens(request):
    """
    Get all available screen choices from ScreensChoices enum
    """
    try:
        # Get all screen choices from the enum
        screens = [
            {
                'value': choice.value,
                'label': choice.label
            } 
            for choice in ScreensChoices
        ]
        
        return JsonResponse({
            'screens': screens,
            'success': True,
            'total_count': len(screens)
        }, status=200)
        
    except Exception as e:
        return JsonResponse({
            'error': str(e),
            'success': False
        }, status=500)