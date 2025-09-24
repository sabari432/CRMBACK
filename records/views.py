from datetime import timedelta
from datetime import datetime, date
from re import findall
import uuid
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views import View
from django.http import HttpResponse, Http404
from django.shortcuts import get_object_or_404
from .models import PatientRecords, RecordsUploadLogs

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.core.paginator import Paginator
from django.db.models import Q
from rest_framework.authentication import BasicAuthentication, TokenAuthentication
from rest_framework.decorators import authentication_classes

from setups.models import Projects
import csv
from decimal import Decimal
from tkinter import XView
import pandas as pd
import csv
import io
import pytz
from dateutil import parser
import  re
import csv
import io
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.views import View
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from .models import RecordsUploadLogs, PatientRecords
from django.core.serializers import serialize
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.core.paginator import Paginator
from django.core.exceptions import ValidationError
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.core.serializers.json import DjangoJSONEncoder
from django.forms.models import model_to_dict
from django.db.models import Q, Value
from django.db.models.functions import Concat
from django.db import transaction
from django.utils import timezone
from django.forms.models import model_to_dict
from django.db.models import Max, OuterRef, Subquery
from django.db.models.functions import TruncDate
from django_filters.rest_framework import DjangoFilterBackend
from django.db import connection

from django.db import transaction
from rest_framework.decorators import api_view, authentication_classes, permission_classes

from rest_framework import generics, permissions, status
from rest_framework.response import Response
from django.db import transaction
from django.utils import timezone
from django.core.exceptions import PermissionDenied
from django.db import models
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import generics, status, permissions
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.decorators import api_view
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.exceptions import NotFound
from rest_framework.permissions import IsAuthenticated
from users.permissions import AllowedStaffCreation, AllowedAdminCreation
from django.db import IntegrityError
from rest_framework import status, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth.models import User
from django.db import models
from django.apps import apps
from .models import *  # Import your existing models
import json



from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError, PermissionDenied
from django.utils import timezone
from django.db import transaction
from django.core.mail import send_mail
from django.conf import settings
from setups.models import Projects, BillingSystemMappingRecord, UserCredentialsSetup, CustomBins, UserProjectAssignment
from setups.serializers import BillingSystemMappingSerializer

from rules.models import RulesAndTypes
from rules.serializers import RulesSerializer

from .models import (
    PatientRecords, CredentialsForm, Codes, RuleVersions,
    DeptartmentPage, RolesPage, SectorPage, ProjectPage, ClientPage,
    StakePage, AppsPage, MappingRecord, PatientRecordNotes, ViewRules1,
    FlowChart, UserCredentials, RecordsUploadLogs, PatientRecordsLogs
)
from .serializers import (
    ApprovalActionSerializer, CreateTargetCorrectionSerializer, PatientRecordSerializer, CredentialsFormSerializer, TargetCorrectionSerializer, ViewRules1Serializer, CodesSerializer,
    MappingRecordSerializer, RecordNotesSerializer, FlowChartSerializer, CreateUserSerializers,
    UserCredentialsSerializer, ProjectPageSerializer, DeptartmentPageSerializer, SectorPageSerializer,
    AppsPageSerializer, RolesPageSerializer, RecordsUploadLogsSerializer, GetActionCodeSerializer,
    UserCredentialsSetupSerializer, ShowProductivityWorkedRecordSerializer
)
from .utils import mapColumns, removeEmptyfields, RuleApplier, mapping_csv_headers, ProcessData, mapping_db_headers

from common.views import CsrfExemptSessionAuthentication
from users.models import BaseUser
# loging
import json
import logging

from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views.decorators.http import require_http_methods
import json

from setups.models import Projects  # Import from setups app




import json
import logging
from datetime import datetime
from django.views import View
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.db import transaction
from django.db.models import Sum, Count, F
from django.contrib.auth.models import User
from django.utils import timezone
from .models import TabTiming, UserTabActivity

logger = logging.getLogger(__name__)

# Get the custom user model
User = get_user_model()

# Import your models (make sure these are in your models.py)
from .models import TabTiming, UserTabActivity



# Configure the logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)  # Set to DEBUG for more detailed logs
handler = logging.StreamHandler()  # You can also use FileHandler for file logs
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
from django.contrib.sessions.models import Session

def parse_service_date(service_date_str):
    try:
        # accept any date str format
        normalized_date_str = re.sub(r'[\/\.\s\:\;]', '-', service_date_str)  # Handles '/', '.', space, ':', ';'
        # Define the format for the date string
        return datetime.strptime(normalized_date_str, '%Y-%m-%d').date()
    except ValueError as e:
        print(f"Error parsing date: {e}")
        return None

def parse_and_format_date(date_str):
    try:
        # Attempt to parse the date using dateutil.parser
        parsed_date = parser.parse(date_str)
        # Convert the parsed date to the 'YYYY-MM-DD' format
        return parsed_date.strftime('%Y-%m-%d')
    
    except (ValueError, parser.ParserError):
        # Handle invalid date formats
        raise ValidationError(f"Invalid date format for: {date_str}. Please provide a valid date.")



def parse_date(date_str):
    """Try to parse the date in 'YYYY-MM-DD' format. Return None if invalid."""
    try:
        return datetime.strptime(date_str, '%Y-%m-%d').date()
    except (ValueError, TypeError):
        return None

@api_view(['POST'])
def apipost(request):
    serializer = CreateUserSerializers(data=request.data)
    if serializer.is_valid():
        serializer.save()
    else:
        print('serializer.errors', serializer.errors)

    return Response(serializer.data)

class StaffUserCredentialView(generics.ListCreateAPIView):
    queryset = UserCredentials.objects.all()
    serializer_class = CreateUserSerializers
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    permission_classes = [AllowedStaffCreation]

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

    def get(self, request, *args, **kwargs):
        users = self.get_user_from_session()
        user_credentials = UserCredentials.objects.filter(created_by=users)
        serializer = self.serializer_class(user_credentials, many=True)
        return JsonResponse(serializer.data, safe=False, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

class AdminUserCredentialView(generics.ListCreateAPIView):
    queryset = UserCredentials.objects.all()
    serializer_class = CreateUserSerializers
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    permission_classes = [AllowedAdminCreation]

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

    def get(self, request, *args, **kwargs):
        users = self.get_user_from_session()
        user_credentials = UserCredentials.objects.filter(created_by=users)
        serializer = self.serializer_class(user_credentials, many=True)
        return JsonResponse(serializer.data, safe=False, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


class GetUploadedFileLogs(generics.ListAPIView):
    permission_classes = (permissions.AllowAny,)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    serializer_class = RecordsUploadLogsSerializer
    queryset = RecordsUploadLogs.objects.all()

class UploadCsvFile(APIView):
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

    def post(self, request, *args, **kwargs):
        # Fetch dynamically
        project_id = request.data.get('project_id')
        organization_id = request.data.get('organization_id')
        selected_bin = request.data.get('selected_bin')
        upload_session_id = str(uuid.uuid4())
        file = request.FILES['file']
        if not file:
            return JsonResponse({"error": "No file provided"}, status=400)
        
        # Validate file
        if not self.is_valid_csv(file):
            return JsonResponse({"error": "Invalid file format. Please upload a CSV file."}, status=400)
        
        try:
            df = pd.read_csv(file)
        except pd.errors.EmptyDataError:
            return JsonResponse({"error": "The uploaded CSV file is empty or malformed."}, status=400)

        # maintain records logs
        records_logs = {
            'uploaded_file_name': file.name
        }

        # NEW: Get CPT level setting from billing system mapping
        try:
            mapping_instance = BillingSystemMappingRecord.objects.get(project=project_id)
            is_cpt_level = mapping_instance.is_cpt_level
        except BillingSystemMappingRecord.DoesNotExist:
            is_cpt_level = False

        # Retrieve mapping data and column names
        mapping_dict = self.get_mapping_data(project_id, df)
        if not mapping_dict:
            return JsonResponse({"error": "Mapping data not found"}, status=400)

        # list all unique fields mapped and validate while processing csv records
        unique_fields = self.get_mapping_required_and_unique_fields(project_id, 'unique')

        # list all required fields mapped and validate while processing csv records
        required_fields = self.get_mapping_required_and_unique_fields(project_id, 'required')

        required_fields.extend([field for field in unique_fields if field not in required_fields])

        # Process CSV file for columns mapping
        df_filtered = self.process_csv(df, mapping_dict)

        """
        Processes a DataFrame, filtering for required fields and checking for missing values.

        Input:
            df (pd.DataFrame): The input DataFrame.
            required_fields (list): A list of column names that are required.

        Returns:
            JsonResponse: A JsonResponse indicating success with the filtered DataFrame or an error message.
        """
        try:
            # Step 1: Filter the DataFrame to keep only the required columns
            try:
                required_fields_filtered = df[required_fields]
            except KeyError as e:
                missing_columns = set(required_fields) - set(df.columns)
                return JsonResponse({"error": f"Missing required columns: {', '.join(missing_columns)}"}, status=400)

            # Step 2: Check for missing values in the filtered DataFrame
            if required_fields_filtered.isnull().values.any():
                missing_value_count = required_fields_filtered.isnull().sum().sum()  # Count total missing values
                return JsonResponse(
                    {"error": f"Missing values found in required columns. Total missing: {missing_value_count}"},
                    status=400)  # Improved error message
            else:
                # Step 3: If no missing values, return the filtered DataFrame in a serializable format
                #  Important: Pandas DataFrame is not directly serializable to JSON.  Convert to a suitable format.
                result = df_filtered

            # Step 3 : Check for duplicate values in resulted data frame
            if unique_fields:
                if not self.check_duplicates_for_unique_field(result, unique_fields):
                    return JsonResponse(
                        {"error": f"Duplicates found in columns."},
                        status=400)

        except Exception as e:
            # Catch any other unexpected exceptions during the process
            return JsonResponse({"error": f"An unexpected error occurred: {str(e)}"},
                                status=500)  # More informative error

        # NEW: Handle CPT level processing vs original processing
        if is_cpt_level:
            processed_records_after_rules_applied = self.process_cpt_level_records(
                result, mapping_dict, project_id, selected_bin
            )
        else:
            # Original processing logic
            # preprocess rules
            project_rule = RulesAndTypes.objects.filter(project__id=project_id)
            if project_rule.count() > 0:
                serializer = RulesSerializer(project_rule, many=True)
                project_rule_data = serializer.data
                cleaned_rules = removeEmptyfields(project_rule_data)

                processor = ProcessData()

                try:
                    processed_records = processor.process_records(result, mapping_dict)

                    # If processed_records is a list, apply rules
                    if isinstance(processed_records, list):
                        rule_applier = RuleApplier(cleaned_rules, processed_records, project_id, selected_bin)
                        processed_records_after_rules_applied = rule_applier.apply_rules()
                    else:
                        if isinstance(processed_records, Exception):
                            return JsonResponse({'error': str(processed_records)}, status=400)
                        else:
                            return JsonResponse({'error': 'Unknown error occurred'}, status=400)

                except Exception as e:
                    return Response({'error': str(e)})

            else:
                return JsonResponse({'error': 'None of the Rules matched for selected Project'}, status=400)

        unique_field_values = self._get_unique_col_values_from_patient_records_model(unique_fields) if unique_fields else None
        unique_field_list = {k: v for d in unique_field_values for k, v in d.items()} if unique_field_values else {}

        if len(unique_field_list) > 0 and processed_records_after_rules_applied:
            df = pd.DataFrame(processed_records_after_rules_applied)
            key = next(iter(unique_field_list))
            value = unique_field_list[key]
            # Convert the DataFrame Column to String [due to model def)
            df[key] = df[key].astype(str)
            updating_filtered_values = df[df[key] == value]
            updating_filtered_values = updating_filtered_values.to_dict(orient='records')
            records_logs['updated_records_uploaded_count'] = len(df.index)

            # duplicate patient records check with unique_field [mandtory]
            duplicate_records_list = self._check_for_duplicate_entry_patient_records(key, processed_records_after_rules_applied)

            newly_adding_filtered_values = [
                record for record in processed_records_after_rules_applied
                # if str(record.get(key)) != str(value) and value not in duplicate_records_list
                if str(record.get(key)) != str(value) and str(record.get(key)) not in duplicate_records_list or value not in duplicate_records_list
            ]
        else:
            newly_adding_filtered_values = processed_records_after_rules_applied

        # create logs model object
        uploaded_file_name = file
        new_records_uploaded_count = 0
        updated_records_uploaded_count = 0
        failed_records_count = 0
        failed_records_data = []

        try:
            if len(unique_field_list) > 0 and updating_filtered_values:
                updated_records_uploaded_count, updated_records = self.update_records(
                    updating_filtered_values, project_id, organization_id, unique_field_list, upload_session_id
                )

            if newly_adding_filtered_values:
                new_records_uploaded_count, new_records = self.save_records(
                    newly_adding_filtered_values, project_id, organization_id, upload_session_id
                )

            # Create upload log with session ID
            upload_log = RecordsUploadLogs.objects.create(
                uploaded_file_name=uploaded_file_name,
                new_records_uploaded_count=new_records_uploaded_count,
                updated_records_uploaded_count=updated_records_uploaded_count,
                failed_records_count=failed_records_count,
                failed_records=failed_records_count > 0,
                upload_session_id=upload_session_id,
                project_id=project_id,
                organization_id=organization_id,
                failed_records_data=failed_records_data
            )

        except Exception as e:
            failed_records_count += 1
            failed_records_data.append({
                'error': str(e),
                'timestamp': timezone.now().isoformat()
            })
            return JsonResponse({"error": str(e)})

        return JsonResponse({"message": "File processed successfully"}, status=200)

    def process_cpt_level_records(self, df_filtered, mapping_dict, project_id, selected_bin):
        """
        NEW: Process records for CPT level functionality
        Groups records by common identifiers but keeps procedure codes separate
        """
        # Group records by common identifiers (mrn, patient_id, account_number, etc.)
        # but keep procedure_code variations as separate entries
        
        grouping_columns = ['mrn', 'patient_id', 'account_number', 'visit_number', 
                           'chart_number', 'service_date']
        
        # Filter only existing columns
        existing_grouping_cols = [col for col in grouping_columns if col in df_filtered.columns]
        
        if not existing_grouping_cols:
            # Fallback to original processing if no grouping columns found
            return self.process_original_records(df_filtered, mapping_dict, project_id, selected_bin)
        
        processed_records = []
        
        # Group by common identifiers
        grouped = df_filtered.groupby(existing_grouping_cols)
        
        for group_key, group_data in grouped:
            # Each group represents records with same patient/account info but different procedure codes
            group_records = group_data.to_dict('records')
            
            # Create a base record with common information
            base_record = group_records[0].copy()
            
            # Store procedure code variations
            procedure_codes = []
            for record in group_records:
                if 'procedure_code' in record and record['procedure_code']:
                    procedure_codes.append({
                        'procedure_code': record['procedure_code'],
                        'amount': record.get('amount', ''),
                        'procedure_count': record.get('procedure_count', ''),
                        # Add other procedure-specific fields
                    })
            
            # NEW: Store procedure variations in a special field
            base_record['cpt_procedures'] = procedure_codes
            base_record['is_cpt_grouped'] = True
            base_record['procedure_count_total'] = len(procedure_codes)
            
            # Keep the first procedure code as primary for compatibility
            if procedure_codes:
                base_record['procedure_code'] = procedure_codes[0]['procedure_code']
                base_record['amount'] = procedure_codes[0]['amount']
            
            processed_records.append(base_record)
        
        return processed_records

    def process_original_records(self, df_filtered, mapping_dict, project_id, selected_bin):
        """
        Fallback to original record processing
        """
        processor = ProcessData()
        processed_records = processor.process_records(df_filtered, mapping_dict)
        
        if isinstance(processed_records, list):
            project_rule = RulesAndTypes.objects.filter(project__id=project_id)
            if project_rule.count() > 0:
                serializer = RulesSerializer(project_rule, many=True)
                project_rule_data = serializer.data
                cleaned_rules = removeEmptyfields(project_rule_data)
                
                rule_applier = RuleApplier(cleaned_rules, processed_records, project_id, selected_bin)
                return rule_applier.apply_rules()
        
        return processed_records

    
    def is_valid_csv(self, file):
        """Validate that the file is a CSV"""
        file_extension = file.name.split('.')[-1].lower()
        return file_extension == 'csv'

    def _get_unique_col_values_from_patient_records_model(self, unique_fields_name_for_validation):
        return json.loads(json.dumps(list(PatientRecords.objects.all().values(*unique_fields_name_for_validation)), cls=DjangoJSONEncoder))

    def get_mapping_data(self, project_id, df):
        """Retrieve mapping data based on project_id and the CSV file"""
        try:
            # project_page = Projects.objects.get(id=project_id)
            mapping_data_instance = BillingSystemMappingRecord.objects.get(project=project_id) if project_id else None

            if mapping_data_instance:
                # Map columns based on the mapping data
                mapping_dict = mapColumns(mapping_data_instance, df.columns.tolist())
                return mapping_dict
        except Projects.DoesNotExist:
            logger.error(f"Projects with project_id {project_id} does not exist.")
            return None
        except MappingRecord.DoesNotExist:
            logger.error(f"MappingRecord for Projects with project_id {project_id} does not exist.")
            return None

    def check_duplicates_for_unique_field(self, df, columns):
        """
        Checks if there are duplicate values in specified columns of a Pandas DataFrame.

        Args:
            df (pd.DataFrame): The input DataFrame.
            columns (list): A list of column names to check for duplicates.

        Returns:
            bool: True if no duplicates are found in all specified columns,
                  False if duplicates are found in any of them.
                  Returns None if any of the columns don't exist.
        """
        # Check if all specified columns exist in the DataFrame
        for column in columns:
            if column not in df.columns:
                return None  # Indicate that one or more columns do not exist

        # Check for duplicates across the specified columns
        return not df.duplicated(subset=columns, keep=False).any()

    def _check_for_duplicate_entry_patient_records(self, key, records_to_filter):
        return [entry[key] for entry in records_to_filter]


    def get_mapping_required_and_unique_fields(self, project_id, key_to_filter):
        try:
            mapping_data_instance = BillingSystemMappingRecord.objects.get(project=project_id)if project_id else None
            unique_fields = set()  # Use a set to avoid duplicates
            # for record in mapping_data_instance:
            serialized_data = BillingSystemMappingSerializer(mapping_data_instance) if mapping_data_instance else None
            # Check if 'data' is a dictionary
            if isinstance(serialized_data.data, dict):
                for key, value in serialized_data.data.items():
                    # Check if 'unique' is true
                    if isinstance(value, dict) and value.get(key_to_filter):
                        field_value = 'mrn' if re.search(r"mrn", value.get('value'), re.IGNORECASE) else value.get('value')
                        unique_fields.add(field_value)

            return list(unique_fields)

        except Projects.DoesNotExist:
            logger.error(f"Projects with project_id {project_id} does not exist.")
            return None
        except MappingRecord.DoesNotExist:
            logger.error(f"MappingRecord for Projects with project_id {project_id} does not exist.")
            return None

    def process_csv(self, df, mapping_dict):
        decimal_field_to_validate = [
            'amount',
            'amount2',
            'amount3',
            'amount4',
            'total_charged',
            'insurance_balance',
            'patient_balance',
            'latest_pay_amount',
            'under_pay',
        ]

        date_field_to_validate = [
            'latest_action_date',
            'next_follow_up_before',
            'claim_denial_date',
            'claim_denial_code',
            'latest_pay_date',
            'last_claim_status_check_date',
            'last_ev_check_date',
            'last_ins_disc_check_date',
            'service_date',
        ]

        int_fields_list = [
            'procedure_count',
            'procedure_count2',
            'procedure_count3',
            'procedure_count4'
        ]
        try:
            # Check if DataFrame has columns
            if df.empty or not df.columns.any():
                return JsonResponse({"error": "No columns found in the CSV file."}, status=400)

            # Filter DataFrame to include only columns that are in the mapping dictionary
            filtered_columns = df[[col for col in df.columns if col in mapping_dict.keys()]]

            for col in filtered_columns.columns:
                if col in date_field_to_validate:
                    # Replace blank/empty date values with a default date, e.g., '1970-01-01'
                    filtered_columns[col] = filtered_columns[col].apply(
                        lambda x: datetime(1999, 1, 1) if pd.isnull(x) or str(x).strip() == "" else pd.to_datetime(x,
                                                                                                                   errors='coerce')
                    )
                # filtered_columns[col] = filtered_columns[col].fillna(datetime(1970, 1, 1))

                if col in decimal_field_to_validate:
                    # Replace blank/empty values with 0.0 for the decimal fields
                    filtered_columns[col] = filtered_columns[col].apply(
                        lambda x: Decimal('0.0') if pd.isnull(x) or str(x).strip() == "" else Decimal(str(x))
                    )

                if col in int_fields_list:
                    # Replace blank/empty values with 0.0 for the decimal fields
                    filtered_columns[col] = filtered_columns[col].apply(
                        lambda x: 0 if pd.isnull(x) or str(x).strip() == "" else 0
                    )
            return filtered_columns
        except Exception as e:
            return JsonResponse({"error": "An error occurred while processing the CSV file."}, status=500)

    def update_records(self, updating_filtered_values, project_id, organization_id, unique_field_list, upload_session_id):
        """
        Enhanced update_records method with tracking
        """
        try:
            updated_count = 0
            updated_records = []
            
            # Start a transaction for bulk updates
            with transaction.atomic():
                for record in updating_filtered_values:
                    try:
                        # Extract the unique identifier for the record
                        unique_key = next(iter(unique_field_list))
                        unique_value = unique_field_list[unique_key]

                        # Fetch the existing record from the database
                        patient_records = PatientRecords.objects.filter(**{unique_key: unique_value})

                        # Update fields from updating_filtered_values
                        for patient_rec in patient_records:
                            for key, value in record.items():
                                if key not in [unique_key]:  # Avoid overwriting the unique key
                                    setattr(patient_rec, key, value)

                            patient_rec.project_id = project_id
                            patient_rec.organization_id = organization_id
                            patient_rec.session_user = self.request.user
                            patient_rec.upload_session_id = upload_session_id  # Add session tracking

                            # Save the updated record
                            patient_rec.save()
                            updated_count += 1
                            updated_records.append(patient_rec)

                            # Create tracking record
                            if hasattr(self, 'create_tracking_record'):
                                self.create_tracking_record(upload_session_id, patient_rec, 'UPDATED')

                    except PatientRecords.DoesNotExist:
                        print(f"Record not found for update with {unique_key}: {unique_value}")
                        continue
                    except Exception as record_error:
                        print(f"Failed to update record: {record_error}")
                        continue

            return updated_count, updated_records

        except Exception as e:
            raise Exception(f"Error in update_records: {str(e)}")

    def create_tracking_record(self, upload_session_id, patient_record, action_type, error_message=None):
        """
        Create tracking record for individual record actions
        """
        try:
            # Get the upload log
            upload_log = RecordsUploadLogs.objects.filter(upload_session_id=upload_session_id).first()
            if upload_log:
                RecordUploadTracking.objects.create(
                    upload_log=upload_log,
                    patient_record=patient_record,
                    action_type=action_type,
                    error_message=error_message
                )
        except Exception as e:
            print(f"Failed to create tracking record: {e}")


    def save_records(self, processed_records, project_id, organization_id, upload_session_id):
        """
        Enhanced save_records method with tracking
        """
        try:
            created_count = 0
            created_records = []
            
            for record in processed_records:
                try:
                    # Add auto fields
                    record['project_id'] = project_id if project_id else ''
                    record['organization_id'] = organization_id if organization_id else ''
                    record['session_user'] = self.request.user
                    record['upload_session_id'] = upload_session_id  # Add session tracking

                    # Convert service_date if present
                    if 'service_date' in record and record['service_date']:
                        try:
                            if isinstance(record['service_date'], str):
                                service_date = datetime.strptime(record['service_date'], '%Y-%m-%d').date()
                                record['service_date'] = service_date
                        except ValueError as e:
                            # Handle invalid date format gracefully
                            record['service_date'] = datetime(1999, 1, 1).date()

                    # Save the record to the database
                    patient_record = PatientRecords(**record)
                    patient_record.save()
                    created_count += 1
                    created_records.append(patient_record)

                    # Create tracking record
                    if hasattr(self, 'create_tracking_record'):
                        self.create_tracking_record(upload_session_id, patient_record, 'NEW')

                except Exception as record_error:
                    # Log individual record failures
                    print(f"Failed to save record: {record_error}")
                    continue

            return created_count, created_records

        except Exception as e:
            raise Exception(f"Error in save_records: {str(e)}")



@method_decorator(login_required, name='dispatch')
class DownloadRecordsView(View):
    """
    Enhanced download view with proper record filtering
    """
    
    def get(self, request, log_id, record_type):
        # Get the upload log
        upload_log = get_object_or_404(RecordsUploadLogs, id=log_id)
        
        # Create CSV response
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="{record_type}_records_{log_id}.csv"'
        
        # Create CSV writer
        writer = csv.writer(response)
        
        # Get records based on type
        records = self.get_records_by_type(upload_log, record_type, request)
        
        if not records or not records.exists():
            writer.writerow(['No records found for this criteria'])
            return response
        
        # Write headers (using PatientRecords - the correct model name)
        headers = [field.name for field in PatientRecords._meta.fields]
        writer.writerow(headers)
        
        # Write data
        for record in records:
            row = []
            for field in PatientRecords._meta.fields:
                value = getattr(record, field.name)
                if value is None:
                    row.append('')
                elif hasattr(value, 'strftime'):  # Date/DateTime fields
                    if hasattr(value, 'hour'):  # DateTime
                        row.append(value.strftime('%Y-%m-%d %H:%M:%S'))
                    else:  # Date
                        row.append(value.strftime('%Y-%m-%d'))
                elif isinstance(value, bool):
                    row.append('True' if value else 'False')
                elif isinstance(value, (dict, list)):  # JSONField
                    row.append(str(value))
                else:
                    row.append(str(value))
            writer.writerow(row)
        
        return response
    def get_base_records_query(self, upload_log, request):
        """
        Get base query for records related to this upload log
        Uses project_id and organization_id to match records
        """
        # Get project_id from session or upload_log
        project_id = request.session.get('project_id') or upload_log.project_id
        organization_id = request.session.get('organization_id') or upload_log.organization_id
        
        # Base query using project_id and organization_id (using PatientRecords - correct model name)
        base_query = PatientRecords.objects.all()
        
        if project_id:
            base_query = base_query.filter(project_id=project_id)
        
        if organization_id:
            base_query = base_query.filter(organization_id=organization_id)
            
        # If upload_log has timestamps, we can also filter by date range
        if hasattr(upload_log, 'created_at') and upload_log.created_at:
            # Get records created around the same time as the upload
            from datetime import timedelta
            start_time = upload_log.created_at - timedelta(hours=1)
            end_time = upload_log.created_at + timedelta(hours=1)
            
            # If PatientRecords has created_at field, use it
            if hasattr(PatientRecords, 'created_at'):
                base_query = base_query.filter(
                    created_at__gte=start_time,
                    created_at__lte=end_time
                )
            # Otherwise, you might need to use service_date or another date field
            # base_query = base_query.filter(service_date=upload_log.created_at.date())
        
        return base_query
    
    def get_records_by_type(self, upload_log, record_type, request):
        """
        Get records based on type and upload log
        """
        base_query = self.get_base_records_query(upload_log, request)
        
        if record_type == 'all':
            return base_query
            
        elif record_type == 'new':
            # Get new records - you might want to use allocation_fresh=True
            # or check if there's a RecordUploadTracking model
            try:
                # Try to get tracked new records if tracking model exists
                tracked_new_records = RecordUploadTracking.objects.filter(
                    upload_log=upload_log,
                    action_type='NEW'
                ).values_list('patient_record_id', flat=True)
                return base_query.filter(id__in=tracked_new_records)
            except:
                # Fallback to using allocation_fresh flag
                return base_query.filter(allocation_fresh=True)
                
        elif record_type == 'updated':
            # Get updated records
            try:
                # Try to get tracked updated records if tracking model exists
                tracked_updated_records = RecordUploadTracking.objects.filter(
                    upload_log=upload_log,
                    action_type='UPDATED'
                ).values_list('patient_record_id', flat=True)
                return base_query.filter(id__in=tracked_updated_records)
            except:
                # Fallback to using allocation flags
                return base_query.filter(
                    allocation_fresh=False,
                    allocation_allocated=True
                )
                
        elif record_type == 'failed':
            # Get failed records from upload_log.failed_records_data if available
            if upload_log.failed_records and upload_log.failed_records_data:
                # If failed_records_data contains record IDs
                failed_ids = []
                if isinstance(upload_log.failed_records_data, dict):
                    # Extract IDs from failed records data
                    failed_ids = upload_log.failed_records_data.get('record_ids', [])
                elif isinstance(upload_log.failed_records_data, list):
                    failed_ids = upload_log.failed_records_data
                
                if failed_ids:
                    return base_query.filter(id__in=failed_ids)
                    
            # Try tracking model approach
            try:
                tracked_failed_records = RecordUploadTracking.objects.filter(
                    upload_log=upload_log,
                    action_type='FAILED'
                ).values_list('patient_record_id', flat=True)
                return base_query.filter(id__in=tracked_failed_records)
            except:
                # Return empty queryset if no failed records tracking
                return PatientRecords.objects.none()
                
        else:
            return PatientRecords.objects.none()


@login_required
def download_records_view(request, log_id, record_type):
    """
    Function-based view alternative
    """
    upload_log = get_object_or_404(RecordsUploadLogs, id=log_id)
    
    # Create CSV response
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{record_type}_records_{log_id}.csv"'
    
    writer = csv.writer(response)
    
    # Get project_id from session or upload_log
    project_id = request.session.get('project_id') or upload_log.project_id
    organization_id = request.session.get('organization_id') or upload_log.organization_id
    
    # Base filter
    base_filter = {}
    if project_id:
        base_filter['project_id'] = project_id
    if organization_id:
        base_filter['organization_id'] = organization_id
    
    # Based on record type, get appropriate records (using PatientRecords - correct model name)
    if record_type == 'all':
        records = PatientRecords.objects.filter(**base_filter)
        
    elif record_type == 'new':
        records = PatientRecords.objects.filter(
            **base_filter,
            allocation_fresh=True
        )
        
    elif record_type == 'updated':
        records = PatientRecords.objects.filter(
            **base_filter,
            allocation_fresh=False,
            allocation_allocated=True
        )
        
    elif record_type == 'failed':
        # Handle failed records based on upload_log.failed_records_data
        if upload_log.failed_records and upload_log.failed_records_data:
            failed_ids = []
            if isinstance(upload_log.failed_records_data, dict):
                failed_ids = upload_log.failed_records_data.get('record_ids', [])
            elif isinstance(upload_log.failed_records_data, list):
                failed_ids = upload_log.failed_records_data
                
            if failed_ids:
                records = PatientRecords.objects.filter(id__in=failed_ids, **base_filter)
            else:
                records = PatientRecords.objects.none()
        else:
            records = PatientRecords.objects.none()
            
    else:
        return HttpResponse("Invalid record type", status=400)
    
    if records.exists():
        # Write headers (using PatientRecords - correct model name)
        headers = [field.name for field in PatientRecords._meta.fields]
        writer.writerow(headers)
        
        # Write data
        for record in records:
            row = []
            for field in PatientRecords._meta.fields:
                value = getattr(record, field.name)
                if value is None:
                    row.append('')
                elif hasattr(value, 'strftime'):
                    row.append(value.strftime('%Y-%m-%d %H:%M:%S') if hasattr(value, 'hour') else value.strftime('%Y-%m-%d'))
                elif isinstance(value, (dict, list)):  # JSONField
                    row.append(str(value))
                else:
                    row.append(str(value))
            writer.writerow(row)
    else:
        writer.writerow(['No records found'])
    
    return response
"""=====================================================================remove===================================================================="""
@csrf_exempt
def upload_csv(request):
    if request.method == 'POST':
        if 'file' in request.FILES:
            file = request.FILES['file']
            project_id = 'QEEA' 
            organization_id = 'JWGY' 
            selected_bin = 'AR'  
            
            if file.name.endswith('.csv'):
                # Read the file into a DataFrame
                df = pd.read_csv(file)
                # print('df', df)
                df.columns = df.columns.str.strip()
                
                # Retrieve mapping data
                try:
                    project_page = Projects.objects.get(project_id=project_id)
                    print('project--',project_page)
                    if project_page.billing_system.id:
                        mapping_data = MappingRecord.objects.get(id=project_page.billing_system.id)
                        if mapping_data:
                            mapping_dict = {
                                'input_source': mapping_data.input_source.get('value', ''),
                                'mrn': mapping_data.mrn.get('value', ''),
                                'patient_id': mapping_data.patient_id.get('value', ''),
                                'account_number': mapping_data.account_number.get('value', ''),
                                'visit_number': mapping_data.visit_number.get('value', ''),
                                'chart_number': mapping_data.chart_number.get('value', ''),
                                'project_key': mapping_data.project_key.get('value', ''),
                                'facility': mapping_data.facility.get('value', ''),
                                'facility_type': mapping_data.facility_type.get('value', ''),
                                'patient_last_name': mapping_data.patient_last_name.get('value', ''),
                                'patient_first_name': mapping_data.patient_first_name.get('value', ''),
                                'patient_phone': mapping_data.patient_phone.get('value', ''),
                                'patient_address': mapping_data.patient_address.get('value', ''),
                                'patient_city': mapping_data.patient_city.get('value', ''),
                                'patient_state': mapping_data.patient_state.get('value', ''),
                                'patient_zip': mapping_data.patient_zip.get('value', ''),
                                'patient_birthday': mapping_data.patient_birthday.get('value', ''),
                                'patient_gender': mapping_data.patient_gender.get('value', ''),
                                'subscriber_last_name': mapping_data.subscriber_last_name.get('value', ''),
                                'subscriber_first_name': mapping_data.subscriber_first_name.get('value', ''),
                                'subscriber_relationship': mapping_data.subscriber_relationship.get('value', ''),
                                'subscriber_phone': mapping_data.subscriber_phone.get('value', ''),
                                'subscriber_address': mapping_data.subscriber_address.get('value', ''),
                                'subscriber_city': mapping_data.subscriber_city.get('value', ''),
                                'subscriber_state': mapping_data.subscriber_state.get('value', ''),
                                'subscriber_zip': mapping_data.subscriber_zip.get('value', ''),
                                'subscriber_birthday': mapping_data.subscriber_birthday.get('value', ''),
                                'subscriber_gender': mapping_data.subscriber_gender.get('value', ''),
                                'current_billed_financial_class': mapping_data.current_billed_financial_class.get('value', ''),
                                'current_billed_payer_name': mapping_data.current_billed_payer_name.get('value', ''),
                                'member_id_current_billed_payer': mapping_data.member_id_current_billed_payer.get('value', ''),
                                'group_number_current_billed_payer': mapping_data.group_number_current_billed_payer.get('value', ''),
                                'current_billed_relationship': mapping_data.current_billed_relationship.get('value', ''),
                                'cob': mapping_data.cob.get('value', ''),
                                'payer_id_current_billed_payer': mapping_data.payer_id_current_billed_payer.get('value', ''),
                                'timely_filing_limit': mapping_data.timely_filing_limit.get('value', ''),
                                'appeal_limit': mapping_data.appeal_limit.get('value', ''),
                                'primary_payer_financial_class': mapping_data.primary_payer_financial_class.get('value', ''),
                                'primary_payer_name': mapping_data.primary_payer_name.get('value', ''),
                                'member_id_primary_payer': mapping_data.member_id_primary_payer.get('value', ''),
                                'group_number_primary_payer': mapping_data.group_number_primary_payer.get('value', ''),
                                'relationship_primary_payer': mapping_data.relationship_primary_payer.get('value', ''),
                                'cob_primary': mapping_data.cob_primary.get('value', ''),
                                'payer_id_primary_payer': mapping_data.payer_id_primary_payer.get('value', ''),
                                'secondary_payer_financial_class': mapping_data.secondary_payer_financial_class.get('value', ''),
                                'secondary_payer_name': mapping_data.secondary_payer_name.get('value', ''),
                                'member_id_secondary_payer': mapping_data.member_id_secondary_payer.get('value', ''),
                                'group_number_secondary_payer': mapping_data.group_number_secondary_payer.get('value', ''),
                                'relationship_secondary_payer': mapping_data.relationship_secondary_payer.get('value', ''),
                                'cob_secondary': mapping_data.cob_secondary.get('value', ''),
                                'payer_id_secondary_payer': mapping_data.payer_id_secondary_payer.get('value', ''),
                                'tertiary_payer_financial_class': mapping_data.tertiary_payer_financial_class.get('value', ''),
                                'tertiary_payer_name': mapping_data.tertiary_payer_name.get('value', ''),
                                'member_id_tertiary_payer': mapping_data.member_id_tertiary_payer.get('value', ''),
                                'group_number_tertiary_payer': mapping_data.group_number_tertiary_payer.get('value', ''),
                                'relationship_tertiary_payer': mapping_data.relationship_tertiary_payer.get('value', ''),
                                'cob_tertiary': mapping_data.cob_tertiary.get('value', ''),
                                'payer_id_tertiary_payer': mapping_data.payer_id_tertiary_payer.get('value', ''),
                                'auth_number': mapping_data.auth_number.get('value', ''),
                                'claim_number': mapping_data.claim_number.get('value', ''),
                                'facility_code': mapping_data.facility_code.get('value', ''),
                                'claim_frequency_type': mapping_data.claim_frequency_type.get('value', ''),
                                'signature': mapping_data.signature.get('value', ''),
                                'assignment_code': mapping_data.assignment_code.get('value', ''),
                                'assign_certification': mapping_data.assign_certification.get('value', ''),
                                'release_info_code': mapping_data.release_info_code.get('value', ''),
                                'service_date': mapping_data.service_date.get('value', ''),
                                'van_trace_number': mapping_data.van_trace_number.get('value', ''),
                                'rendering_provider_id': mapping_data.rendering_provider_id.get('value', ''),
                                'taxonomy_code': mapping_data.taxonomy_code.get('value', ''),
                                'procedure_code': mapping_data.procedure_code.get('value', ''),
                                'amount': mapping_data.amount.get('value', ''),
                                'procedure_count': mapping_data.procedure_count.get('value', ''),
                                'tooth_code': mapping_data.tooth_code.get('value', ''),
                                'procedure_code2': mapping_data.procedure_code2.get('value', ''),
                                'amount2': mapping_data.amount2.get('value', ''),
                                'procedure_count2': mapping_data.procedure_count2.get('value', ''),
                                'tooth_code2': mapping_data.tooth_code2.get('value', ''),
                                'procedure_code3': mapping_data.procedure_code3.get('value', ''),
                                'amount3': mapping_data.amount3.get('value', ''),
                                'procedure_count3': mapping_data.procedure_count3.get('value', ''),
                                'tooth_code3': mapping_data.tooth_code3.get('value', ''),
                                'procedure_code4': mapping_data.procedure_code4.get('value', ''),
                                'amount4': mapping_data.amount4.get('value', ''),
                                'procedure_count4': mapping_data.procedure_count4.get('value', ''),
                                'tooth_code4': mapping_data.tooth_code4.get('value', ''),
                                'dx1': mapping_data.dx1.get('value', ''),
                                'dx2': mapping_data.dx2.get('value', ''),
                                'dx3': mapping_data.dx3.get('value', ''),
                                'dx4': mapping_data.dx4.get('value', ''),
                                'dx5': mapping_data.dx5.get('value', ''),
                                'dx6': mapping_data.dx6.get('value', ''),
                                'total_charged': mapping_data.total_charged.get('value', ''),
                                'check_number': mapping_data.check_number.get('value', ''),
                                'insurance_balance': mapping_data.insurance_balance.get('value', ''),
                                'patient_balance': mapping_data.patient_balance.get('value', ''),
                                'contract_name': mapping_data.contract_name.get('value', ''),
                                'division': mapping_data.division.get('value', ''),
                                'type_of_service': mapping_data.type_of_service.get('value', ''),
                                'current_queue': mapping_data.current_queue.get('value', ''),
                                'queue_days': mapping_data.queue_days.get('value', ''),
                                'lates_action_date': mapping_data.lates_action_date.get('value', ''),
                                'next_follow_up_before': mapping_data.next_follow_up_before.get('value', ''),
                                'claim_denial_date': mapping_data.claim_denial_date.get('value', ''),
                                'latest_pay_date': mapping_data.latest_pay_date.get('value', ''),
                                'latest_pay_amount': mapping_data.latest_pay_amount.get('value', ''),
                                # 'insurance_payment_date': mapping_data.insurance_payment_date.get('value', ''),
                                # 'insurance_payment_amount': mapping_data.insurance_payment_amount.get('value', ''),
                                # 'patient_payment_date': mapping_data.patient_payment_date.get('value', ''),
                                # 'patient_payment_amount': mapping_data.patient_payment_amount.get('value', ''),
                                # 'balance_before_appeal': mapping_data.balance_before_appeal.get('value', ''),
                                # 'balance_after_appeal': mapping_data.balance_after_appeal.get('value', ''),
                                # 'appeal_sent_date': mapping_data.appeal_sent_date.get('value', ''),
                                'under_pay': mapping_data.under_pay.get('value', ''),
                                'last_ins_disc_check_date': mapping_data.last_ins_disc_check_date.get('value', ''),
                                'last_ev_check_date': mapping_data.last_ev_check_date.get('value', ''),
                                'claim_priority': mapping_data.claim_priority.get('value', ''),
                                'category': mapping_data.category.get('value', ''),
                                'sub_category': mapping_data.sub_category.get('value', ''),
                                'status': mapping_data.status.get('value', ''),
                                'action': mapping_data.action.get('value', ''),
                                'provider_name': mapping_data.provider_name.get('value', ''),
                                'provider_npi': mapping_data.provider_npi.get('value', ''),
                                'provider_location': mapping_data.provider_location.get('value', ''),
                                'assigned_to': mapping_data.assigned_to.get('value', ''),
                                'last_claim_status_check_date': mapping_data.last_claim_status_check_date.get('value', ''),
                                
                            }
                        else:
                            return JsonResponse({"error": "Mapping data not found"}, status=400)
                    else:
                        return JsonResponse({"error": "Project does not have a valid billing system"}, status=400)
                except Projects.DoesNotExist:
                    return JsonResponse({"error": "Project not found"}, status=400)
                except MappingRecord.DoesNotExist:
                    return JsonResponse({"error": "Mapping record not found"}, status=400)

                # Map headers based on mapping_dict
                mapped_columns = {value: key for key, value in mapping_dict.items() if value}

                # print("Mapped Columns:", mapped_columns)
                filtered_columns = [col for col in mapping_dict.values() if col in df.columns]
                

                # print("filtered_columns--", filtered_columns)
                # Filter DataFrame to only include the mapped columns
                df_filtered = df[filtered_columns]
                
                # print(df_filtered.columns)

                # print('df_filtred', df_filtered)
                # Process DataFrame and save records
                records = []

                shows_data = []
                print('*****************************'*3)
                print('*****************************' * 3)

                # Filter ViewRules1 objects based on the project_id
                project_rule = ViewRules1.objects.filter(projects__icontains=f'"{project_id}"')

                print("project_rule--", project_rule)

                # Serialize the data
                serializer = ViewRules1Serializer(project_rule, many=True)
                project_rule_data = serializer.data

                # print("project_rule_data--", project_rule_data)

                # Parsing the nested fields that are stored as JSON strings


                for rule in project_rule_data:
                    rule['text_search_fields'] = json.loads(rule['text_search_fields'])
                    rule['range_filters'] = json.loads(rule['range_filters'])
                    rule['action'] = json.loads(rule['action'])
                    rule['rule_target'] = json.loads(rule['rule_target'])
                    rule['projects'] = json.loads(rule['projects'])

                # Apply the function to remove empty fields
                
                filtered_project_rule_data = []
                # Optional: Convert the cleaned-up nested fields back to JSON strings if needed
                # for rule in filtered_project_rule_data:
                #     rule['text_search_fields'] = json.dumps(rule['text_search_fields'])
                #     rule['range_filters'] = json.dumps(rule['range_filters'])

                print("filtered_project_rule_data--1--", filtered_project_rule_data)

                for each in filtered_project_rule_data:
                    # Remove keys from each dictionary safely
                    each.pop('view_id', None)
                    each.pop('rule_name', None)
                    each.pop('deptartment', None)
                    each.pop('approvals', None)
                    each.pop('projects', None)
                    each.pop('created_by', None)
                    each.pop('created_at', None)
                    each.pop('rule_category', None)
                    each.pop('rule_status', None)
                    each.pop('approval_status', None)
                    each.pop('rule_target', None)
                    
                
                print("filtered_project_rule_data--2--", filtered_project_rule_data)

                print('*****************************'*3)

                for _, row in df_filtered.iterrows():
                    record = {key: row[val] for key, val in mapping_dict.items() if val in df_filtered.columns}

                    print('**********uploaded-record**********************')
                    print(record)
                    print('**********uploaded-record**********************')


                    today_date = date.today() 


                    service_date_str = record['service_date']


                    

                    print("service_date_str--", service_date_str)   
                    # Convert to datetime.date
                    service_date = parse_service_date(service_date_str)
                    ########Ageing_Bucket_Mapping###########
                    ageing_bucket_days = (today_date - service_date).days
                    ageing_bucket = ("0-30" if ageing_bucket_days <= 30 else
                                    "31-60" if ageing_bucket_days <= 60 else
                                    "61-90" if ageing_bucket_days <= 90 else
                                    "91-180" if ageing_bucket_days <= 180 else
                                    "181-360" if ageing_bucket_days <= 360 else
                                    "360 and above")

                    record['ageing_bucket'] = ageing_bucket  # Calculate the difference

                    ############################################

                    

                    print("record--", type(record))
                    print("filtered_project_rule_data--",type(filtered_project_rule_data))

                    match = ''
                    if match == 1:
                        print('##################RECORD MATCHES THE RULE#########################')

                        data_section = filtered_project_rule_data.get('action', '[]')

                        if data_section:
                            data_target = list(data_section[0].keys())
                            if data_target:
                                if data_target[0] == 'review':

                                    
                                    # Access bins and users safely
                                    bins = data_section[0]['review'].get('bins', [])
                                    users = data_section[0]['review'].get('users', [])
                                    
                                    print('bins--',bins)
                                    print('users--',users)
                                    # Get the first bin and first user, if they exist
                                    data_distribute = bins[0] if bins else None
                                    user = users[0] if users else None
                                    
                                    print(f'Data Distribute: {data_distribute}')
                                    print(f'User: {user}')

                                    record['review_status'] = 1
                                    record['review_by'] = {data_distribute: user}

                                elif data_target[0] == 'move':

                                    # Access bins and users safely
                                    bins = data_section[0]['move'].get('bins', [])
                                    tabs = data_section[0]['move'].get('tab', "")
                                    
                                    # Get the first bin and first user, if they exist
                                    data_distribute = bins[0].title() if bins else None
                                    tab = tabs if tabs else None

                                    
                                    print(f'Data Distribute: {data_distribute}')
                                    print(f'tabs: {tab}')
                                    record['allocation_status']= 1
                                    record['allocated_to'] = {data_distribute: tab}

                                else:
                                    print(data_section[0]) #dict
                                    if data_section[0].get("holdQ").get("holdq"):
                                        duration = data_section[0].get("holdQ").get("holdq")
                                        print(f"data was {data_target} -- {duration}")

                                        record['hold_status'] = 1
                                        record['hold'] = {'duration': duration}
                                    else:
                                        ageing_days = data_section[0].get("holdQ").get("ageing_bucket")

                                        print("ageing_bucket_days---", ageing_bucket_days)
                                        if ageing_bucket_days < int(ageing_days):
                                            record['hold_status'] = 1
                                            record['hold'] = {'duration': ageing_days}
                                        else:
                                            data_section = filtered_project_rule_data[0].get('action', '[]')

                                            if data_section:
                                                data_target = list(data_section[0].keys())
                                                if data_target:
                                                    if data_target[0] == 'review':

                                                        
                                                        # Access bins and users safely
                                                        bins = selected_bin
                                                        tab = 'fresh'
                                                    

                                                        record['allocation_status'] = 1
                                                        record['allocated_to'] = {bins: tab}

                                                    elif data_target[0] == 'move':

                                                        # Access bins and users safely
                                                        bins = selected_bin
                                                        tabs = 'fresh'
                                                    
                                                        record['allocation_status']= 1
                                                        record['allocated_to'] = {bins: tabs}

                                                    else:
                                                        

                                                        record['allocation_status'] = 1
                                                        record['allocated_to'] = {selected_bin: 'fresh'}



                        print('###########################################')
                    else:
                        print('******RECORD DOES NOT MATCH THE RULE*******')

                        data_section = filtered_project_rule_data[0].get('action', '[]')
                        print('data--',data_section)
                        print(data_section[0].keys())
                        if data_section:
                            data_target = list(data_section[0].keys())
                            if data_target:
                                if data_target[0] == 'review':

                                    
                                    # Access bins and users safely
                                    bins = selected_bin
                                    tab = 'fresh'
                                    record['allocation_status'] = 1
                                    record['allocated_to'] = {bins: tab}

                                elif data_target[0] == 'move':

                                    # Access bins and users safely
                                    bins = selected_bin
                                    tabs = 'fresh'
                                    # print('bins--',bins)
                                    # print('tab--',tabs)
                                   
                                    record['allocation_status']= 1
                                    record['allocated_to'] = {bins: tabs}
                                    print(record)

                                else:
                                    

                                    record['allocation_status'] = 1
                                    record['allocated_to'] = {selected_bin: 'fresh'}






                    

                    
                    # Assume today_date is the current date
                    today_date = date.today() 
                    service_date_str = record['service_date']

                    print("service_date_str--", service_date_str)   
                    # Convert to datetime.date
                    service_date = service_date = parse_service_date(service_date_str)

                    #

                    record['project_id'] = project_id
                    record['organization_id']= organization_id
                    record['allocation_fresh'] = int(1)
                    
                    show_data = {val: row[val] for key, val in mapping_dict.items() if val in df_filtered.columns}
                    shows_data.append(show_data)
                    records.append(record)
                

               
                
                for record_data in records:
                    record_data['service_date'] = parse_and_format_date(record_data['service_date'])
                   
                    # Create a new PatientRecords instance
                    patient_record = PatientRecords(**record_data)

                    
                    
                    # Save the instance to the database
                    patient_record.save()
                
                return JsonResponse({"message": "File processed successfully"})
            else:
                return JsonResponse({"error": "Invalid file format. Only CSV files are supported."}, status=400)
        else:
            return JsonResponse({"error": "No file provided"}, status=400)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=405)

"""=====================================================================remove end===================================================================="""

@csrf_exempt
@require_http_methods(["GET", "POST"])
def credentials_manage(request):
    if request.method == 'GET':
        sector_id = request.GET.get('sector_id')
        user_id = request.GET.get('user_id')
        
        print('section id--1--',sector_id)
        print('user id--', user_id)

        # print("user_id---", user_id, type(user_id))


    if request.method == 'POST':
        data = json.loads(request.body)
        action = data.get('action')
        pk = data.get('pk')
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        email = data.get('email')
        password = data.get('password')
        department_id = data.get('department_id')
        project_ids = data.get('project_ids')  # This should be a list of project IDs

        client_id = data.get('client_id')
        role_id = data.get('role_id')
        sector_id = data.get('sector_id')  
        print('section id--2--',sector_id)
        stake_id = data.get('stake_id')
        app_id = data.get('app_id')

        department = DeptartmentPage.objects.filter(deptartment_id=department_id).first() if department_id else None
        projects = ProjectPage.objects.filter(project_id__in=project_ids) if project_ids else []
        client = ClientPage.objects.filter(client_id=client_id).first() if client_id else None
        role = RolesPage.objects.filter(role_id=role_id).first() if role_id else None
        sector = SectorPage.objects.filter(sector_id=sector_id).first() if sector_id else None
        stake = StakePage.objects.filter(stake_id=stake_id).first() if stake_id else None
        app = AppsPage.objects.filter(app_id=app_id).first() if app_id else None

        if action == 'create':
            CredentialsForm.objects.create(
                first_name=first_name,
                last_name=last_name,
                email=email,
                password=password,
                department=department,
                projects=project_ids,  # Store project IDs as JSON
                client=client,
                role=role,
                sector=sector,
                stake=stake,
                app=app,
            )
        elif action == "edit":

            credential = CredentialsForm.objects.get(id=pk)
            credential.first_name = first_name
            credential.last_name = last_name
            credential.email = email
            credential.password = password
            credential.department = department
            credential.projects = project_ids  # Update project IDs
            credential.client = client
            credential.role = role
            credential.sector = sector
            credential.stake = stake
            credential.app = app
            credential.save()
        elif action == 'delete':
            CredentialsForm.objects.get(id=pk).delete()

        return JsonResponse({'status': 'success'})

    if user_id and int(user_id) != 45:
    
        credentials = CredentialsForm.objects.filter(sector_id=sector_id).prefetch_related(
            'department', 'client', 'role', 'sector', 'stake', 'app'
        ).values(
            'id', 'first_name', 'last_name', 'email', 'password',
            'department__department_name',
            'projects',  # Raw JSON field
            'client__client_name', 'role__role_name', 'sector__sector_name',
            'stake__stake_name', 'app__app_name'
        )
    else:
        credentials = CredentialsForm.objects.all().prefetch_related(
            'department', 'client', 'role', 'sector', 'stake', 'app'
        ).values(
            'id', 'first_name', 'last_name', 'email', 'password',
            'department__department_name',
            'projects',  # Raw JSON field
            'client__client_name', 'role__role_name', 'sector__sector_name',
            'stake__stake_name', 'app__app_name'
        )


    # Convert project IDs to names
    for credential in credentials:
        project_ids = credential.get('projects', [])
        projects = ProjectPage.objects.filter(project_id__in=project_ids).values_list('project_name', flat=True)
        credential['projects'] = list(projects)
    

    departments = DeptartmentPage.objects.filter(organization_id=sector_id).values('deptartment_id', 'department_name')
    projects = ProjectPage.objects.filter(organization_id=sector_id).values('project_id', 'project_name')
    clients = ClientPage.objects.filter(organization_id=sector_id).values('client_id', 'client_name', 'sector_id')
    roles = RolesPage.objects.filter(organization_id=sector_id).values('role_id', 'role_name')
    sectors = SectorPage.objects.filter(sector_id=sector_id).values('sector_id', 'sector_name')
    stakes = StakePage.objects.all().values('stake_id', 'stake_name')
    apps = AppsPage.objects.filter(organization_id =sector_id).values('app_id', 'app_name')
    
    return JsonResponse({
        'credentials': list(credentials),
        'departments': list(departments),
        'projects': list(projects),
        'clients': list(clients),
        'roles': list(roles),
        'sectors': list(sectors),
        'stakes': list(stakes),
        'apps': list(apps)
    })

class ManageCredentialsView(generics.ListCreateAPIView, generics.RetrieveUpdateDestroyAPIView):
    queryset = UserCredentials.objects.all()
    serializer_class = CreateUserSerializers
    permission_classes = (permissions.AllowAny,)
    # lookup_field = 'employee_id'
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    departments = DeptartmentPage.objects.all().values('deptartment_id', 'department_name')
    projects = ProjectPage.objects.all().values('project_id', 'project_name')
    clients = ClientPage.objects.all().values('client_id', 'client_name')
    roles = RolesPage.objects.all().values('role_id', 'role_name')
    sectors = SectorPage.objects.all().values('sector_id', 'sector_name')
    stakes = StakePage.objects.all().values('stake_id', 'stake_name')
    apps = AppsPage.objects.all().values('app_id', 'app_name')


    def get(self, request, *args, **kwargs):
        if 'pk' in kwargs:
            return self.retrieve(request, *args, **kwargs)
        credentials = self.list(request, *args, **kwargs).data
        return JsonResponse({
            'credentials': list(credentials),
            'departments': list(self.departments),
            'projects': list(self.projects),
            'clients': list(self.clients),
            'roles': list(self.roles),
            'sectors': list(self.sectors),
            'stakes': list(self.stakes),
            'apps': list(self.apps)
        })

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        return self.destroy(request, *args, **kwargs)


def success_view(request):
    return render(request, 'success.html')


class PatientRecordListView(APIView):
    def get(self, request):
        paginator = PageNumberPagination()
        paginator.page_size = 10
        records = PatientRecords.objects.all()
        result_page = paginator.paginate_queryset(records, request)
        serializer = PatientRecordSerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)


class PatientRecordDetailView(APIView):
    def get(self, request, pk):
        try:
            record = PatientRecords.objects.get(pk=pk)
        except PatientRecords.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        serializer = PatientRecordSerializer(record)
        return Response(serializer.data)

class UserCredentialViewSet(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

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
        Get the queryset of UserCredentials for the authenticated user.
        """
        user = self.get_user_from_session()

        if user:
            # Fetching the user credentials along with related fields
            user_credentials = UserCredentials.objects.filter(email=user.email)

            if user_credentials.exists():
                return user_credentials

        return UserCredentials.objects.none()   # Return empty if no credentials are found or user not authenticated

    def get(self, request, *args, **kwargs):
        """
        Handle the GET request and return the user credentials.
        """
        queryset = self.get_queryset()

        if not queryset:
            return Response({
                'status': 'error',
                'message': 'User credentials not found'
            }, status=status.HTTP_404_NOT_FOUND)

        serializer = UserCredentialsSerializer(queryset, many=True)

        return Response({
            'status': 'success',
            'data': serializer.data
        }, status=status.HTTP_200_OK)

@require_http_methods(["GET"])
def check_auth(request):
    pass
    return JsonResponse({'isAuthenticated': True})

    # if request.user.is_authenticated:
    #     return JsonResponse({'isAuthenticated': True})
    # return JsonResponse({'isAuthenticated': False})


class GetCreateDepratmentView(generics.ListCreateAPIView):
    queryset = DeptartmentPage.objects.all()
    serializer_class = DeptartmentPageSerializer
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

class ManageDepartmentView(generics.RetrieveUpdateDestroyAPIView):
    queryset = DeptartmentPage.objects.all()
    serializer_class = DeptartmentPageSerializer
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)


# @csrf_exempt
@require_http_methods(["GET", "POST"])
def department_manage(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        action = data.get('action')
        pk = data.get('pk')
        name = data.get('department_name')

        if action == 'create':
            sector_id = data.get('sector_id')
            DeptartmentPage.objects.create(department_name=name, organization_id=sector_id)
        elif action == 'update':
            department = DeptartmentPage.objects.get(deptartment_id=pk)
            department.department_name = name
            department.save()
        elif action == 'delete':
            DeptartmentPage.objects.filter(deptartment_id=pk).delete()

        return JsonResponse({'status': 'success'})

    elif request.method == 'GET':
        sector_id = request.GET.get('sector_id')
        user_id = request.GET.get('user_id')
        print("sector_id", sector_id)
        print("user_id", user_id)
        if user_id != '45':
            departments = DeptartmentPage.objects.filter(organization_id=sector_id).values('deptartment_id', 'department_name')
        else:
            departments = DeptartmentPage.objects.all().values('deptartment_id', 'department_name')
    return JsonResponse({'departments': list(departments)})


class GetCreateRolesView(generics.ListCreateAPIView):
    queryset = RolesPage.objects.all()
    serializer_class = RolesPageSerializer
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

class RetriveUpdateDeleteRolesView(generics.RetrieveUpdateDestroyAPIView):
    queryset = RolesPage.objects.all()
    serializer_class = RolesPageSerializer
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

# Roles Views
@csrf_exempt
@require_http_methods(["GET", "POST"])
def roles_manage(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        action = data.get('action')
        pk = data.get('pk')
        name = data.get('role_name')
        screens = data.get('screens', [])  # Expecting a list of screens
        
        if action == 'create':

            sector_id = data.get('sector_id')
            # Create a new role with provided name and screens
            role = RolesPage.objects.create(
                role_name=name,
                screens=screens,  # Directly set the list of screens
                organization_id=sector_id
            )
        elif action == 'update':
            # Update an existing role
            role = RolesPage.objects.get(role_id=pk)
            role.role_name = name
            role.screens = screens  # Update the list of screens
            print('role name--',role.role_name)
            print('role screens--', role.screens)
            role.save()
        elif action == 'delete':
            # Delete a role by primary key
            RolesPage.objects.filter(role_id=pk).delete()
        else:
            return JsonResponse({'status': 'error', 'message': 'Invalid action'}, status=400)

        return JsonResponse({'status': 'success'})
    
    elif request.method == 'GET':
        page_number = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 10))
        sector_id = request.GET.get('sector_id')
        user_id = request.GET.get('user_id')
        if user_id != '45':
            roles = RolesPage.objects.filter(organization_id=sector_id)
        else:
            roles = RolesPage.objects.all()

        paginator = Paginator(roles, page_size)
        page = paginator.get_page(page_number)

        roles_data = list(page.object_list.values('role_id', 'role_name', 'screens'))
        total_pages = paginator.num_pages

        return JsonResponse({
            'roles': roles_data,
            'total_pages': total_pages,
            'current_page': page_number,
            'page_size': page_size
        })

    return JsonResponse({'status': 'error'}, status=400)


class GetClientsNames(APIView):
    permission_classes = (permissions.AllowAny,)

    def get_client_names(self, client_ids):
        if isinstance(client_ids, list) and client_ids:
            return ClientPage.objects.filter(client_id__in=client_ids).values('client_name', 'client_id')
        elif isinstance(client_ids, dict):
            return ClientPage.objects.filter(client_id__in=client_ids.get('id', [])).values('client_name', 'client_id')
        elif isinstance(client_ids, str):
            return ClientPage.objects.filter(client_id__contains=client_ids).values('client_name', 'client_id')
        else:
            return []

    def get(self, request):
        client_ids_param = request.GET.get('clients', None)

        # Validate the presence of the client_ids parameter
        if not client_ids_param:
            return Response({"error": "Missing client_ids parameter"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Attempt to load the JSON data
            client_ids = json.loads(client_ids_param)
            if not isinstance(client_ids, (list, dict, str)):
                raise ValueError("client_ids should be a list, dict or string.")
        except (json.JSONDecodeError, ValueError) as e:
            return Response({"error": f"Invalid format: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

        # Proceed with processing if all validations pass
        client_names_queryset = self.get_client_names(client_ids)

        # Handle the response based on the number of returned objects
        if client_names_queryset.exists():
            if client_names_queryset.count() == 1:
                client_names_list_by_id = client_names_queryset.first()
            else:
                client_names_list_by_id = client_names_queryset  # Return queryset for multiple items

            return Response({
                'client_names_list_by_id': [client for client in client_names_list_by_id] if isinstance(
                    client_names_list_by_id, list) else client_names_list_by_id,
            })

        return Response({"error": "No clients found"}, status=status.HTTP_404_NOT_FOUND)

@csrf_exempt
@require_http_methods(["GET", "POST"])
def client_manage(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        action = data.get('action')
        pk = data.get('pk')
        name = data.get('client_name')
        status = data.get('status')
        sector_id = data.get('sector_id')

        if action == 'create':
            # Fetch the SectorPage instance using sector_id
            try:
               
                sector_instance = SectorPage.objects.get(sector_id=sector_id)
            except SectorPage.DoesNotExist:
                return JsonResponse({'status': 'error', 'message': 'Sector not found'}, status=400)
            ClientPage.objects.create(client_name=name, status=status, sector_id=sector_instance,  organization_id=sector_id)
        elif action == 'update':
            # Fetch the SectorPage instance using sector_id
            try:
                sector_instance = SectorPage.objects.get(sector_id=sector_id)
            except SectorPage.DoesNotExist:
                return JsonResponse({'status': 'error', 'message': 'Sector not found'}, status=400)
            try:
                client = ClientPage.objects.get(client_id=pk)
                client.client_name = name
                client.status = status
                client.sector_id = sector_instance
                client.save()
            except ClientPage.DoesNotExist:
                return JsonResponse({'status': 'error', 'message': 'Client not found'}, status=400)
        elif action == 'delete':
            ClientPage.objects.filter(client_id=pk).delete()
        
        return JsonResponse({'status': 'success'})
    
    if request.method == 'GET':
        sector_id = request.GET.get('sector_id')
        user_id = request.GET.get('user_id')
        if user_id != '45':
            clients = ClientPage.objects.filter(organization_id=sector_id).values('client_id', 'client_name', 'status', 'sector_id__sector_name')
        else:
            clients = ClientPage.objects.all().values('client_id', 'client_name', 'status', 'sector_id__sector_name')
    return JsonResponse({'clients': list(clients)})


class ProjectGetCreateView(generics.ListCreateAPIView):
    queryset = ProjectPage.objects.all()
    serializer_class = ProjectPageSerializer
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

class ProjectManageView(generics.RetrieveUpdateDestroyAPIView):
    queryset = ProjectPage.objects.all()
    serializer_class = ProjectPageSerializer
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    lookup_field = 'project_id'

@csrf_exempt
@require_http_methods(["GET", "POST"])
def project_manage(request):
    if request.method == 'POST':
        data = json.loads(request.body)

        action = data.get('action')
        pk = data.get('pk')
        name = data.get('project_name')
        client_ids = data.get('client_ids', [])  # Expect a list of client IDs
        status = data.get('status')
        billing_system_id = data.get('billing_system')  # New field for billing system ID
        
        if action == 'create':
            sector_id = data.get('sector_id')
            project = ProjectPage.objects.create(
                project_name=name,
                status=status,
                billing_system_id=billing_system_id,
                clients=client_ids,
                organization_id=sector_id

            )
            
        elif action == 'update':
            project = ProjectPage.objects.get(project_id=pk)
            project.project_name = name
            project.status = status
            project.billing_system_id = billing_system_id
            project.clients = client_ids
            project.save()
            
        elif action == 'delete':
            ProjectPage.objects.filter(project_id=pk).delete()
        
        return JsonResponse({'status': 'success'})
    
    if request.method == 'GET':
        sector_id = request.GET.get('sector_id')
        user_id = request.GET.get('user_id')
        if user_id != '45':
            projects = ProjectPage.objects.filter(organization_id=sector_id).values()
        else:
            projects = ProjectPage.objects.all().values()

        
        return JsonResponse({'projects': list(projects)})
    
    return JsonResponse({'status': 'error'}, status=400)




class SectororOrgnizationGetCreateView(generics.ListCreateAPIView):
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    serializer_class = SectorPageSerializer
    queryset = SectorPage.objects.all()

class SectororOrgnizationRetriveUpdateDeleteView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    serializer_class = SectorPageSerializer
    queryset = SectorPage.objects.all()

# Sector Views
@csrf_exempt
@require_http_methods(["GET", "POST"])
def sector_manage(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        action = data.get('action')
        pk = data.get('pk')
        name = data.get('sector_name')
        apps = data.get('selected_apps', [])  # Fetch apps field

        if action == 'create':
            SectorPage.objects.create(sector_name=name, apps=apps)
        elif action == 'update':
            sector = SectorPage.objects.get(sector_id=pk)
            sector.sector_name = name
            sector.apps = apps
            sector.save()
        elif action == 'delete':
            SectorPage.objects.filter(sector_id=pk).delete()
        else:
            return JsonResponse({'status': 'error', 'message': 'Invalid action'}, status=400)

        return JsonResponse({'status': 'success'})
    
    elif request.method == 'GET':
        sector_id = request.GET.get('sector_id')
        user_id = request.GET.get('user_id')
        if user_id != '45':
            sectors = SectorPage.objects.filter(sector_id=sector_id).values('sector_id', 'sector_name', 'apps')
        else:
            sectors = SectorPage.objects.all().values('sector_id', 'sector_name', 'apps')


        return JsonResponse({'sectors': list(sectors)})

    return JsonResponse({'status': 'error'}, status=400)

@csrf_exempt
@require_http_methods(["GET"])
def apps_list(request):
    apps = AppsPage.objects.all().values('app_id', 'app_name')  # Adjust fields according to your App model
    return JsonResponse({'apps': list(apps)})

@csrf_exempt
@require_http_methods(["GET", "POST"])
def stake_manage(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        action = data.get('action')
        pk = data.get('pk')
        name = data.get('stake_name')

        if action == 'create':
            StakePage.objects.create(stake_name=name)
        elif action == 'update':
            stake = StakePage.objects.get(stake_id=pk)
            stake.stake_name = name
            stake.save()
        elif action == 'delete':
            StakePage.objects.filter(stake_id=pk).delete()

        return JsonResponse({'status': 'success'})

    stakes = StakePage.objects.all().values('stake_id', 'stake_name')
    return JsonResponse({'stakes': list(stakes)})


class GetorCreateAppsView(generics.ListCreateAPIView):
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    serializer_class = AppsPageSerializer
    queryset = AppsPage.objects.all()

class RetriveUpdateDeleteAppsView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    serializer_class = AppsPageSerializer
    queryset = AppsPage.objects.all()

@csrf_exempt
@require_http_methods(["GET", "POST"])
def app_page_manage(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        action = data.get('action')
        pk = data.get('pk')
        name = data.get('app_name')

        if action == 'create':
            sector_id = data.get('sector_id')
            AppsPage.objects.create(app_name=name, organization_id=sector_id)
        elif action == 'update':
            app_page = AppsPage.objects.get(app_id=pk)
            app_page.app_name = name
            app_page.save()
        elif action == 'delete':
            AppsPage.objects.filter(app_id=pk).delete()

        return JsonResponse({'status': 'success'})
    if request.method == 'GET':
        sector_id = request.GET.get('sector_id')
        user_id = request.GET.get('user_id') 


        if user_id != '45':
            app_pages = AppsPage.objects.filter(organization_id=sector_id).values('app_id', 'app_name')
        
        else:
            app_pages = AppsPage.objects.all().values('app_id', 'app_name')
    return JsonResponse({'app_pages': list(app_pages)})

          
          
@csrf_exempt
def process_file(request):
    if request.method == 'POST' and request.FILES.get('file'):
        file = request.FILES['file']
        file_content = file.read().decode('utf-8')
        csv_reader = csv.reader(io.StringIO(file_content))
        headers = next(csv_reader, [])
        return JsonResponse({'headers': headers})
    return JsonResponse({'error': 'No file uploaded'}, status=400)


@csrf_exempt
def save_mapped_data(request):
    if request.method == 'POST':
        try:
            # Get the uploaded file and custom file name
            file = request.FILES.get('file')
            sector_id = request.POST.get('sector_id')
            custom_file_name = request.POST.get('file_name')
            mapping = json.loads(request.POST.get('mapping'))
            csv_headers = request.POST.get('csv_headers')

            # Build a dictionary for the fields to be saved in MappingRecord
            mapping_data = {f'{key}': value for key, value in mapping.items()}
            # Add the custom file name to the dictionary
            mapping_data['billing_system_file_name'] = custom_file_name
            mapping_data['csv_headers'] = csv_headers
            mapping_data['organization_id'] = sector_id

            # Ensure the dictionary contains only valid fields
            valid_fields = {field.name for field in MappingRecord._meta.get_fields()}
            filtered_data = {key: value for key, value in mapping_data.items() if key in valid_fields}
            


            # Create a new MappingRecord entry with the filtered data
            MappingRecord.objects.create(**filtered_data)

            return JsonResponse({'status': 'Mapping saved successfully'})

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON in mapping'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'error': 'Invalid request'}, status=400)

# class GetUpdateDeleteMappingsView(generics.ListCreateAPIView, generics.RetrieveUpdateDestroyAPIView):
#     queryset = MappingRecord.objects.all()
#     serializer_class = MappingRecordSerializer
#     permission_classes = (permissions.AllowAny,)
#     authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
#
#     def get(self, request, *args, **kwargs):
#         sector_id = self.request.GET.get('sector_id')
#
#         if not 'sector_id':
#             return Response({"error": "Missing required query parameters"}, status=status.HTTP_400_BAD_REQUEST)
#
#         try:
#             sector_id_list = json.loads(sector_id)
#         except json.JSONDecodeError:
#             return JsonResponse({"error": "Invalid project_ids format"}, status=status.HTTP_400_BAD_REQUEST)
#
#         try:
#             # Query to filter users where project_id is in the projects list
#             if isinstance(sector_id_list, list) and len(sector_id_list) > 0:
#                 mapping_records = self.queryset.filter(organization_id__in=sector_id_list)
#             elif isinstance(sector_id_list, dict):
#                 mapping_records = self.queryset.filter(organization_id=sector_id_list.get('sectors'))
#             elif isinstance(sector_id_list, str):
#                 mapping_records = self.queryset.filter(organization_id=sector_id_list)
#             else:
#                 return JsonResponse({"error": "Unexpected format of project_ids"},
#                                     status=status.HTTP_400_BAD_REQUEST)
#         except MappingRecord.DoesNotExist:
#             return JsonResponse({"error": "MappingRecord not found"}, status=status.HTTP_404_NOT_FOUND)
#
#         # mapping_records = self.queryset.filter(organization_id=sector_id)
#         serializer = MappingRecordSerializer(mapping_records, many=True) if mapping_records else []
#         return Response(serializer.data, status=status.HTTP_200_OK)
#
#     def put(self, request, *args, **kwargs):
#         return self.update(request, *args, **kwargs)
#
#     def delete(self, request, *args, **kwargs):
#         return self.destroy(request, *args, **kwargs)
#

class MappingRecordListCreateView(generics.ListCreateAPIView):
    queryset = MappingRecord.objects.all()
    serializer_class = MappingRecordSerializer
    permission_classes = (permissions.AllowAny,)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

    def perform_create(self, serializer):
        # Handle the file and custom data manually
        file = self.request.FILES.get('file')
        sector_id = self.request.data.get('sector_id')
        custom_file_name = self.request.data.get('file_name')
        mapping = self.request.data.get('mapping')
        csv_headers = self.request.data.get('csv_headers')

        if not file or not sector_id or not custom_file_name or not mapping:
            raise ValidationError("Missing required fields")

        try:
            mapping = json.loads(mapping)  # Make sure mapping is a valid JSON
        except json.JSONDecodeError:
            raise ValidationError("Invalid JSON in mapping")

        # Build a dictionary for the fields to be saved
        mapping_data = {f'{key}': value for key, value in mapping.items()}
        mapping_data['billing_system_file_name'] = custom_file_name
        mapping_data['csv_headers'] = csv_headers
        mapping_data['organization_id'] = sector_id

        # Ensure the data only contains valid fields (filter by model fields)
        valid_fields = {field.name for field in MappingRecord._meta.get_fields()}
        filtered_data = {key: value for key, value in mapping_data.items() if key in valid_fields}

        # Save the MappingRecord instance
        serializer.save(**filtered_data)

    def create(self, request, *args, **kwargs):
        # Handle the POST request
        return super().create(request, *args, **kwargs)

    def list(self, request, *args, **kwargs):
        # Handle the GET request (this just returns a list of all MappingRecord objects)
        return super().list(request, *args, **kwargs)

class RetriveUpdateDeleteMappingsView(generics.RetrieveUpdateDestroyAPIView):
    queryset = MappingRecord.objects.all()
    serializer_class = MappingRecordSerializer
    permission_classes = (permissions.AllowAny,)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)


    def retrieve(self, request, *args, **kwargs):
        pk = self.kwargs.get('pk')
        if not pk:
            return Response({"error": "Missing 'id' in query parameters to retrive"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            instace = self.get_object()
            serializer = self.get_serializer(instace)
            return Response(serializer.data)
        except MappingRecord.DoesNotExist:
            return JsonResponse({"error": "MappingRecord not found"}, status=status.HTTP_404_NOT_FOUND)

    def put(self, request, *args, **kwargs):
        pk = self.kwargs.get('pk')
        if not pk:
            return Response({"error": "Missing 'id' in query parameters to put"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            instance = self.get_object()  # use the default lookup field (pk)
            serializer = self.get_serializer(instance, data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            logger.info("Successfully updated record with ID: %s", pk)
            return Response(serializer.data)
        except MappingRecord.DoesNotExist:
            return JsonResponse({"error": "MappingRecord not found"}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, *args, **kwargs):
        response = self.destroy(request, *args, **kwargs)
        if response.status_code == status.HTTP_204_NO_CONTENT:
            logger.info("Successfully deleted record with ID: %s", kwargs['pk'])
        return response

# Get a Single Mapping Record
@api_view(['GET'])
def get_mapping(request, pk):
    try:
        mapping = MappingRecord.objects.get(pk=pk)
        serializer = MappingRecordSerializer(mapping)
        data = serializer.data

        # Remove 'id' and 'billing_system_file_name' from the response data
        data.pop('id', None)



        return Response(data, status=status.HTTP_200_OK)
    except MappingRecord.DoesNotExist:
        return Response({'error': 'Mapping record not found'}, status=status.HTTP_404_NOT_FOUND)

# Update a Mapping Record
@api_view(['POST'])
def update_mapping(request, pk):
    try:
        # Fetch the existing mapping record by primary key (pk)
        mapping = MappingRecord.objects.get(pk=pk)

        # Extract the data from the request
        data = request.data.get('mapping', '{}')

        # Check if data is a string and needs parsing
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                return Response({"error": "Invalid JSON format for mapping data"}, status=status.HTTP_400_BAD_REQUEST)

        # Update the fields of the mapping record
        for field, value in data.items():
            # Check if the field exists in the model
            if hasattr(mapping, field):
                setattr(mapping, field, value)
            else:
                return Response({"error": f"Field {field} does not exist in the model"}, status=status.HTTP_400_BAD_REQUEST)

        # Save the updated mapping record
        mapping.save()

        # Respond with the updated data
        serializer = MappingRecordSerializer(mapping)
        return Response(serializer.data, status=status.HTTP_200_OK)

    except MappingRecord.DoesNotExist:
        return Response({"error": "MappingRecord not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        # Log or handle other possible exceptions
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

# Delete a Mapping Record
@api_view(['DELETE'])
def delete_mapping(request, pk):
    try:
        mapping = MappingRecord.objects.get(pk=pk)
        mapping.delete()
        return Response({'status': 'Mapping deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    except MappingRecord.DoesNotExist:
        return Response({'error': 'Mapping record not found'}, status=status.HTTP_404_NOT_FOUND)








@csrf_exempt
def upload_csv_1(request):
    if request.method == 'POST':
        file = request.FILES.get('file')
        if not file:
            return JsonResponse({'error': 'No file uploaded'}, status=400)

        # Save the uploaded file
        file_id = default_storage.save(file.name, ContentFile(file.read()))
        # Get the file path
        file_path = default_storage.path(file_id)

        # Read CSV file and get headers
        try:
            with open(file_path, newline='', encoding='utf-8') as csvfile:
                reader = csv.reader(csvfile)
                headers = next(reader)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

        # Return file ID and headers
        return JsonResponse({'file_id': file_id, 'headers': headers})

    return JsonResponse({'error': 'Invalid request method'}, status=405)

def get_csv_headers(request, file_id):
    file_path = default_storage.path(file_id)
    df = pd.read_csv(file_path)
    headers = df.columns.tolist()
    return Response({'headers': headers})

def get_db_headers(request):
    try:
        # Get the model fields from PatientRecord
        fields = [header_name for header_name in mapping_db_headers]
        return JsonResponse({'headers': fields})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def save_mapping(request):
    file_id = request.data['mapping'].get('fileId')
    # mapping = request.data['mapping'].get('mapping')
    # Save the mapping to the database or any storage
    return Response({'status': 'success'})


@csrf_exempt
def user_details(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        
        # Find the user based on the email
        try:
            user = CredentialsForm.objects.get(email=email)
            sector = user.sector
            projects = list(user.projects.all().values('id', 'name'))  # Assuming projects is a related field
            response_data = {
                'sector': sector.name,  # Assuming sector has a 'name' field
                'projects': projects
            }
            return JsonResponse(response_data, status=200)
        except CredentialsForm.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)
    return JsonResponse({'error': 'Invalid request method'}, status=400)


class GetProjectName(APIView):
    permission_classes = (permissions.AllowAny,)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

    def get(self, request):
        # Retrieve the 'project_ids' query parameter from the request
        project_ids = request.GET.get('project_ids', '[]')  # Default to an empty list if not provided

        # Convert the JSON string back to a Python list
        try:
            project_id_list = json.loads(project_ids)  # Use json.loads to parse the string into a list
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid project_ids format"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Fetch projects based on the provided project IDs
            projects = ProjectPage.objects.filter(project_id__in=project_id_list).values('project_id', 'project_name')
        except ProjectPage.DoesNotExist:
            return JsonResponse({"error": "Projects not found"}, status=status.HTTP_404_NOT_FOUND)

        projects_details = [
            {"project_id": project['project_id'], "project_name": project['project_name']}
            for project in projects
        ] if projects else []

        return JsonResponse(projects_details, safe=False)

class ClientsBySector(APIView):
    permission_classes = (permissions.AllowAny,)
    def get(self, request, sector_id):
        if sector_id == 'all':
            clients = ClientPage.objects.all()
        else:
            clients = ClientPage.objects.filter(sector_id=sector_id)

        client_data = [{'client_id': client.client_id, 'client_name': client.client_name} for client in clients]
        return Response({'clients': client_data})


class ProjectsByClients(APIView):
    permission_classes = (permissions.AllowAny,)
    def get(self, request, client_id):
        # Ensure client_id is a string
        client_id = client_id

        # Filter projects where the `clients` field contains the client_id
        projects = ProjectPage.objects.filter(clients__icontains=client_id)

        # Prepare project data for response
        project_data = [{'project_id': project.project_id, 'project_name': project.project_name} for project in projects]

        return Response({'projects': project_data})

@api_view(['POST'])
def get_uploaded_records(request):
    
    
    if request.method == 'POST':
        data = json.loads(request.body)
        
        project_id = data.get('project_id', 1)
        offset = data.get('offset', 0)
        limit = data.get('limit', 20)
        filters = data.get('filters', [])
        tab = 'allocation_' + str(data.get('tab', 'fresh').lower())
        header = data.get('header', 'Allocation-Bins')
        user_id = data.get('user_id')  # Get the user ID from headers
       

    # Step 1: Retrieve the Project and Billing System ID
    project = get_object_or_404(ProjectPage, project_id=project_id)
    billing_system_id = project.billing_system_id
    
    # Step 2: Retrieve the Mapping Record
    mapping_data = get_object_or_404(MappingRecord, id=billing_system_id)

    # print('mapping_record', mapping_record)
    
    mapping_dict = {'input_source': mapping_data.input_source.get('value', ''),
                                'mrn': mapping_data.mrn.get('value', ''),
                                'patient_id': mapping_data.patient_id.get('value', ''),
                                'account_number': mapping_data.account_number.get('value', ''),
                                'visit_number': mapping_data.visit_number.get('value', ''),
                                'chart_number': mapping_data.chart_number.get('value', ''),
                                'project_key': mapping_data.project_key.get('value', ''),
                                'facility': mapping_data.facility.get('value', ''),
                                'facility_type': mapping_data.facility_type.get('value', ''),
                                'patient_last_name': mapping_data.patient_last_name.get('value', ''),
                                'patient_first_name': mapping_data.patient_first_name.get('value', ''),
                                'patient_phone': mapping_data.patient_phone.get('value', ''),
                                'patient_address': mapping_data.patient_address.get('value', ''),
                                'patient_city': mapping_data.patient_city.get('value', ''),
                                'patient_state': mapping_data.patient_state.get('value', ''),
                                'patient_zip': mapping_data.patient_zip.get('value', ''),
                                'patient_birthday': mapping_data.patient_birthday.get('value', ''),
                                'patient_gender': mapping_data.patient_gender.get('value', ''),
                                'subscriber_last_name': mapping_data.subscriber_last_name.get('value', ''),
                                'subscriber_first_name': mapping_data.subscriber_first_name.get('value', ''),
                                'subscriber_relationship': mapping_data.subscriber_relationship.get('value', ''),
                                'subscriber_phone': mapping_data.subscriber_phone.get('value', ''),
                                'subscriber_address': mapping_data.subscriber_address.get('value', ''),
                                'subscriber_city': mapping_data.subscriber_city.get('value', ''),
                                'subscriber_state': mapping_data.subscriber_state.get('value', ''),
                                'subscriber_zip': mapping_data.subscriber_zip.get('value', ''),
                                'subscriber_birthday': mapping_data.subscriber_birthday.get('value', ''),
                                'subscriber_gender': mapping_data.subscriber_gender.get('value', ''),
                                'current_billed_financial_class': mapping_data.current_billed_financial_class.get('value', ''),
                                'current_billed_payer_name': mapping_data.current_billed_payer_name.get('value', ''),
                                'member_id_current_billed_payer': mapping_data.member_id_current_billed_payer.get('value', ''),
                                'group_number_current_billed_payer': mapping_data.group_number_current_billed_payer.get('value', ''),
                                'current_billed_relationship': mapping_data.current_billed_relationship.get('value', ''),
                                'cob': mapping_data.cob.get('value', ''),
                                'payer_id_current_billed_payer': mapping_data.payer_id_current_billed_payer.get('value', ''),
                                'timely_filing_limit': mapping_data.timely_filing_limit.get('value', ''),
                                'appeal_limit': mapping_data.appeal_limit.get('value', ''),
                                'primary_payer_financial_class': mapping_data.primary_payer_financial_class.get('value', ''),
                                'primary_payer_name': mapping_data.primary_payer_name.get('value', ''),
                                'member_id_primary_payer': mapping_data.member_id_primary_payer.get('value', ''),
                                'group_number_primary_payer': mapping_data.group_number_primary_payer.get('value', ''),
                                'relationship_primary_payer': mapping_data.relationship_primary_payer.get('value', ''),
                                'cob_primary': mapping_data.cob_primary.get('value', ''),
                                'payer_id_primary_payer': mapping_data.payer_id_primary_payer.get('value', ''),
                                'secondary_payer_financial_class': mapping_data.secondary_payer_financial_class.get('value', ''),
                                'secondary_payer_name': mapping_data.secondary_payer_name.get('value', ''),
                                'member_id_secondary_payer': mapping_data.member_id_secondary_payer.get('value', ''),
                                'group_number_secondary_payer': mapping_data.group_number_secondary_payer.get('value', ''),
                                'relationship_secondary_payer': mapping_data.relationship_secondary_payer.get('value', ''),
                                'cob_secondary': mapping_data.cob_secondary.get('value', ''),
                                'payer_id_secondary_payer': mapping_data.payer_id_secondary_payer.get('value', ''),
                                'tertiary_payer_financial_class': mapping_data.tertiary_payer_financial_class.get('value', ''),
                                'tertiary_payer_name': mapping_data.tertiary_payer_name.get('value', ''),
                                'member_id_tertiary_payer': mapping_data.member_id_tertiary_payer.get('value', ''),
                                'group_number_tertiary_payer': mapping_data.group_number_tertiary_payer.get('value', ''),
                                'relationship_tertiary_payer': mapping_data.relationship_tertiary_payer.get('value', ''),
                                'cob_tertiary': mapping_data.cob_tertiary.get('value', ''),
                                'payer_id_tertiary_payer': mapping_data.payer_id_tertiary_payer.get('value', ''),
                                'auth_number': mapping_data.auth_number.get('value', ''),
                                'claim_number': mapping_data.claim_number.get('value', ''),
                                'facility_code': mapping_data.facility_code.get('value', ''),
                                'claim_frequency_type': mapping_data.claim_frequency_type.get('value', ''),
                                'signature': mapping_data.signature.get('value', ''),
                                'assignment_code': mapping_data.assignment_code.get('value', ''),
                                'assign_certification': mapping_data.assign_certification.get('value', ''),
                                'release_info_code': mapping_data.release_info_code.get('value', ''),
                                'service_date': mapping_data.service_date.get('value', ''),
                                'van_trace_number': mapping_data.van_trace_number.get('value', ''),
                                'rendering_provider_id': mapping_data.rendering_provider_id.get('value', ''),
                                'taxonomy_code': mapping_data.taxonomy_code.get('value', ''),
                                'procedure_code': mapping_data.procedure_code.get('value', ''),
                                'amount': mapping_data.amount.get('value', ''),
                                'procedure_count': mapping_data.procedure_count.get('value', ''),
                                'tooth_code': mapping_data.tooth_code.get('value', ''),
                                'procedure_code2': mapping_data.procedure_code2.get('value', ''),
                                'amount2': mapping_data.amount2.get('value', ''),
                                'procedure_count2': mapping_data.procedure_count2.get('value', ''),
                                'tooth_code2': mapping_data.tooth_code2.get('value', ''),
                                'procedure_code3': mapping_data.procedure_code3.get('value', ''),
                                'amount3': mapping_data.amount3.get('value', ''),
                                'procedure_count3': mapping_data.procedure_count3.get('value', ''),
                                'tooth_code3': mapping_data.tooth_code3.get('value', ''),
                                'procedure_code4': mapping_data.procedure_code4.get('value', ''),
                                'amount4': mapping_data.amount4.get('value', ''),
                                'procedure_count4': mapping_data.procedure_count4.get('value', ''),
                                'tooth_code4': mapping_data.tooth_code4.get('value', ''),
                                'dx1': mapping_data.dx1.get('value', ''),
                                'dx2': mapping_data.dx2.get('value', ''),
                                'dx3': mapping_data.dx3.get('value', ''),
                                'dx4': mapping_data.dx4.get('value', ''),
                                'dx5': mapping_data.dx5.get('value', ''),
                                'dx6': mapping_data.dx6.get('value', ''),
                                'total_charged': mapping_data.total_charged.get('value', ''),
                                'check_number': mapping_data.check_number.get('value', ''),
                                'insurance_balance': mapping_data.insurance_balance.get('value', ''),
                                'patient_balance': mapping_data.patient_balance.get('value', ''),
                                'contract_name': mapping_data.contract_name.get('value', ''),
                                'division': mapping_data.division.get('value', ''),
                                'type_of_service': mapping_data.type_of_service.get('value', ''),
                                'current_queue': mapping_data.current_queue.get('value', ''),
                                'queue_days': mapping_data.queue_days.get('value', ''),
                                'latest_action_date': mapping_data.lates_action_date.get('value', ''),
                                'next_follow_up_before': mapping_data.next_follow_up_before.get('value', ''),
                                'claim_denial_date': mapping_data.claim_denial_date.get('value', ''),
                                'latest_pay_date': mapping_data.latest_pay_date.get('value', ''),
                                'latest_pay_amount': mapping_data.latest_pay_amount.get('value', ''),
                                # 'insurance_payment_date': mapping_data.insurance_payment_date.get('value', ''),
                                # 'insurance_payment_amount': mapping_data.insurance_payment_amount.get('value', ''),
                                # 'patient_payment_date': mapping_data.patient_payment_date.get('value', ''),
                                # 'patient_payment_amount': mapping_data.patient_payment_amount.get('value', ''),
                                # 'balance_before_appeal': mapping_data.balance_before_appeal.get('value', ''),
                                # 'balance_after_appeal': mapping_data.balance_after_appeal.get('value', ''),
                                # 'appeal_sent_date': mapping_data.appeal_sent_date.get('value', ''),
                                'under_pay': mapping_data.under_pay.get('value', ''),
                                'last_ins_disc_check_date': mapping_data.last_ins_disc_check_date.get('value', ''),
                                'last_ev_check_date': mapping_data.last_ev_check_date.get('value', ''),
                                'claim_priority': mapping_data.claim_priority.get('value', ''),
                                'category': mapping_data.category.get('value', ''),
                                'sub_category': mapping_data.sub_category.get('value', ''),
                                'status': mapping_data.status.get('value', ''),
                                'action': mapping_data.action.get('value', ''),
                                'provider_name': mapping_data.provider_name.get('value', ''),
                                'provider_npi': mapping_data.provider_npi.get('value', ''),
                                'provider_location': mapping_data.provider_location.get('value', ''),
                                'assigned_to': mapping_data.assigned_to.get('value', ''),
                                'last_claim_status_check_date': mapping_data.last_claim_status_check_date.get('value', ''),
                            }

    filtered_dict = {db_field: csv_header for db_field, csv_header in mapping_dict.items() if csv_header}

    

    


    if tab != 'allocation_fresh' and header != 'Executive':
        filtered_dict['session_user'] = 'Allocated_user'
        filtered_dict['allocated_date'] = 'Allocated_Date'
        filtered_dict['worked_date'] = 'Worked_Date'
        
        # filtered_dict['ageing_bucket'] = 'Ageing_Bucket'
    filtered_dict['ageing_bucket'] = 'Ageing_Bucket'
    filtered_dict['id'] = 'agent_id'
    # Build query filters
    query_filters = Q(project_id=str(project_id)) & Q(**{tab: 1})
    if header == "Executive":

        query_filters &= Q(current_user_id=str(user_id))

    print("query_filters:--", query_filters)

    for filter_item in filters:
        header_name = filter_item['header_name']
        filter_option = filter_item['filter_option']
        filter_value = filter_item['filter_value']
        
        # Map CSV header to database field
        db_field = next((field for field, header in filtered_dict.items() if header == header_name), None)
        
        if db_field:
                if filter_option == 'equals':
                    query_filters &= Q(**{db_field: filter_value})
                elif filter_option == 'contains':
                    query_filters &= Q(**{f"{db_field}__icontains": filter_value})
                elif filter_option == 'not_equals':
                    query_filters &= ~Q(**{db_field: filter_value})
                elif filter_option == 'range':
                    range_values = filter_value.split(',')
                    if len(range_values) == 2:
                        query_filters &= Q(**{f"{db_field}__range": (range_values[0], range_values[1])})
                elif filter_option == 'greater_than':
                    query_filters &= Q(**{f"{db_field}__gt": filter_value})
                elif filter_option == 'lesser_than':
                    query_filters &= Q(**{f"{db_field}__lt": filter_value})
                elif filter_option == 'date_range':
                    start_date, end_date = filter_value.split(',')
                    query_filters &= Q(**{f"{db_field}__range": (start_date, end_date)})


    # Query PatientRecord with only the filtered fields
    patient_records = PatientRecords.objects.filter(query_filters).values(*filtered_dict.keys())
    
    # Format the data according to CSV mapped headers
    formatted_data = []
    if patient_records:
        for record in patient_records:

            print('***********************************')
            print(record)
            print('************************************')
            # Map the database fields to their corresponding CSV headers
            formatted_record = {filtered_dict[db_field]: record[db_field] for db_field in filtered_dict}
            
            
            if 'service_date' in formatted_record:
                
                service_date_str = formatted_record['service_date']
                service_date = datetime.strptime(service_date_str, '%Y-%m-%d')  # Parse the string to datetime
                formatted_record['service-date'] = service_date.strftime('%m-%d-%Y')  # Format it back to 'MM-DD-YYYY'

            
            # Check if 'Allocated_user' is in the formatted record
            if 'Allocated_user' in formatted_record:
                user_id = formatted_record['Allocated_user']
                # Retrieve the user information from CredentialsForm
                allocated_user = CredentialsForm.objects.filter(id=user_id).first()
                if allocated_user:
                    # Replace the user ID with the user's name or any other relevant information
                    formatted_record['Allocated_user'] = allocated_user.first_name+' '+ allocated_user.last_name  # Assuming 'name' is a field in CredentialsForm
                else:
                    # If no user is found, you might want to set it to None or an empty string
                    formatted_record['Allocated_user'] = None

            formatted_data.append(formatted_record)

    # The formatted_data now contains the PatientRecord data mapped to CSV headers, with user information included
    return JsonResponse({"records": formatted_data})


@api_view(['GET'])
def get_notes(request):
    record_id = request.query_params.get('record_id')
    if record_id:
        notes = PatientRecordNotes.objects.filter(record_id=record_id).order_by('-date')
        serializer = RecordNotesSerializer(notes, many=True)
        return Response(serializer.data)
    return Response([])

class GetOrCreateNotesView(generics.ListCreateAPIView):
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    serializer_class = RecordNotesSerializer
    queryset = PatientRecordNotes.objects.all()
    lookup_field = 'title'


@api_view(['POST'])
def add_note(request):
    record_ids = request.data.get('record_ids') #Data getting in list.
    notes = request.data.get('notes')
    sub_header = (request.data.get('sub_header')).title()
    header = request.data.get('header')
    tab = (request.data.get('tab')).title()
    user_name = request.data.get('user_name')
    status_code = request.data.get('statuscode')
    action_code = request.data.get('actioncode')
    ist = pytz.timezone('Asia/Kolkata')
    ist_time = timezone.now().astimezone(ist)


    # print('8787--', request.data.get('header'))
    header_mapping = {
    'Allocation-bins': 'allocated_to',
    'Review-bins': 'review_by',
    'HoldQ': 'hold',
    'Executive': 'executive_bin',
    }

    if record_ids and notes and user_name:
        for record_id in record_ids:
            # Create a new note
            note = PatientRecordNotes.objects.create(record_id=record_id, notes=notes, user_name=user_name, status_code=status_code, action_code=action_code)

            print('status-note', note)

            # Ensure the header is valid
            if request.data.get('header') in header_mapping:
                field_to_update = header_mapping[header]
                
                update_data = {f"{field_to_update}": {sub_header: 'worked'}}

                print(update_data)

                if header != 'Allocation-bins':
                    # Update the PatientRecords
                    status = PatientRecords.objects.filter(patient_id=record_id).update(
                        allocation_allocated=False,
                        allocation_fresh=False,
                        allocation_worked=True,
                        allocated_to={sub_header: 'worked'},
                        worked_date=ist_time,  # Set the current date and time
                        **update_data,  # Dynamically set the field based on the header
                    )
                else:
                    # Update the PatientRecords
                    status = PatientRecords.objects.filter(patient_id=record_id).update(
                        allocation_allocated=False,
                        allocation_fresh=False,
                        allocation_worked=True,
                       
                        worked_date=ist_time,  # Set the current date and time
                        **update_data,  # Dynamically set the field based on the header
                    )

                print('status--', status)
                return Response({'status': 'Note added', 'note_id': note.id})
            else:
                return Response({'status': 'header is missing'}, status=400)

    return Response({'status': 'Failed to add note'}, status=400)


# @api_view(['GET'])
# def get_users(request):
#     if request.method == 'GET':
#         data = json.loads(request.body)
#         project_id = data.get('project_id')
#
#         if type(project_id) is not list:
#             project_id = [project_id]
#
#         else:
#             project_id = project_id
#
#
#         # Query to filter users where project_id is in the projects list
#         users = UserCredentials.objects.filter(projects__contains=project_id).annotate(
#             full_name=Concat('first_name', Value(' '), 'last_name')
#         ).values('full_name', 'id')
#
#         # Return the users list as a JSON response
#         return JsonResponse({'users': list(users)}, safe=False)

class GetUsersView(APIView):
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

    def get(self, request):
        project_ids_str = request.GET.get('project_ids')
        if not project_ids_str:
            return Response({'detail': 'Project ID is required'}, status=400)

        try:
            # Parse JSON
            project_id_list = json.loads(project_ids_str)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format for project_ids"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Normalize to list of integers
            if isinstance(project_id_list, int):
                project_ids = [project_id_list]
            elif isinstance(project_id_list, list):
                if len(project_id_list) == 0:
                    return Response({'users': []})
                # Convert all items to integers
                project_ids = [int(pid) for pid in project_id_list]
            else:
                return JsonResponse({"error": "project_ids must be an integer or list of integers"}, 
                                  status=status.HTTP_400_BAD_REQUEST)

            # Query users
            users = (UserProjectAssignment.objects
                    .select_related('user')
                    .filter(project__id__in=project_ids)
                    .annotate(full_name=Concat('user__first_name', Value(' '), 'user__last_name'))
                    .values('full_name', 'user__employee_id')
                    .distinct())

            return Response({'users': list(users)})

        except (ValueError, TypeError):
            return JsonResponse({"error": "All project IDs must be valid integers"}, 
                              status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return JsonResponse({"error": f"Database error: {str(e)}"}, 
                              status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
def assign_records(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        project_id = data.get('project_id')
        records_list = data.get('records')  # ['123','124']
        assign_id = data.get('assign')
        tab = (data.get('tab')).lower()
        sub_header =(data.get('sub_header')).title()

        ist = pytz.timezone('Asia/Kolkata')
        ist_time = timezone.now().astimezone(ist)

        # Update records where patient_id contains any value from records_list
        updated_count = PatientRecords.objects.filter(patient_id__in=records_list).update(
            allocation_allocated=True,
            allocation_fresh = False,
            current_user_id=assign_id,
            allocated_date=ist_time, # Set the current date and time
            executive_status = True,
            executive_bin = {sub_header:'allocated'},
            allocation_status = True,
            allocated_to = {sub_header:'allocated'}

        )

        return JsonResponse({'status': 200, 'msg': 'Successfully updated', 'updated_records_count': updated_count})



class AssignRecordsView(APIView):
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

    def post(self, request, *args, **kwargs):
        data = request.data  # DRF will parse the request body into JSON automatically
        sub_header = data.get('sub_header', '').lower()
        # project_id = data.get('project_id')
        # records_list = data.get('records')  # ['123','124']
        # assigned_to = data.get('assign')
        # tab = data.get('tab', '').lower()

        ist = pytz.timezone('Asia/Kolkata')
        ist_time = timezone.now().astimezone(ist)

        # assigning user i.e user working on records
        assigned_by_user = request.user

        # Update records where patient_id contains any value from records_list
        patients = PatientRecords.objects.filter(
            patient_id__in=data.get('records')
        )
        patients.update(
            allocation_allocated=True,
            executive_status=True,
            allocation_status=True,
            review_status=False,
            allocation_fresh=False,
            assigned_by = assigned_by_user,
            allocated_date=ist_time,  # Set the current date and time
            executive_bin=sub_header,
            current_queue={sub_header: 'allocated'}
        )

        # Update M2M using through model
        assigning_to = data.get('assign')
        assigned_users = UserCredentialsSetup.objects.filter(employee_id=assigning_to)
        PatientRecords.assigned_to.through.objects.filter(
            patientrecords_id__in=patients.values_list('id', flat=True)
        ).delete()

        through_objs = [
            PatientRecords.assigned_to.through(
                patientrecords_id=p.id,
                baseuser_id=u.id
            )
            for p in patients for u in assigned_users
        ]
        PatientRecords.assigned_to.through.objects.bulk_create(through_objs)

        # Create log entries in bulk
        log_entries = [
            PatientRecordsLogs(patient_record=patient, record_logs_id=patient.pk, action='UPDATE')
            for patient in patients
        ]
        PatientRecordsLogs.objects.bulk_create(log_entries)

        return Response(
            {'status': 200, 'msg': 'Success', 'updated': patients.count()},
            status=status.HTTP_200_OK
        )
@api_view(['POST'])
def create_rule(request):
    try:
        # Extract data from the request
        data = request.data
        
        # Log incoming data
        print('Data received--', data)

        # Manually construct the model instance
        rule = ViewRules1(
            rule_name=data.get('rule_name', ''),
            deptartment=data.get('department', ''),
            created_by = data.get('created_by', ''),
            ageing_bucket=data.get('ageing_bucket', ''),
            auth=data.get('auth', ''),
            approvals=json.dumps(data.get('approvals', {})),
            action=json.dumps(data.get('action', [])),
            text_search_fields=json.dumps(data.get('free_text_fields', {})),
            projects=json.dumps(data.get('projects', [])),
            range_filters=json.dumps(data.get('rules', {})),
            rule_category=data.get('rule_category', ''),
            rule_target = json.dumps(data.get('rule_target', [])),

        )
        
        # Save the instance to the database
        rule.save()

        # Prepare the response data
        response_data = {
            # 'id': rule.id,
            'rule_name': rule.rule_name,
            'department': rule.deptartment,
            'ageing_bucket': rule.ageing_bucket,
            'auth': rule.auth,
            'approvals': json.loads(rule.approvals),
            'action': json.loads(rule.action),
            'input_text_fields': json.loads(rule.text_search_fields),
            'projects': json.loads(rule.projects),
            'range_fields': json.loads(rule.range_filters),
            'rule_category': rule.rule_category,
            'rule_target': json.loads(rule.rule_target),
        }

        print('Rule saved--', response_data)
        return Response(response_data, status=status.HTTP_201_CREATED)

    except Exception as e:
        print("The error was--", str(e))
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class RuleViewSet(generics.ListCreateAPIView):
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    serializer_class = ViewRules1Serializer

    def get_roles_instance(self, project_id, user_id, source):
        try:
            # Query to filter users where project_id is in the projects list
            if isinstance(project_id, list) and len(project_id) > 0:
                return ViewRules1.objects.filter(
                    projects__icontains=project_id[0],
                    # created_by=user_id,
                    rule_category='SOP Rules'  # Just use filter() instead of include()
                ) if source else ViewRules1.objects.filter(
                    projects__icontains=project_id[0],
#                     created_by=user_id,
                ).exclude(
                    rule_category='SOP Rules'
                )
            elif isinstance(project_id, dict):
                return ViewRules1.objects.filter(
                    projects__icontains=project_id.get('id'),
#                     created_by=user_id,
                    rule_category='SOP Rules'  # Just use filter() instead of include()
                ) if source else ViewRules1.objects.filter(
                    projects__icontains=project_id.get('id'),
#                     created_by=user_id,
                ).exclude(
                    rule_category='SOP Rules'
                )
            elif isinstance(project_id, str):
                return ViewRules1.objects.filter(
                    projects__icontains=project_id,
#                     created_by=user_id,
                    rule_category='SOP Rules'  # Just use filter() instead of include()
                ) if source else ViewRules1.objects.filter(
                    projects__icontains=project_id,
#                     created_by=user_id,
                ).exclude(
                    rule_category='SOP Rules'
                )
            elif isinstance(project_id, int):
                return ViewRules1.objects.filter(
                    projects__icontains=project_id,
                    #                     created_by=user_id,
                    rule_category='SOP Rules'  # Just use filter() instead of include()
                ) if source else ViewRules1.objects.filter(
                    projects__icontains=project_id,
                    #                     created_by=user_id,
                ).exclude(
                    rule_category='SOP Rules'
                )
            else:
                return ViewRules1.objects.filter(
                    projects__icontains=0,
#                     created_by=user_id,
                    rule_category='SOP Rules'  # Just use filter() instead of include()
                ) if source else ViewRules1.objects.filter(
                    projects__icontains=0,
#                     created_by=user_id,
                ).exclude(
                    rule_category='SOP Rules'
                )

        except ProjectPage.DoesNotExist:
            return JsonResponse({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return JsonResponse({"error": "Unexpected format of project_ids"},
                                status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        try:
            project_id = json.loads(request.GET.get('project_id'))
            user_id = request.GET.get('user_id')
            source = request.data.get('source', 0)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid format"}, status=status.HTTP_400_BAD_REQUEST)

        rules = self.get_roles_instance(project_id, user_id, source)

        response_data = self.serializer_class(rules, many=True)
        return Response(response_data.data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

@api_view(['POST'])
def update_rule_status(request, rule_id):
    try:
        # Fetch the rule using the provided rule_id
        rule = ViewRules1.objects.get(view_id=rule_id)

        # Get rule_status from the request body and update if provided
        updated_status = request.data.get('rule_status', None)
        if updated_status is not None:
            
            rule.rule_status = updated_status

        # Update other fields regardless of rule_status
        rule.ageing_bucket = request.data.get('ageing_bucket', '')
        rule.auth = request.data.get('auth', '')
        rule.approvals = json.dumps(request.data.get('approvals', {}))
        rule.action = json.dumps(request.data.get('action', []))
        rule.free_text_fields = json.dumps(request.data.get('free_text_fields', {}))
        rule.projects = json.dumps(request.data.get('projects', []))
        rule.range_filters = json.dumps(request.data.get('rules', {}))
       
        
        rule.rule_category = request.data.get('rule_category', '')
        rule.rule_target = json.dumps(request.data.get('rule_target', []))

    
        
        # Save the updated rule
        a = rule.save()
        
        if request.data.get('rule_category') == 'SOP Rules':
            version_count = RuleVersions.objects.filter(reference_id= rule_id).count()
            
            version = RuleVersions(
                reference_id = rule_id,
                approved_by = json.dumps(request.data.get('approvals', {})),
                descripation = request.data.get('description'),
                author = request.data.get('created_by'),
            )
            
            version.save()
        

        return Response({"response": "Success"}, status=status.HTTP_200_OK)

    except ViewRules1.DoesNotExist:
        return Response({'error': 'Rule not found'}, status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



@api_view(['DELETE'])
def delete_rule(request, rule_id):
    if request.method == 'DELETE':
        try:
            rule = ViewRules1.objects.get(view_id=rule_id)
            rule.delete()
            return JsonResponse({'message': 'Rule deleted successfully.'}, status=200)
        except ViewRules1.DoesNotExist:
            return JsonResponse({'error': 'Rule not found.'}, status=404)
    return JsonResponse({'error': 'Invalid request method.'}, status=400)


class GetUploadedRecords(APIView):
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.formatted_data = []
        self.records_filter_criteria = {}
        self.status_filter = {}
        self.query_filters = {}
        self.filtered_dict = {}

    def count_patient_records_dynamically(self):
        return PatientRecords.objects.filter(self.query_filters, **self.records_filter_criteria, **self.status_filter).values(*self.filtered_dict.keys()).count()

    def fetch_patient_records_dynamically(self, offset, limit):
        return PatientRecords.objects.filter(self.query_filters, **self.records_filter_criteria, **self.status_filter).values(*self.filtered_dict.keys())[offset:offset + limit]

    def get_billing_system(self, project_id):
        try:
            if isinstance(project_id, list) and len(project_id) > 0:
                return get_object_or_404(BillingSystemMappingRecord, project=project_id[0]).pk
            elif isinstance(project_id, int):
                return get_object_or_404(BillingSystemMappingRecord, project=project_id).pk
            else:
                return get_object_or_404(Projects, id=0).billing_system_mapping.pk
        except Projects.DoesNotExist:
            return JsonResponse({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return JsonResponse({"error": "Unexpected format of project_ids"}, status=status.HTTP_400_BAD_REQUEST)

    def get_filtered_dict(self, billing_system_id):
        mapping_data = model_to_dict(get_object_or_404(BillingSystemMappingRecord, pk=billing_system_id))

        filtered_dict_col = {column: getattr(mapping_data, column, {}).get('value', '') for column in mapping_data}
        self.filtered_dict = {db_field: csv_header for db_field, csv_header in filtered_dict_col.items() if
                         db_field in mapping_csv_headers}

    def formated_records_data(self, patient_records):
        # Group records by unique identifier (patient_id + account_number + visit_number)
        grouped_records = {}
        
        for record in patient_records:
            # Create unique group key
            group_key = f"{record.get('patient_id', '')}_{record.get('account_number', '')}_{record.get('visit_number', '')}"
            
            formatted_record = {key: record[key] for key in self.filtered_dict.keys() if key in record}

            # Formatting service date and other fields
            if 'service_date' in formatted_record:
                service_date_str = formatted_record['service_date']
                service_date = datetime.strptime(service_date_str, '%Y-%m-%d') if not isinstance(service_date_str, date) else service_date_str
                formatted_record['service_date'] = service_date.strftime('%m-%d-%Y')

            if 'created_at' in formatted_record:
                created_at = formatted_record['created_at']
                if created_at.tzinfo is not None:
                    created_at = created_at.replace(tzinfo=None)
                days_since_created = (datetime.now() - created_at).days
                formatted_record['days_since_created'] = days_since_created

            if 'Allocated_user' in formatted_record:
                allocated_user_user_id = formatted_record['Allocated_user']
                allocated_user = UserCredentials.objects.filter(id=allocated_user_user_id).first()
                formatted_record['Allocated_user'] = f"{allocated_user.first_name} {allocated_user.last_name}" if allocated_user else None

            # Group records by unique key
            if group_key not in grouped_records:
                grouped_records[group_key] = {
                    'main_record': formatted_record,
                    'procedure_details': [],
                    'total_amount': 0,
                    'procedure_codes': set(),
                    'record_ids': []
                }
            
            # Add procedure details
            grouped_records[group_key]['procedure_details'].append({
                'id': record.get('id'),
                'procedure_code': record.get('procedure_code', ''),
                'amount': record.get('amount', 0),
                'description': record.get('description', ''),
                'service_date': formatted_record.get('service_date', ''),
                'charge_amount': record.get('charge_amount', 0)
            })
            
            # Add to totals
            try:
                amount = float(record.get('amount', 0))
                grouped_records[group_key]['total_amount'] += amount
            except (ValueError, TypeError):
                pass
                
            if record.get('procedure_code'):
                grouped_records[group_key]['procedure_codes'].add(record.get('procedure_code'))
                
            grouped_records[group_key]['record_ids'].append(record.get('id'))
        
        # Create final formatted records
        for group_key, group_data in grouped_records.items():
            main_record = group_data['main_record'].copy()
            
            # Mark as grouped if multiple records
            if len(group_data['procedure_details']) > 1:
                main_record['display_type'] = 'cpt_grouped'
                main_record['is_grouped'] = True
                main_record['total_procedures'] = len(group_data['procedure_details'])
                main_record['procedure_codes'] = ', '.join(sorted(group_data['procedure_codes']))
                main_record['total_amount'] = group_data['total_amount']
                main_record['procedure_details'] = group_data['procedure_details']
                main_record['grouped_record_ids'] = group_data['record_ids']
                
                # Update amount field with total
                if 'amount' in main_record:
                    main_record['amount'] = group_data['total_amount']
            else:
                main_record['display_type'] = 'single'
                main_record['is_grouped'] = False
                main_record['total_procedures'] = 1
                main_record['procedure_details'] = group_data['procedure_details']
            
            self.formatted_data.append(main_record)

    def get_procedure_details_endpoint(self, request):
        """
        New endpoint to get procedure details when user double-clicks a grouped record
        """
        try:
            record_ids = request.GET.get('record_ids', '').split(',')
            if not record_ids:
                return JsonResponse({"error": "record_ids parameter is required"}, status=400)
            
            # Get all procedures for the grouped record
            procedures = PatientRecords.objects.filter(id__in=record_ids).values(
                'id', 'procedure_code', 'amount', 'description', 'service_date', 'charge_amount'
            )
            
            formatted_procedures = []
            for proc in procedures:
                formatted_proc = dict(proc)
                if 'service_date' in formatted_proc and formatted_proc['service_date']:
                    service_date = formatted_proc['service_date']
                    if isinstance(service_date, str):
                        service_date = datetime.strptime(service_date, '%Y-%m-%d').date()
                    formatted_proc['service_date'] = service_date.strftime('%m-%d-%Y')
                formatted_procedures.append(formatted_proc)
            
            return JsonResponse({
                "procedure_details": formatted_procedures,
                "total_procedures": len(formatted_procedures)
            })
            
        except Exception as e:
            return JsonResponse({"error": f"Error fetching procedure details: {str(e)}"}, status=500)

    def applied_filters_on_records(self, filters, filtered_dict):
        for filter_item in filters:
            header_name = filter_item['header_name']
            filter_option = filter_item['filter_option']
            filter_value = filter_item['filter_value']
            db_field = next((field for field, header in filtered_dict.items() if header == header_name), None)

            if db_field:
                if filter_option == 'equals':
                    self.query_filters &= Q(**{db_field: filter_value})
                elif filter_option == 'contains':
                    self.query_filters &= Q(**{f"{db_field}__icontains": filter_value})
                elif filter_option == 'not_equals':
                    self.query_filters &= ~Q(**{db_field: filter_value})
                elif filter_option == 'range':
                    range_values = filter_value.split(',')
                    if len(range_values) == 2:
                        self.query_filters &= Q(**{f"{db_field}__range": (range_values[0], range_values[1])})
                elif filter_option == 'greater_than':
                    self.query_filters &= Q(**{f"{db_field}__gt": filter_value})
                elif filter_option == 'lesser_than':
                    self.query_filters &= Q(**{f"{db_field}__lt": filter_value})
                elif filter_option == 'date_range':
                    start_date, end_date = filter_value.split(',')
                    self.query_filters &= Q(**{f"{db_field}__range": (start_date, end_date)})

    def get(self, request):
        try:
            offset = int(request.GET.get('offset', 0))
            limit = int(request.GET.get('limit', 20))
            
            # Fixed project_id parsing
            project_id_str = request.GET.get('project_id')
            if not project_id_str:
                return JsonResponse({"error": "project_id is required"}, status=status.HTTP_400_BAD_REQUEST)
            
            try:
                # Try to parse as JSON first
                project_id = json.loads(project_id_str)
            except json.JSONDecodeError:
                # If JSON parsing fails, try to convert directly to int
                try:
                    project_id = int(project_id_str)
                except ValueError:
                    return JsonResponse({"error": "Invalid project_id format"}, status=status.HTTP_400_BAD_REQUEST)
            
            tab = request.GET.get('tab', '').lower()  # Convert to lowercase and provide default
            search = request.GET.get('search', '')
            sort_key = request.GET.get('sort', 'id')
            sort_direction = request.GET.get('direction', 'ascending')
            sub_header = request.GET.get('sub_header', '')
            session_user = request.user
            header = request.GET.get('header', 'Allocation-Bins')
            filters = request.GET.get('filters', [])
            
        except ValueError as e:
            return JsonResponse({"error": f"Invalid parameter format: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return JsonResponse({"error": f"Parameter parsing error: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Get billing system
            billing_system_id = self.get_billing_system(project_id) if project_id else 0
            if isinstance(billing_system_id, JsonResponse):
                return billing_system_id  # Return error response if get_billing_system failed
            
            self.get_filtered_dict(billing_system_id)

            if header in ['Allocation-Bins', 'Review-Bins', 'HoldQ', 'Executive', 'all_records']:
                status_mapping = {
                    'Allocation-Bins': 'allocation_status',
                    'Review-Bins': 'review_status',
                    'HoldQ': 'hold_status',
                    'Executive': 'executive_status'
                }

                if tab != "fresh":
                    self.filtered_dict['session_user'] = 'Allocated_user'
                    self.filtered_dict['allocated_date'] = 'Allocated_Date'
                    self.filtered_dict['worked_date'] = 'Worked_Date'
                self.filtered_dict['ageing_bucket'] = 'Ageing_Bucket'
                self.filtered_dict['id'] = 'id'

                if header == 'HoldQ':
                    self.filtered_dict['hold'] = "hold"

                self.query_filters = Q(project_id=str(project_id))

                # Logic for different headers
                if header == 'Review-Bins':
                    if not session_user.is_authenticated:
                        return JsonResponse({"error": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)
                    
                    self.records_filter_criteria = {
                        f"review_bin_headers__icontains": sub_header.lower(),
                        f"review_by": session_user
                    }
                    self.status_filter = {status_mapping[header]: True}

                elif header == 'Allocation-Bins':
                    if not tab:
                        return JsonResponse({"error": "tab parameter is required for Allocation-Bins"}, status=status.HTTP_400_BAD_REQUEST)
                    
                    self.records_filter_criteria = {
                        f"current_queue__{sub_header.lower()}__icontains": tab
                    }
                    self.status_filter = {status_mapping[header]: True}

                elif header == 'Executive':
                    if not session_user.is_authenticated:
                        return JsonResponse({"error": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)
                    
                    try:
                        base_user_id = UserCredentialsSetup.objects.get(id=session_user.id).id
                        self.records_filter_criteria = {
                            f"executive_bin__icontains": sub_header.lower(),
                            f"assigned_to__id": base_user_id
                        }
                        self.status_filter = {status_mapping[header]: True}
                    except UserCredentialsSetup.DoesNotExist:
                        return JsonResponse({"error": "User credentials not found"}, status=status.HTTP_404_NOT_FOUND)

                total_records = self.count_patient_records_dynamically()
                patient_records = self.fetch_patient_records_dynamically(offset, limit)

                if patient_records:
                    self.formated_records_data(patient_records)
                    
                    # Add summary information
                    total_grouped_records = sum(1 for record in self.formatted_data if record.get('is_grouped', False))
                    total_single_records = len(self.formatted_data) - total_grouped_records
                    
                    return JsonResponse({
                        "records": self.formatted_data, 
                        'total_records': total_records,
                        'displayed_records': len(self.formatted_data),  # Actual rows shown
                        'total_grouped_records': total_grouped_records,
                        'total_single_records': total_single_records
                    })
                else:
                    return JsonResponse({"records": [], 'total_records': 0, 'displayed_records': 0})
            else:
                return JsonResponse({"error": f"Invalid header: {header}"}, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            return JsonResponse({"error": f"Server error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetUserAllocationAppliedUploadedRecords(generics.ListAPIView):
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    queryset = PatientRecords.objects.all()
    serializer_class = PatientRecordSerializer

    def get_queryset(self):
        try:
            custom_bins_id = self.request.query_params.get('id', None)
            custom_bins_instance = CustomBins.objects.get(id=custom_bins_id)
            return custom_bins_instance.custom_bins_applied_records_set.all()

        except Exception as e:
            pass



# class GetUploadedRecords(APIView):
#     permission_classes = (permissions.AllowAny,)
#     parser_classes = (MultiPartParser, FormParser)
#     authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
#
#     def count_patient_records_dynamically(self, query_filters, records_filter_criteria, status_filter, filtered_dict):
#         return PatientRecords.objects.filter(query_filters).filter(**records_filter_criteria).filter(**status_filter).values(*filtered_dict.keys()).count()
#
#     def fetch_patient_records_dynamically(self, query_filters, records_filter_criteria, status_filter, filtered_dict, offset, limit):
#         return PatientRecords.objects.filter(query_filters).filter(**records_filter_criteria).filter(**status_filter).values(*filtered_dict.keys())[offset:offset + limit]
#
#     def get_billing_system(self, project_id):
#         try:
#             # Query to filter users where project_id is in the projects list
#             if isinstance(project_id, list) and len(project_id) > 0:
#                 return get_object_or_404(BillingSystemMappingRecord, project=project_id[0]).pk
#             elif isinstance(project_id, int):
#                 return get_object_or_404(BillingSystemMappingRecord, project=project_id).pk
#             # elif isinstance(project_id, dict):
#             #     return get_object_or_404(Projects, id=project_id.get('id')).billing_system_mapping.pk
#             # elif isinstance(project_id, str):
#             #     return get_object_or_404(Projects, id=project_id).billing_system_mapping.pk
#             else:
#                 return get_object_or_404(Projects, id=0).billing_system_mapping.pk
#
#         except Projects.DoesNotExist:
#             return JsonResponse({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
#         except Exception as e:
#             return JsonResponse({"error": "Unexpected format of project_ids"},
#                                 status=status.HTTP_400_BAD_REQUEST)
#
#     def build_query_filter(self, query_filters, header = "Executive"):
#         pass
#
#
#     def get(self, request):
#         try:
#             offset = int(request.GET.get('offset', 0))
#             limit = int(request.GET.get('limit', 20))
#             project_id = json.loads(request.GET.get('project_id'))
#             tab = request.GET.get('tab')
#             search = request.GET.get('search', '')
#             sort_key = request.GET.get('sort', 'id')
#             sort_direction = request.GET.get('direction', 'ascending')
#             sub_header = request.GET.get('sub_header', '')
#             session_user = request.user
#             header = request.GET.get('header', 'Allocation-Bins')
#             filters = request.GET.get('filters', [])
#         except json.JSONDecodeError:
#             return JsonResponse({"error": "Invalid format"}, status=status.HTTP_400_BAD_REQUEST)
#
#         # Step 2: Retrieve the Mapping Record
#         billing_system_id = self.get_billing_system(project_id) if project_id else 0
#         mapping_data = model_to_dict(get_object_or_404(BillingSystemMappingRecord, pk=billing_system_id))
#
#         # map csv columns with table headers
#         filtered_dict = {}
#         for column in mapping_data:
#             filtered_dict[column] = getattr(mapping_data, column, {}).get('value', '')
#         filtered_dict = {db_field: csv_header for db_field, csv_header in filtered_dict.items() if db_field in mapping_csv_headers}
#
#
#         if tab != "fresh":
#             filtered_dict['session_user'] = 'Allocated_user'
#             filtered_dict['allocated_date'] = 'Allocated_Date'
#             filtered_dict['worked_date'] = 'Worked_Date'
#         filtered_dict['ageing_bucket'] = 'Ageing_Bucket'
#         filtered_dict['id'] = 'id'
#         # filtered_dict['created_at'] = 'created_at'
#
#         if header == 'HoldQ':
#             filtered_dict['hold'] = "hold"
#
#         # Build query filters
#         query_filters = Q(project_id=str(project_id))
#         # if header == "Executive":
#             # query_filters &= Q(session_user=session_user)
#
#         for filter_item in filters:
#             header_name = filter_item['header_name']
#             filter_option = filter_item['filter_option']
#             filter_value = filter_item['filter_value']
#
#             db_field = next((field for field, header in filtered_dict.items() if header == header_name), None)
#
#             if db_field:
#                 if filter_option == 'equals':
#                     query_filters &= Q(**{db_field: filter_value})
#                 elif filter_option == 'contains':
#                     query_filters &= Q(**{f"{db_field}__icontains": filter_value})
#                 elif filter_option == 'not_equals':
#                     query_filters &= ~Q(**{db_field: filter_value})
#                 elif filter_option == 'range':
#                     range_values = filter_value.split(',')
#                     if len(range_values) == 2:
#                         query_filters &= Q(**{f"{db_field}__range": (range_values[0], range_values[1])})
#                 elif filter_option == 'greater_than':
#                     query_filters &= Q(**{f"{db_field}__gt": filter_value})
#                 elif filter_option == 'lesser_than':
#                     query_filters &= Q(**{f"{db_field}__lt": filter_value})
#                 elif filter_option == 'date_range':
#                     start_date, end_date = filter_value.split(',')
#                     query_filters &= Q(**{f"{db_field}__range": (start_date, end_date)})
#
#         if header and header in ['Allocation-Bins', 'Review-Bins',
#                                  'HoldQ', 'Executive', 'all_records']:  # Check for either value
#             status_mapping = {
#                     'Allocation-Bins': 'allocation_status',
#                     'Review-Bins': 'review_status',
#                     'HoldQ': 'hold_status',
#                     'Executive': 'executive_status'
#                 }
#
#             # Initialize the dynamic filter criteria
#             records_filter_criteria = {}
#             status_filter = {}
#
#             # Conditional filtering values based on the header
#             if header == 'Review-Bins':
#                 records_filter_criteria = {
#                     f"review_bin_headers__icontains": sub_header.lower(),
#                     f"review_by": session_user
#                 }
#                 status_filter = {status_mapping[header]: True}
#
#             elif header == 'Allocation-Bins':
#                 records_filter_criteria = {
#                     f"current_queue__{sub_header.lower()}__icontains": tab.lower()
#                 }
#                 status_filter = {status_mapping[header]: True}
#
#             elif header == 'Executive':
#                 base_user_employee_id = UserCredentialsSetup.objects.get(id=session_user.id).employee_id
#                 records_filter_criteria = {
#                     f"executive_bin__icontains": sub_header.lower(),
#                     f"assigned_to__id": base_user_employee_id
#                 }
#                 status_filter = {status_mapping[header]: True}

#             # Get total count before pagination
#             total_records = self.count_patient_records_dynamically(query_filters, records_filter_criteria, status_filter, filtered_dict)
#
#             # Apply the filters
#             patient_records = self.fetch_patient_records_dynamically(query_filters, records_filter_criteria, status_filter, filtered_dict,
#                                                                      offset, limit)
#
#             formatted_data = []
#
#             if patient_records:
#                 for record in patient_records:
#                     record_id = record.get('id')
#                     record_codes = PatientRecordNotes.objects.prefetch_related('codes').filter(patient_record=record_id)
#
#                     if 'hold' in record:
#                         record['hold'] = record.get('hold').get('duration')
#
#                     # Map the database fields to their corresponding CSV headers
#                     formatted_record = {key: record[key] for key in filtered_dict.keys() if key in record}
#
#                     if formatted_record.get('status_code'):
#                         formatted_record['status_code'] = record_codes.get('status_code', '')
#                         formatted_record['action_code'] = record_codes.get('action_code', '')
#
#                     # Format 'service_date' to 'MM-DD-YYYY'
#                     if 'service_date' in formatted_record:
#                         service_date_str = formatted_record['service_date']
#                         service_date = datetime.strptime(service_date_str, '%Y-%m-%d') if not isinstance(
#                             service_date_str, date) else service_date_str  # Parse to datetime
#                         formatted_record['service_date'] = service_date.strftime('%m-%d-%Y')  # Reformat date
#
#                     if 'created_at' in formatted_record:
#                         created_at = formatted_record['created_at']
#
#                         # Convert aware datetime to naive datetime by removing the timezone
#                         if created_at.tzinfo is not None:
#                             created_at = created_at.replace(tzinfo=None)
#
#                         # Calculate the days difference
#                         days_since_created = (datetime.now() - created_at).days
#                         formatted_record['days_since_created'] = days_since_created
#
#                     # If 'Allocated_user' is present, retrieve user info from CredentialsForm
#                     if 'Allocated_user' in formatted_record:
#                         allocated_user_user_id = formatted_record['Allocated_user']
#                         allocated_user = UserCredentials.objects.filter(id=allocated_user_user_id).first()
#
#                         if allocated_user:
#                             # Replace user ID with first and last name
#                             formatted_record[
#                                 'Allocated_user'] = f"{allocated_user.first_name} {allocated_user.last_name}"
#                         else:
#                             # If no user found, set it to None
#                             formatted_record['Allocated_user'] = None
#
#                     # Add the formatted record to the final data list
#                     formatted_data.append(formatted_record)
#
#                 # Return the formatted data as JSON response
#                 return JsonResponse({"records": formatted_data, 'total_records': total_records})
#         return JsonResponse({"records": 'formatted_data', 'total_records': 'total_records'})

class GetWorkedPatientRecord(APIView):
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

    def get_latest_record_per_day(self):
        logs_of_month = timezone.now() - timedelta(days=30)
        return (
            PatientRecordsLogs.objects
            .filter(
                patient_record=OuterRef('patient_record'),
                updated_at__gte=logs_of_month
            )
            .annotate(date=TruncDate('updated_at'))
            .values('patient_record', 'date')
            .annotate(latest_time=Max('updated_at'))
            .values('latest_time')
        )

    def count_patient_record_logs_dynamically(self, query_filters, records_filter_criteria, filtered_dict, offset, limit):
        return (
                   PatientRecordsLogs.objects
                   .select_related('patient_record')
                   .filter(patient_record__worked_date__isnull=False)
                   .filter(updated_at__in=Subquery(self.get_latest_record_per_day()))
                   .order_by('-updated_at')
               ).filter(query_filters).values(*filtered_dict.keys())[offset:offset + limit].count()

        # return PatientRecordsLogs.objects.select_related('patient_record').filter(query_filters).values(*filtered_dict.keys())[offset:offset + limit].count()

    def fetch_patient_record_logs_dynamically(self, query_filters, records_filter_criteria, filtered_dict, offset, limit):
        return (
            PatientRecordsLogs.objects
            .select_related('patient_record')
            .filter(patient_record__worked_date__isnull=False)
            .filter(updated_at__in=Subquery(self.get_latest_record_per_day()))
            .order_by('-updated_at')
        ).filter(query_filters).values(*filtered_dict.keys())[offset:offset + limit]

        # return [log.patient_record for log in logs]
        # return PatientRecordsLogs.objects.select_related('patient_record').filter(query_filters).values(*filtered_dict.keys())[offset:offset + limit]

    def get_billing_system(self, project_id):
        try:
            # Query to filter users where project_id is in the projects list
            if isinstance(project_id, list) and len(project_id) > 0:
                project = get_object_or_404(Projects, id=project_id[0])
            elif isinstance(project_id, dict):
                project = get_object_or_404(Projects, id=project_id.get('id'))
            elif isinstance(project_id, str):
                project = get_object_or_404(Projects, id=project_id)
            elif isinstance(project_id, int):
                project = get_object_or_404(Projects, id=project_id)
            else:
                project = get_object_or_404(Projects, id=0)
            
            # Get the first billing system mapping for this project
            # Since project can have multiple billing systems, we get the first one
            billing_mapping = project.billing_project_set.first()
            
            if billing_mapping:
                return billing_mapping.pk
            else:
                return JsonResponse({"error": "No billing system found for this project"}, 
                                status=status.HTTP_404_NOT_FOUND)

        except Projects.DoesNotExist:
            return JsonResponse({"error": "Project not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return JsonResponse({"error": f"Unexpected error: {str(e)}"}, 
                            status=status.HTTP_400_BAD_REQUEST)

    def build_query_filter(self, query_filters, header="Executive"):
        pass

    def get(self, request):
        try:
            offset = int(request.GET.get('offset', 0))
            limit = int(request.GET.get('limit', 20))
            project_id = json.loads(request.GET.get('project_id'))
            tab = request.GET.get('tab')
            search = request.GET.get('search', '')
            sort_key = request.GET.get('sort', 'id')
            sort_direction = request.GET.get('direction', 'ascending')
            sub_header = request.GET.get('sub_header', '')
            user_id = request.user
            header = request.GET.get('header', 'Allocation-Bins')
            filters = request.GET.get('filters', [])
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid format"}, status=status.HTTP_400_BAD_REQUEST)

        # Step 2: Retrieve the Mapping Record
        billing_system_id = self.get_billing_system(project_id) if project_id else 0
        mapping_data = model_to_dict(get_object_or_404(BillingSystemMappingRecord, pk=billing_system_id))

        # Map CSV columns with table headers
        filtered_dict = {}
        for column in mapping_data:
            filtered_dict[column] = getattr(mapping_data, column, {}).get('value', '')
        filtered_dict = {f"patient_record__{db_field}": csv_header for db_field, csv_header in filtered_dict.items() if
                         db_field in mapping_csv_headers}

        """
        add look up fields directly into filter dict 
        """
        filtered_dict['patient_record__session_user'] = 'Allocated_user'
        filtered_dict['patient_record__allocated_date'] = 'Allocated_Date'
        filtered_dict['patient_record__worked_date'] = 'Worked_Date'
        filtered_dict['patient_record__ageing_bucket'] = 'Ageing_Bucket'
        filtered_dict['patient_record__id'] = 'id'

        # Build query filters
        query_filters = Q(patient_record__project_id=str(project_id))


        for filter_item in filters:
            """
            for table filtering
            """
            header_name = filter_item['header_name']
            filter_option = filter_item['filter_option']
            filter_value = filter_item['filter_value']

            db_field = next((field for field, header in filtered_dict.items() if header == header_name), None)

            if db_field:
                if filter_option == 'equals':
                    query_filters &= Q(**{db_field: filter_value})
                elif filter_option == 'contains':
                    query_filters &= Q(**{f"{db_field}__icontains": filter_value})
                elif filter_option == 'not_equals':
                    query_filters &= ~Q(**{db_field: filter_value})
                elif filter_option == 'range':
                    range_values = filter_value.split(',')
                    if len(range_values) == 2:
                        query_filters &= Q(**{f"{db_field}__range": (range_values[0], range_values[1])})
                elif filter_option == 'greater_than':
                    query_filters &= Q(**{f"{db_field}__gt": filter_value})
                elif filter_option == 'lesser_than':
                    query_filters &= Q(**{f"{db_field}__lt": filter_value})
                elif filter_option == 'date_range':
                    start_date, end_date = filter_value.split(',')
                    query_filters &= Q(**{f"{db_field}__range": (start_date, end_date)})

        if header and header in ['Allocation-Bins']:  # Check for Allocation-Bins worked values only
            records_filter_criteria = {}
            status_filter = {}
            status_mapping = {
                'Allocation-Bins': 'allocation_status'
            }

            # Conditional filtering values based on the header
            if header == 'Allocation-Bins':
                records_filter_criteria = {
                    f"worked_date": user_id.id
                }
                status_filter = {status_mapping[header]: True}

            # Get total count before pagination
            total_records = self.count_patient_record_logs_dynamically(query_filters, records_filter_criteria, filtered_dict, offset, limit)

            # Apply the filters
            patient_records_logs = self.fetch_patient_record_logs_dynamically(query_filters, records_filter_criteria, filtered_dict, offset, limit)

            formatted_data = []

            if patient_records_logs:
                for record in patient_records_logs:
                    record_id = record.get('patient_record__id')
                    record_codes = PatientRecordNotes.objects.prefetch_related('codes').filter(patient_record=record_id)

                    # Map the database fields to their corresponding CSV headers
                    formatted_record = {key: record[key] for key in filtered_dict.keys() if key in record}

                    if formatted_record.get('patient_record__codes') and formatted_record['status_code'] not in ['', "", []]:
                        formatted_record['status_code'] = record_codes.get('status_code', '')
                        formatted_record['action_code'] = record_codes.get('action_code', '')

                    # Format 'service_date' to 'MM-DD-YYYY'
                    if 'patient_record__service_date' in formatted_record and formatted_record['patient_record__service_date'] in ['', [], {}]:
                        service_date_str = formatted_record['patient_record__service_date']
                        service_date = datetime.strptime(service_date_str, '%Y-%m-%d') if not isinstance(
                            service_date_str, date) else service_date_str  # Parse to datetime
                        formatted_record['patient_record__service_date'] = service_date.strftime('%m-%d-%Y')  # Reformat date

                    # FIXME: check for created_at value in formatted_record / PatientRecordNotes and add created_at time to formatted record
                    if 'created_at' in formatted_record:
                        created_at = formatted_record['created_at']

                        # Convert aware datetime to naive datetime by removing the timezone
                        if created_at.tzinfo is not None:
                            created_at = created_at.replace(tzinfo=None)

                        # Calculate the days difference
                        days_since_created = (datetime.now() - created_at).days
                        formatted_record['days_since_created'] = days_since_created

                    # FIXME: validate patient_record__allocated_to field from formatted_record / PatientRecordNotes model object,
                    #  add patient_record__allocated_to to formatted_record
                    # If 'Allocated_user' is present, retrieve user info from CredentialsForm
                    if 'patient_record__allocated_to' in formatted_record:
                        user_id = formatted_record['patient_record__allocated_to']
                        allocated_user = UserCredentialsSetup.objects.filter(id=user_id).first()

                        if allocated_user:
                            # Replace user ID with first and last name
                            formatted_record[
                                'patient_record__allocated_to'] = f"{allocated_user.first_name} {allocated_user.last_name}"
                        else:
                            # If no user found, set it to None
                            formatted_record['patient_record__allocated_to'] = None

                    # Add the formatted record to the final data list
                    formatted_data.append(formatted_record)

                # Return the formatted data as JSON response
                return JsonResponse({"records": formatted_data, 'total_records': total_records})
        return JsonResponse({"records": 'formatted_data', 'total_records': 'total_records'})


@csrf_exempt
@api_view(['POST'])
def get_uploaded_records_2(request):

    
    data = json.loads(request.body)
    project_id = data.get('project_id', 1)
    offset = data.get('offset', 0)
    limit = data.get('limit', 20)
    filters = data.get('filters', [])
    tab = str(data.get('tab', 'fresh').lower())
    header = data.get('header', 'Allocation-Bins')
    sub_header = data.get('sub_header', 'AR')
    user_id = data.get('user_id') 
    

   

    # Step 1: Retrieve the Project and Billing System ID
    project = get_object_or_404(ProjectPage, project_id=project_id)
    billing_system_id = project.billing_system.id
    
    # Step 2: Retrieve the Mapping Record
    mapping_data = get_object_or_404(MappingRecord, id=billing_system_id)
    filtered_dict = {}
    for column in mapping_data:
        filtered_dict[column] = getattr(mapping_data, column, {}).get('value', '')
        print(filtered_dict)
    # mapping_dict = {'input_source': mapping_data.input_source.get('value', ''),
    #                             'mrn': mapping_data.mrn.get('value', ''),
    #                             'patient_id': mapping_data.patient_id.get('value', ''),
    #                             'account_number': mapping_data.account_number.get('value', ''),
    #                             'visit_number': mapping_data.visit_number.get('value', ''),
    #                             'chart_number': mapping_data.chart_number.get('value', ''),
    #                             'project_key': mapping_data.project_key.get('value', ''),
    #                             'facility': mapping_data.facility.get('value', ''),
    #                             'facility_type': mapping_data.facility_type.get('value', ''),
    #                             'patient_last_name': mapping_data.patient_last_name.get('value', ''),
    #                             'patient_first_name': mapping_data.patient_first_name.get('value', ''),
    #                             'patient_phone': mapping_data.patient_phone.get('value', ''),
    #                             'patient_address': mapping_data.patient_address.get('value', ''),
    #                             'patient_city': mapping_data.patient_city.get('value', ''),
    #                             'patient_state': mapping_data.patient_state.get('value', ''),
    #                             'patient_zip': mapping_data.patient_zip.get('value', ''),
    #                             'patient_birthday': mapping_data.patient_birthday.get('value', ''),
    #                             'patient_gender': mapping_data.patient_gender.get('value', ''),
    #                             'subscriber_last_name': mapping_data.subscriber_last_name.get('value', ''),
    #                             'subscriber_first_name': mapping_data.subscriber_first_name.get('value', ''),
    #                             'subscriber_relationship': mapping_data.subscriber_relationship.get('value', ''),
    #                             'subscriber_phone': mapping_data.subscriber_phone.get('value', ''),
    #                             'subscriber_address': mapping_data.subscriber_address.get('value', ''),
    #                             'subscriber_city': mapping_data.subscriber_city.get('value', ''),
    #                             'subscriber_state': mapping_data.subscriber_state.get('value', ''),
    #                             'subscriber_zip': mapping_data.subscriber_zip.get('value', ''),
    #                             'subscriber_birthday': mapping_data.subscriber_birthday.get('value', ''),
    #                             'subscriber_gender': mapping_data.subscriber_gender.get('value', ''),
    #                             'current_billed_financial_class': mapping_data.current_billed_financial_class.get('value', ''),
    #                             'current_billed_payer_name': mapping_data.current_billed_payer_name.get('value', ''),
    #                             'member_id_current_billed_payer': mapping_data.member_id_current_billed_payer.get('value', ''),
    #                             'group_number_current_billed_payer': mapping_data.group_number_current_billed_payer.get('value', ''),
    #                             'current_billed_relationship': mapping_data.current_billed_relationship.get('value', ''),
    #                             'cob': mapping_data.cob.get('value', ''),
    #                             'payer_id_current_billed_payer': mapping_data.payer_id_current_billed_payer.get('value', ''),
    #                             'timely_filing_limit': mapping_data.timely_filing_limit.get('value', ''),
    #                             'appeal_limit': mapping_data.appeal_limit.get('value', ''),
    #                             'primary_payer_financial_class': mapping_data.primary_payer_financial_class.get('value', ''),
    #                             'primary_payer_name': mapping_data.primary_payer_name.get('value', ''),
    #                             'member_id_primary_payer': mapping_data.member_id_primary_payer.get('value', ''),
    #                             'group_number_primary_payer': mapping_data.group_number_primary_payer.get('value', ''),
    #                             'relationship_primary_payer': mapping_data.relationship_primary_payer.get('value', ''),
    #                             'cob_primary': mapping_data.cob_primary.get('value', ''),
    #                             'payer_id_primary_payer': mapping_data.payer_id_primary_payer.get('value', ''),
    #                             'secondary_payer_financial_class': mapping_data.secondary_payer_financial_class.get('value', ''),
    #                             'secondary_payer_name': mapping_data.secondary_payer_name.get('value', ''),
    #                             'member_id_secondary_payer': mapping_data.member_id_secondary_payer.get('value', ''),
    #                             'group_number_secondary_payer': mapping_data.group_number_secondary_payer.get('value', ''),
    #                             'relationship_secondary_payer': mapping_data.relationship_secondary_payer.get('value', ''),
    #                             'cob_secondary': mapping_data.cob_secondary.get('value', ''),
    #                             'payer_id_secondary_payer': mapping_data.payer_id_secondary_payer.get('value', ''),
    #                             'tertiary_payer_financial_class': mapping_data.tertiary_payer_financial_class.get('value', ''),
    #                             'tertiary_payer_name': mapping_data.tertiary_payer_name.get('value', ''),
    #                             'member_id_tertiary_payer': mapping_data.member_id_tertiary_payer.get('value', ''),
    #                             'group_number_tertiary_payer': mapping_data.group_number_tertiary_payer.get('value', ''),
    #                             'relationship_tertiary_payer': mapping_data.relationship_tertiary_payer.get('value', ''),
    #                             'cob_tertiary': mapping_data.cob_tertiary.get('value', ''),
    #                             'payer_id_tertiary_payer': mapping_data.payer_id_tertiary_payer.get('value', ''),
    #                             'auth_number': mapping_data.auth_number.get('value', ''),
    #                             'claim_number': mapping_data.claim_number.get('value', ''),
    #                             'facility_code': mapping_data.facility_code.get('value', ''),
    #                             'claim_frequency_type': mapping_data.claim_frequency_type.get('value', ''),
    #                             'signature': mapping_data.signature.get('value', ''),
    #                             'assignment_code': mapping_data.assignment_code.get('value', ''),
    #                             'assign_certification': mapping_data.assign_certification.get('value', ''),
    #                             'release_info_code': mapping_data.release_info_code.get('value', ''),
    #                             'service_date': mapping_data.service_date.get('value', ''),
    #                             'van_trace_number': mapping_data.van_trace_number.get('value', ''),
    #                             'rendering_provider_id': mapping_data.rendering_provider_id.get('value', ''),
    #                             'taxonomy_code': mapping_data.taxonomy_code.get('value', ''),
    #                             'procedure_code': mapping_data.procedure_code.get('value', ''),
    #                             'amount': mapping_data.amount.get('value', ''),
    #                             'procedure_count': mapping_data.procedure_count.get('value', ''),
    #                             'tooth_code': mapping_data.tooth_code.get('value', ''),
    #                             'procedure_code2': mapping_data.procedure_code2.get('value', ''),
    #                             'amount2': mapping_data.amount2.get('value', ''),
    #                             'procedure_count2': mapping_data.procedure_count2.get('value', ''),
    #                             'tooth_code2': mapping_data.tooth_code2.get('value', ''),
    #                             'procedure_code3': mapping_data.procedure_code3.get('value', ''),
    #                             'amount3': mapping_data.amount3.get('value', ''),
    #                             'procedure_count3': mapping_data.procedure_count3.get('value', ''),
    #                             'tooth_code3': mapping_data.tooth_code3.get('value', ''),
    #                             'procedure_code4': mapping_data.procedure_code4.get('value', ''),
    #                             'amount4': mapping_data.amount4.get('value', ''),
    #                             'procedure_count4': mapping_data.procedure_count4.get('value', ''),
    #                             'tooth_code4': mapping_data.tooth_code4.get('value', ''),
    #                             'dx1': mapping_data.dx1.get('value', ''),
    #                             'dx2': mapping_data.dx2.get('value', ''),
    #                             'dx3': mapping_data.dx3.get('value', ''),
    #                             'dx4': mapping_data.dx4.get('value', ''),
    #                             'dx5': mapping_data.dx5.get('value', ''),
    #                             'dx6': mapping_data.dx6.get('value', ''),
    #                             'total_charged': mapping_data.total_charged.get('value', ''),
    #                             'check_number': mapping_data.check_number.get('value', ''),
    #                             'insurance_balance': mapping_data.insurance_balance.get('value', ''),
    #                             'patient_balance': mapping_data.patient_balance.get('value', ''),
    #                             'contract_name': mapping_data.contract_name.get('value', ''),
    #                             'division': mapping_data.division.get('value', ''),
    #                             'type_of_service': mapping_data.type_of_service.get('value', ''),
    #                             'current_queue': mapping_data.current_queue.get('value', ''),
    #                             'queue_days': mapping_data.queue_days.get('value', ''),
    #                             'lates_action_date': mapping_data.lates_action_date.get('value', ''),
    #                             'next_follow_up_before': mapping_data.next_follow_up_before.get('value', ''),
    #                             'claim_denial_date': mapping_data.claim_denial_date.get('value', ''),
    #                             'latest_pay_date': mapping_data.latest_pay_date.get('value', ''),
    #                             'latest_pay_amount': mapping_data.latest_pay_amount.get('value', ''),
    #                             # 'insurance_payment_date': mapping_data.insurance_payment_date.get('value', ''),
    #                             # 'insurance_payment_amount': mapping_data.insurance_payment_amount.get('value', ''),
    #                             # 'patient_payment_date': mapping_data.patient_payment_date.get('value', ''),
    #                             # 'patient_payment_amount': mapping_data.patient_payment_amount.get('value', ''),
    #                             # 'balance_before_appeal': mapping_data.balance_before_appeal.get('value', ''),
    #                             # 'balance_after_appeal': mapping_data.balance_after_appeal.get('value', ''),
    #                             # 'appeal_sent_date': mapping_data.appeal_sent_date.get('value', ''),
    #                             'under_pay': mapping_data.under_pay.get('value', ''),
    #                             'last_ins_disc_check_date': mapping_data.last_ins_disc_check_date.get('value', ''),
    #                             'last_ev_check_date': mapping_data.last_ev_check_date.get('value', ''),
    #                             'claim_priority': mapping_data.claim_priority.get('value', ''),
    #                             'category': mapping_data.category.get('value', ''),
    #                             'sub_category': mapping_data.sub_category.get('value', ''),
    #                             'status': mapping_data.status.get('value', ''),
    #                             'action': mapping_data.action.get('value', ''),
    #                             'provider_name': mapping_data.provider_name.get('value', ''),
    #                             'provider_npi': mapping_data.provider_npi.get('value', ''),
    #                             'provider_location': mapping_data.provider_location.get('value', ''),
    #                             'assigned_to': mapping_data.assigned_to.get('value', ''),
    #                             'last_claim_status_check_date': mapping_data.last_claim_status_check_date.get('value', ''),
    #                         }
    #
    # filtered_dict = {db_field: csv_header for db_field, csv_header in mapping_dict.items() if csv_header}

    if tab != "fresh":
        filtered_dict['current_user_id'] = 'Allocated_user'
        filtered_dict['allocated_date'] = 'Allocated_Date'
        filtered_dict['worked_date'] = 'Worked_Date'
    filtered_dict['ageing_bucket'] = 'Ageing_Bucket'
    filtered_dict['id'] = 'id'
    filtered_dict['created_at']= 'created_at'
    

    


    if header == 'HoldQ':
        filtered_dict['hold'] = "hold"

    # Build query filters
    query_filters = Q(project_id=str(project_id))
    if header == "Executive":

        query_filters &= Q(current_user_id=str(user_id))

    print("query_filters:--", query_filters)

    for filter_item in filters:
        header_name = filter_item['header_name']
        filter_option = filter_item['filter_option']
        filter_value = filter_item['filter_value']

        db_field = next((field for field, header in filtered_dict.items() if header == header_name), None)
            
        if db_field:
                if filter_option == 'equals':
                    query_filters &= Q(**{db_field: filter_value})
                elif filter_option == 'contains':
                    query_filters &= Q(**{f"{db_field}__icontains": filter_value})
                elif filter_option == 'not_equals':
                    query_filters &= ~Q(**{db_field: filter_value})
                elif filter_option == 'range':
                    range_values = filter_value.split(',')
                    if len(range_values) == 2:
                        query_filters &= Q(**{f"{db_field}__range": (range_values[0], range_values[1])})
                elif filter_option == 'greater_than':
                    query_filters &= Q(**{f"{db_field}__gt": filter_value})
                elif filter_option == 'lesser_than':
                    query_filters &= Q(**{f"{db_field}__lt": filter_value})
                elif filter_option == 'date_range':
                    start_date, end_date = filter_value.split(',')
                    query_filters &= Q(**{f"{db_field}__range": (start_date, end_date)})



    if header:

        
        if header in ['Allocation-Bins', 'Review-Bins', 'HoldQ', 'Executive', 'all_records']:  # Check for either value

            status_mapping = {
                'Allocation-Bins': 'allocation_status',
                'Review-Bins': 'review_status',
                'HoldQ' : 'hold_status',
                'Executive': 'executive_status'
            }

      
            # If it's 'Review-Bins', set the tab to the user ID
            if header == 'Review-Bins':
                tab = user_id
                allocation_name = "review_by"
                sub_header = sub_header.lower()
                # Dynamically select the status field based on the header
                status_field = status_mapping[header]

                total_records = PatientRecords.objects.filter(
                    **{status_field: 1},  # Filter based on the status field
                    **{f"{allocation_name}__contains": {sub_header: tab}}  # Filter for allocated_to (JSON field)
                ).filter(query_filters).values(*filtered_dict.keys()).count()
                
                # Apply the filters
                patient_records = PatientRecords.objects.filter(
                    **{status_field: 1},  # Filter based on the status field
                    **{f"{allocation_name}__contains": {sub_header: tab}}  # Filter for allocated_to (JSON field)
                ).filter(query_filters).values(*filtered_dict.keys())[offset:offset+limit]
            elif header == 'Allocation-Bins':
                allocation_name = "allocated_to"
                sub_header = sub_header.title()
                tab = tab
                # Dynamically select the status field based on the header
                status_field = status_mapping[header]
                
                # Get total count before pagination
                total_records = PatientRecords.objects.filter(
                    **{status_field: 1},  # Filter based on the status field
                    **{f"{allocation_name}__contains": {sub_header: tab}}  # Filter for allocated_to (JSON field)
                ).filter(query_filters).values(*filtered_dict.keys()).count()
                #############################################
                
                # Apply the filters
                patient_records = PatientRecords.objects.filter(
                    **{status_field: 1},  # Filter based on the status field
                    **{f"{allocation_name}__contains": {sub_header: tab}}  # Filter for allocated_to (JSON field)
                ).filter(query_filters).values(*filtered_dict.keys())[offset:offset+limit]

                
            elif header == 'Executive':
                allocation_name = "executive_bin"
                sub_header = sub_header.title()
                tab = tab.lower()
                # Dynamically select the status field based on the header
                status_field = status_mapping[header]

                total_records = PatientRecords.objects.filter(
                    **{status_field: 1},  # Filter based on the status field
                    **{f"{allocation_name}__contains": {sub_header: tab}}  # Filter for allocated_to (JSON field)
                ).filter(query_filters).values(*filtered_dict.keys()).count()
                
                # Apply the filters
                patient_records = PatientRecords.objects.filter(
                    **{status_field: 1},  # Filter based on the status field
                    **{f"{allocation_name}__contains": {sub_header: tab}}  # Filter for allocated_to (JSON field)
                ).filter(query_filters).values(*filtered_dict.keys())[offset:offset+limit]

            elif header == 'all_records':
                total_records = PatientRecords.objects.filter().filter(query_filters).values(*filtered_dict.keys()).count()
                patient_records = PatientRecords.objects.filter().filter(query_filters).values(*filtered_dict.keys())[offset:offset+limit]

            else:
                status_field = status_mapping[header]
                
                total_records = PatientRecords.objects.filter(
                    **{status_field: 1},  # Filter based on the status field
                ).filter(query_filters).values(*filtered_dict.keys()).count()
                
                # Apply the filters
                patient_records = PatientRecords.objects.filter(
                    **{status_field: 1},  # Filter based on the status field
                ).filter(query_filters).values(*filtered_dict.keys())[offset:offset+limit]
                

            

            formatted_data = []

            if patient_records:
                for record in patient_records:
                    record_id = record.get('id')
                    record_codes = PatientRecordNotes.objects.filter(record=record_id).values('status_code', 'action_code').last()
                    
                    
                    
                   
                    if 'hold' in record:
                        record['hold'] = record.get('hold').get('duration')
                    # Map the database fields to their corresponding CSV headers
                    formatted_record = {filtered_dict[db_field]: record[db_field] for db_field in filtered_dict}
                    # Add status_code and action_code to the record dictionary if they exist
                    
                    if formatted_record.get('status_code'):
                        formatted_record['status_code'] = record_codes.get('status_code', '')
                        formatted_record['action_code'] = record_codes.get('action_code', '')
                        
                    # Format 'service_date' to 'MM-DD-YYYY'
                    if 'service_date' in formatted_record:
                        service_date_str = formatted_record['service_date']
                        service_date = datetime.strptime(service_date_str, '%Y-%m-%d')  # Parse to datetime
                        formatted_record['service_date'] = service_date.strftime('%m-%d-%Y')  # Reformat date

                    if 'created_at' in formatted_record:
                        created_at = formatted_record['created_at']
                        
                        # Convert aware datetime to naive datetime by removing the timezone
                        if created_at.tzinfo is not None:
                            created_at = created_at.replace(tzinfo=None)
                        
                        # Calculate the days difference
                        days_since_created = (datetime.now() - created_at).days
                        formatted_record['days_since_created'] = days_since_created
                        
                    # If 'Allocated_user' is present, retrieve user info from CredentialsForm
                    if 'Allocated_user' in formatted_record:
                        user_id = formatted_record['Allocated_user']
                        allocated_user = CredentialsForm.objects.filter(id=user_id).first()

                        if allocated_user:
                            # Replace user ID with first and last name
                            formatted_record['Allocated_user'] = f"{allocated_user.first_name} {allocated_user.last_name}"
                        else:
                            # If no user found, set it to None
                            formatted_record['Allocated_user'] = None

                    # Add the formatted record to the final data list
                    formatted_data.append(formatted_record)

            # Return the formatted data as JSON response
            return JsonResponse({"records": formatted_data, 'total_records': total_records})
      
class ZeroUpload(APIView):
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

    def post(self, request, *args, **kwargs):
        # Extract data from the request
        project_id = 'PF1Z' 
        organization_id = '1X0D' 
        user_id = ''
        
        # Fetch dynamically
        project_id = request.data.get('project_id')
        organization_id = request.data.get('organization_id')
        selected_bin = request.data.get('selected_bin')
        
        file = request.FILES['file']
        if not file:
            return JsonResponse({"error": "No file provided"}, status=400)
        
        # Validate file
        if not self.is_valid_csv(file):
            return JsonResponse({"error": "Invalid file format. Please upload a CSV file."}, status=400)
        
        try:
            df = pd.read_csv(file)
        except pd.errors.EmptyDataError:
            return JsonResponse({"error": "The uploaded CSV file is empty or malformed."}, status=400)

        
        # Retrieve mapping data and column names
        mapping_dict = self.get_mapping_data(project_id, df)
        if not mapping_dict:
            return JsonResponse({"error": "Mapping data not found"}, status=400)

        # Process CSV file and map the columns
        df_filtered = self.process_csv(df, mapping_dict)
        
        # Calculate aging buckets for each record
        records = self.process_records(df_filtered, mapping_dict)

        return  JsonResponse({'sucess': 'not'}, status=400)

    def is_valid_csv(self, file):
        """Validate that the file is a CSV"""
        file_extension = file.name.split('.')[-1].lower()
        return file_extension == 'csv'
        
    def get_mapping_data(self, project_id, df):
        """Retrieve mapping data based on project_id and the CSV file"""
        try:
            project_page = ProjectPage.objects.get(project_id=project_id)
            mapping_data_instance = MappingRecord.objects.get(id=project_page.billing_system.id) if project_page.billing_system.id else None

            
            if mapping_data_instance:
                # Map columns based on the mapping data
                mapping_dict = mapColumns(mapping_data_instance, df.columns.tolist())
                return mapping_dict
        except ProjectPage.DoesNotExist:
            return None
        except MappingRecord.DoesNotExist:
            return None
    
    def process_csv(self, df, mapping_dict):
        try:
            # Check if DataFrame has columns
            if df.empty or not df.columns.any():
                return JsonResponse({"error": "No columns found in the CSV file."}, status=400)

            # Filter DataFrame to include only columns that are in the mapping dictionary
            filtered_columns = [col for col in mapping_dict.values() if mapping_dict and col in df.columns]
            return df[filtered_columns]

        except Exception as e:
            return JsonResponse({"error": "An error occurred while processing the CSV file."}, status=500)

    def process_records(self, df_filtered, mapping_dict):
        """Process the records in the filtered DataFrame"""
        records = []
        try:
            for _, row in df_filtered.iterrows():
                record = {key: row[val] for key, val in mapping_dict.items() if val in df_filtered.columns}
                service_date_str = record['service_date'] if len(record) > 0 and record['service_date'] else ''
                records.append(record)
        
            return records
        except Exception as e:
            return JsonResponse({"error": "An error occurred while processing the csv record."}, status=500)


@api_view(['POST'])
def zero_upload2(request):
    if 'file' in request.FILES:
        file = request.FILES['file']
        project_id = request.POST.get('project')
        organization_id = request.POST.get('id')
        user_id = request.POST.get('user_id')


        if file.name.endswith('.csv'):
                # Read the file into a DataFrame
                df = pd.read_csv(file)
                # print('df', df)
                df.columns = df.columns.str.strip()
                
                # Retrieve mapping data
                try:
                    project = ProjectPage.objects.get(project_id=project_id)
                    if project.billing_system_id:
                        mapping_data = MappingRecord.objects.get(id=project.billing_system_id)
                         
                        if mapping_data:
                            
                            mapping_dict = {
                                'input_source': mapping_data.input_source.get('value', ''),
                                'mrn': mapping_data.mrn.get('value', ''),
                                'patient_id': mapping_data.patient_id.get('value', ''),
                                'account_number': mapping_data.account_number.get('value', ''),
                                'visit_number': mapping_data.visit_number.get('value', ''),
                                'chart_number': mapping_data.chart_number.get('value', ''),
                                'project_key': mapping_data.project_key.get('value', ''),
                                'facility': mapping_data.facility.get('value', ''),
                                'facility_type': mapping_data.facility_type.get('value', ''),
                                'patient_last_name': mapping_data.patient_last_name.get('value', ''),
                                'patient_first_name': mapping_data.patient_first_name.get('value', ''),
                                'patient_phone': mapping_data.patient_phone.get('value', ''),
                                'patient_address': mapping_data.patient_address.get('value', ''),
                                'patient_city': mapping_data.patient_city.get('value', ''),
                                'patient_state': mapping_data.patient_state.get('value', ''),
                                'patient_zip': mapping_data.patient_zip.get('value', ''),
                                'patient_birthday': mapping_data.patient_birthday.get('value', ''),
                                'patient_gender': mapping_data.patient_gender.get('value', ''),
                                'subscriber_last_name': mapping_data.subscriber_last_name.get('value', ''),
                                'subscriber_first_name': mapping_data.subscriber_first_name.get('value', ''),
                                'subscriber_relationship': mapping_data.subscriber_relationship.get('value', ''),
                                'subscriber_phone': mapping_data.subscriber_phone.get('value', ''),
                                'subscriber_address': mapping_data.subscriber_address.get('value', ''),
                                'subscriber_city': mapping_data.subscriber_city.get('value', ''),
                                'subscriber_state': mapping_data.subscriber_state.get('value', ''),
                                'subscriber_zip': mapping_data.subscriber_zip.get('value', ''),
                                'subscriber_birthday': mapping_data.subscriber_birthday.get('value', ''),
                                'subscriber_gender': mapping_data.subscriber_gender.get('value', ''),
                                'current_billed_financial_class': mapping_data.current_billed_financial_class.get('value', ''),
                                'current_billed_payer_name': mapping_data.current_billed_payer_name.get('value', ''),
                                'member_id_current_billed_payer': mapping_data.member_id_current_billed_payer.get('value', ''),
                                'group_number_current_billed_payer': mapping_data.group_number_current_billed_payer.get('value', ''),
                                'current_billed_relationship': mapping_data.current_billed_relationship.get('value', ''),
                                'cob': mapping_data.cob.get('value', ''),
                                'payer_id_current_billed_payer': mapping_data.payer_id_current_billed_payer.get('value', ''),
                                'timely_filing_limit': mapping_data.timely_filing_limit.get('value', ''),
                                'appeal_limit': mapping_data.appeal_limit.get('value', ''),
                                'primary_payer_financial_class': mapping_data.primary_payer_financial_class.get('value', ''),
                                'primary_payer_name': mapping_data.primary_payer_name.get('value', ''),
                                'member_id_primary_payer': mapping_data.member_id_primary_payer.get('value', ''),
                                'group_number_primary_payer': mapping_data.group_number_primary_payer.get('value', ''),
                                'relationship_primary_payer': mapping_data.relationship_primary_payer.get('value', ''),
                                'cob_primary': mapping_data.cob_primary.get('value', ''),
                                'payer_id_primary_payer': mapping_data.payer_id_primary_payer.get('value', ''),
                                'secondary_payer_financial_class': mapping_data.secondary_payer_financial_class.get('value', ''),
                                'secondary_payer_name': mapping_data.secondary_payer_name.get('value', ''),
                                'member_id_secondary_payer': mapping_data.member_id_secondary_payer.get('value', ''),
                                'group_number_secondary_payer': mapping_data.group_number_secondary_payer.get('value', ''),
                                'relationship_secondary_payer': mapping_data.relationship_secondary_payer.get('value', ''),
                                'cob_secondary': mapping_data.cob_secondary.get('value', ''),
                                'payer_id_secondary_payer': mapping_data.payer_id_secondary_payer.get('value', ''),
                                'tertiary_payer_financial_class': mapping_data.tertiary_payer_financial_class.get('value', ''),
                                'tertiary_payer_name': mapping_data.tertiary_payer_name.get('value', ''),
                                'member_id_tertiary_payer': mapping_data.member_id_tertiary_payer.get('value', ''),
                                'group_number_tertiary_payer': mapping_data.group_number_tertiary_payer.get('value', ''),
                                'relationship_tertiary_payer': mapping_data.relationship_tertiary_payer.get('value', ''),
                                'cob_tertiary': mapping_data.cob_tertiary.get('value', ''),
                                'payer_id_tertiary_payer': mapping_data.payer_id_tertiary_payer.get('value', ''),
                                'auth_number': mapping_data.auth_number.get('value', ''),
                                'claim_number': mapping_data.claim_number.get('value', ''),
                                'facility_code': mapping_data.facility_code.get('value', ''),
                                'claim_frequency_type': mapping_data.claim_frequency_type.get('value', ''),
                                'signature': mapping_data.signature.get('value', ''),
                                'assignment_code': mapping_data.assignment_code.get('value', ''),
                                'assign_certification': mapping_data.assign_certification.get('value', ''),
                                'release_info_code': mapping_data.release_info_code.get('value', ''),
                                'service_date': mapping_data.service_date.get('value', ''),
                                'van_trace_number': mapping_data.van_trace_number.get('value', ''),
                                'rendering_provider_id': mapping_data.rendering_provider_id.get('value', ''),
                                'taxonomy_code': mapping_data.taxonomy_code.get('value', ''),
                                'procedure_code': mapping_data.procedure_code.get('value', ''),
                                'amount': mapping_data.amount.get('value', ''),
                                'procedure_count': mapping_data.procedure_count.get('value', ''),
                                'tooth_code': mapping_data.tooth_code.get('value', ''),
                                'procedure_code2': mapping_data.procedure_code2.get('value', ''),
                                'amount2': mapping_data.amount2.get('value', ''),
                                'procedure_count2': mapping_data.procedure_count2.get('value', ''),
                                'tooth_code2': mapping_data.tooth_code2.get('value', ''),
                                'procedure_code3': mapping_data.procedure_code3.get('value', ''),
                                'amount3': mapping_data.amount3.get('value', ''),
                                'procedure_count3': mapping_data.procedure_count3.get('value', ''),
                                'tooth_code3': mapping_data.tooth_code3.get('value', ''),
                                'procedure_code4': mapping_data.procedure_code4.get('value', ''),
                                'amount4': mapping_data.amount4.get('value', ''),
                                'procedure_count4': mapping_data.procedure_count4.get('value', ''),
                                'tooth_code4': mapping_data.tooth_code4.get('value', ''),
                                'dx1': mapping_data.dx1.get('value', ''),
                                'dx2': mapping_data.dx2.get('value', ''),
                                'dx3': mapping_data.dx3.get('value', ''),
                                'dx4': mapping_data.dx4.get('value', ''),
                                'dx5': mapping_data.dx5.get('value', ''),
                                'dx6': mapping_data.dx6.get('value', ''),
                                'total_charged': mapping_data.total_charged.get('value', ''),
                                'check_number': mapping_data.check_number.get('value', ''),
                                'insurance_balance': mapping_data.insurance_balance.get('value', ''),
                                'patient_balance': mapping_data.patient_balance.get('value', ''),
                                'contract_name': mapping_data.contract_name.get('value', ''),
                                'division': mapping_data.division.get('value', ''),
                                'type_of_service': mapping_data.type_of_service.get('value', ''),
                                'current_queue': mapping_data.current_queue.get('value', ''),
                                'queue_days': mapping_data.queue_days.get('value', ''),
                                'lates_action_date': mapping_data.lates_action_date.get('value', ''),
                                'next_follow_up_before': mapping_data.next_follow_up_before.get('value', ''),
                                'claim_denial_date': mapping_data.claim_denial_date.get('value', ''),
                                'latest_pay_date': mapping_data.latest_pay_date.get('value', ''),
                                'latest_pay_amount': mapping_data.latest_pay_amount.get('value', ''),
                                # 'insurance_payment_date': mapping_data.insurance_payment_date.get('value', ''),
                                # 'insurance_payment_amount': mapping_data.insurance_payment_amount.get('value', ''),
                                # 'patient_payment_date': mapping_data.patient_payment_date.get('value', ''),
                                # 'patient_payment_amount': mapping_data.patient_payment_amount.get('value', ''),
                                # 'balance_before_appeal': mapping_data.balance_before_appeal.get('value', ''),
                                # 'balance_after_appeal': mapping_data.balance_after_appeal.get('value', ''),
                                # 'appeal_sent_date': mapping_data.appeal_sent_date.get('value', ''),
                                'under_pay': mapping_data.under_pay.get('value', ''),
                                'last_ins_disc_check_date': mapping_data.last_ins_disc_check_date.get('value', ''),
                                'last_ev_check_date': mapping_data.last_ev_check_date.get('value', ''),
                                'claim_priority': mapping_data.claim_priority.get('value', ''),
                                'category': mapping_data.category.get('value', ''),
                                'sub_category': mapping_data.sub_category.get('value', ''),
                                'status': mapping_data.status.get('value', ''),
                                'action': mapping_data.action.get('value', ''),
                                'provider_name': mapping_data.provider_name.get('value', ''),
                                'provider_npi': mapping_data.provider_npi.get('value', ''),
                                'provider_location': mapping_data.provider_location.get('value', ''),
                                'assigned_to': mapping_data.assigned_to.get('value', ''),
                                'last_claim_status_check_date': mapping_data.last_claim_status_check_date.get('value', ''),
                                
                            }
                        else:
                            return JsonResponse({"error": "Mapping data not found"}, status=400)
                    else:
                        return JsonResponse({"error": "Project does not have a valid billing system"}, status=400)
                except ProjectPage.DoesNotExist:
                    return JsonResponse({"error": "Project not found"}, status=400)
                except MappingRecord.DoesNotExist:
                    return JsonResponse({"error": "Mapping record not found"}, status=400)

                # Map headers based on mapping_dict
                mapped_columns = {value: key for key, value in mapping_dict.items() if value}
                mapping_data_dict = model_to_dict(mapping_data) # Now mapping_data_dict is a dictionary representation of the model
               
                ###To find out unique record column ###
                record_unique = ''
                for col_name in mapped_columns.values():
                    print('col_name--', mapping_data_dict[col_name])
                    
                    if mapping_data_dict[col_name].get('unique'):
                        
                        record_unique += col_name
                    # else: 
                    #     pass
                    

                    
                filtered_columns = [col for col in mapping_dict.values() if col in df.columns]
                
                df_filtered = df[filtered_columns]
                
                for _, row in df_filtered.iterrows():
                    record = {key: row[val] for key, val in mapping_dict.items() if val in df_filtered.columns}

                    print('record====', record)

                    patient_balance_update = 0
                    if record.get('patient_balance', 0):
                        patient_balance = record['patient_balance']
                        patient_balance_update = 1 

                    insurance_balance_update =0
                    if record.get('insurance_balance', 0):
                        insurance_balance = record['insurance_balance']
                        insurance_balance_update = 1


                    #todo
                    

                    record_unique_id = record[record_unique]

                    print("record_unique_id---", record_unique, '---', record_unique_id)

                    patient_record = PatientRecords.objects.filter(**{record_unique: record_unique_id}).order_by('-created_at').first()
                    
                    
                    if patient_balance_update and insurance_balance_update:
                        notes = f''' Patient_balance was updated from "{patient_record.patient_balance}" to "{record['patient_balance']}"
                                     and insurance_balance was updated from "{patient_record.insurance_balance}" to "{record['insurance_balance']}" '''
                    elif insurance_balance_update:
                        notes = f"insurance_balance was updated from '{patient_record.insurance_balance}' to '{record['insurance_balance']}' "
                    elif patient_balance_update:
                        notes = f"Patient_balance was updated from '{patient_record.patient_balance}' to '{record['patient_balance']}' "
                    # Updating the patient_balance and insurance_balance fields if they exist
                    if patient_balance_update:
                        patient_record.patient_balance = patient_balance

                    
                    if insurance_balance_update:
                        patient_record.insurance_balance = insurance_balance

                    
                    tab_details = patient_record.allocated_to
                    for key, value in tab_details.items():
                        tab_details[key] = 'zeroed'
                    
                    print("tab_details--", tab_details)
                    
                    patient_record.allocated_to = tab_details
                    
                    
                    
                    
                    # Saving the updated patient record
                    patient_record.save()

                    

                    

                    record_id = patient_record.id

                    user_data = CredentialsForm.objects.get(id=user_id)

                    

                    full_name = user_data.first_name + ' ' + user_data.last_name
                    print("user_data==", full_name)

                    ist = pytz.timezone('Asia/Kolkata')
                    ist_time = timezone.now().astimezone(ist)
                    status = PatientRecordNotes.objects.create(record=record_id, notes=notes, user_name=full_name)

                    print("status of record notes---", status)




                    

                    

                return JsonResponse({"message": "File processed successfully"})


class GetCreateFlowChart(generics.ListCreateAPIView):
    serializer_class = FlowChartSerializer
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication)

    def get_queryset(self):
        """
        Override get_queryset to filter by project if project_id is provided
        """
        queryset = FlowChart.objects.all()
        project_id = self.request.query_params.get('project_id', None)
        
        if project_id is not None:
            # Filter by project field (assuming it's a string field)
            queryset = queryset.filter(project=project_id)
        
        return queryset.order_by('-created_at')  # Order by newest first

    def create(self, request, *args, **kwargs):
        try:
            return super().create(request, *args, **kwargs)
        except IntegrityError as e:
            return Response({"detail": "A FlowChart with this status_code already exists."},
                            status=status.HTTP_400_BAD_REQUEST)

class ManageFlowChart(generics.RetrieveUpdateDestroyAPIView):
    queryset = FlowChart.objects.all()
    serializer_class = FlowChartSerializer
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication)

class Copyflowchart(generics.ListCreateAPIView, generics.RetrieveUpdateDestroyAPIView):
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication)
    queryset = FlowChart.objects.all()
    serializer_class = FlowChartSerializer

@api_view(['GET'])
@authentication_classes((CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((permissions.AllowAny,))
def get_workflow_header_names(request):
    """
    Get workflow header names directly from database table
    """
    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns
                WHERE table_name = 'records_workflowheaders' 
                AND column_name != 'id'
                ORDER BY ordinal_position
            """)
            columns = cursor.fetchall()
            field_names = [col[0] for col in columns]
        
        return Response(field_names, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@authentication_classes((CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((permissions.AllowAny,))
def only_flowchart_headers(request):
    """
    Get only flowchart header names directly from database table
    """
    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns
                WHERE table_name = 'records_workflowheaders' 
                AND column_name != 'id'
                ORDER BY ordinal_position
            """)
            columns = cursor.fetchall()
            field_names = [col[0] for col in columns]
        
        return Response(field_names, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@authentication_classes((CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((permissions.AllowAny,))
def create_flowchart(request):
    flow_data = request.data.get('flow_data')
    name = request.data.get('name')
    project = request.data.get('project')  # Add project parameter
    
    if not flow_data or not name:
        return Response({'error': 'Flow data and name are required.'}, status=status.HTTP_400_BAD_REQUEST)
    
    flowchart = FlowChart.objects.create(
        name=name, 
        flow_data=flow_data,
        project=project if project else None
    )
    
    serializer = FlowChartSerializer(flowchart)
    return Response(serializer.data, status=status.HTTP_201_CREATED)

@api_view(['POST'])
@authentication_classes((CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((permissions.AllowAny,))
def update_flowchart(request, flow_id):
    try:
        flowchart = FlowChart.objects.get(id=flow_id)
    except FlowChart.DoesNotExist:
        return Response({'error': 'FlowChart not found.'}, status=status.HTTP_404_NOT_FOUND)
    
    flow_data = request.data.get('flow_data')
    name = request.data.get('name')
    project = request.data.get('project')
    
    if not flow_data or not name:
        return Response({'error': 'Flow data and name are required.'}, status=status.HTTP_400_BAD_REQUEST)
    
    flowchart.name = name
    flowchart.flow_data = flow_data
    if project is not None:
        flowchart.project = project
    flowchart.save()
    
    serializer = FlowChartSerializer(flowchart)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
@authentication_classes((CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((permissions.AllowAny,))
def get_flowcharts(request):
    """
    Get flowcharts with optional project filtering
    """
    project_id = request.query_params.get('project_id', None)
    
    if project_id:
        flowcharts = FlowChart.objects.filter(project=project_id).order_by('-created_at')
    else:
        flowcharts = FlowChart.objects.all().order_by('-created_at')
    
    serializer = FlowChartSerializer(flowcharts, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
@authentication_classes((CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((permissions.AllowAny,))
def get_flowcharts_by_project(request, project_id):
    """
    Get flowcharts for a specific project
    """
    try:
        flowcharts = FlowChart.objects.filter(project=project_id).order_by('-created_at')
        serializer = FlowChartSerializer(flowcharts, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@authentication_classes((CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((permissions.AllowAny,))
def get_flowchart(request, pk):
    try:
        flowchart = FlowChart.objects.get(pk=pk)
    except FlowChart.DoesNotExist:
        return Response({'error': 'Flowchart not found.'}, status=status.HTTP_404_NOT_FOUND)

    serializer = FlowChartSerializer(flowchart)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['DELETE'])
@authentication_classes((CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((permissions.AllowAny,))
def delete_flowchart(request, pk):
    try:
        flowchart = FlowChart.objects.get(pk=pk)
    except FlowChart.DoesNotExist:
        return Response({'error': 'Flowchart not found.'}, status=status.HTTP_404_NOT_FOUND)
    
    flowchart.delete()
    return Response({'message': 'Flowchart deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)

@api_view(['GET'])
@authentication_classes((CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((permissions.AllowAny,))
def flow_chart_process(request):
    project_id = request.query_params.get('project_id', None)
    
    if project_id:
        flow_chart = FlowChart.objects.filter(project=project_id).latest('created_at')
    else:
        flow_chart = FlowChart.objects.latest('created_at')
    
    req_data = (flow_chart.flow_data).get('nodes')
    label_names = []
    for each in req_data:
        if 'label' in each['data']:
            each['data']['id'] = each['id']
            label_names.append(each['data'])
            
    return Response({'data': label_names})

class FlowChartProcessView(APIView):
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication)

    def get(self, request):
        project_id = request.query_params.get('project_id', None)
        
        if project_id:
            flow_chart = FlowChart.objects.filter(project=project_id).latest('created_at')
        else:
            flow_chart = FlowChart.objects.latest('created_at')
        
        req_data = flow_chart.flow_data.get('nodes')
        label_names = []
        for each in req_data:
            if 'label' in each['data']:
                each['data']['id'] = each['id']
                label_names.append(each['data'])

        return Response({'data': label_names}, status=status.HTTP_200_OK)

class GetCreateStatusCode(APIView):
    queryset = Codes.objects.all()
    serializer_class = CodesSerializer
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

    def get(self, request):
        project_id = request.GET.get('project_ids', None)
        status_instance = self.queryset.filter(project = project_id) if project_id is not None else ''
        serializer = self.serializer_class(status_instance, many=True)
        return JsonResponse(serializer.data, safe=False, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            # Create the object and return a response
            serializer.save()
            return JsonResponse(serializer.data, status=status.HTTP_201_CREATED)
        return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Create or update a Codes
@api_view(['POST', 'PUT'])
def create_update_status_action(request, pk=None):
    if pk:
        try:
            status_action = Codes.objects.get(pk=pk)
        except Codes.DoesNotExist:
            return Response({'error': 'Status code not found'}, status=404)
    else:
        status_action = None

    if request.method == 'POST':
        serializer = CodesSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    elif request.method == 'PUT' and status_action:
        serializer = CodesSerializer(status_action, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

# View all status-action codes
@api_view(['GET'])
def view_status_actions(request):
    # Get the project parameter from the query parameters
    project_id = request.query_params.get('project', None)

    # If project_id is provided, filter the Codes based on the project
    if project_id:
        status_actions = Codes.objects.filter(project=project_id)
    else:
        status_actions = Codes.objects.all()

    # Serialize and return the data
    serializer = CodesSerializer(status_actions, many=True)
    return Response(serializer.data)


# Delete a Codes
@api_view(['DELETE'])
def delete_status_action(request, pk):
    try:
        status_action = Codes.objects.get(pk=pk)
        status_action.delete()
        return Response(status=204)
    except Codes.DoesNotExist:
        return Response({'error': 'Status code not found'}, status=404)


@api_view(['GET'])
def get_status_codes(request):
    """
    Get all status codes.
    """
    # Get the project parameter from the query parameters
    project_id = request.query_params.get('project', None)

    # If project_id is provided, filter the Codes based on the project
    if project_id:
        status_actions = Codes.objects.filter(project=project_id)
    else:
        status_actions = Codes.objects.all()

    # Serialize and return the data
    serializer = CodesSerializer(status_actions, many=True)
    return Response(serializer.data)

class GetStatusCodesView(APIView):
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)

    def get(self, request):
        """
        Get all status codes.
        """
        # Get the project parameter from the query parameters
        project_id = request.query_params.get('project', None)

        # If project_id is provided, filter the Codes based on the project
        if project_id:
            status_actions = Codes.objects.filter(project=project_id)
        else:
            status_actions = Codes.objects.all()

        # Serialize and return the data
        serializer = CodesSerializer(status_actions, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['GET'])
@authentication_classes((CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((permissions.AllowAny,))
def get_action_codes(request):
    """
    Get action codes based on a status code.
    """
    status_code_id = request.query_params.get('status_code')
    try:
        code = Codes.objects.get(id=status_code_id).values('action_codes')
        return Response(CodesSerializer(code.data))
    except Codes.DoesNotExist:
        return Response({'error': 'Status code not found'}, status=status.HTTP_404_NOT_FOUND)

class GetActionCodesView(generics.ListAPIView):
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication)
    queryset = Codes.objects.all()
    serializer_class = GetActionCodeSerializer

    def get_queryset(self):
        status_code_id = self.request.query_params.get('status_code', None)
        if status_code_id:
            return Codes.objects.filter(id=status_code_id).values('action_codes')

class ProductivityCalculationView(generics.ListAPIView):
    """
    List of Users
    No of Accounts Allocated
    No of Records Allocated
    Total Target
    Work Productivity per month
    """
    serializer_class = UserCredentialsSetupSerializer
    permission_classes = (permissions.IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication)
    
    def get_queryset(self):
        """
        This method filters users based on the client_id passed in the query parameters.
        """
        project_id = self.request.query_params.get('project_id', None)
        employee_id = self.request.query_params.get('employee_id', None)

        if not project_id:
            raise NotFound(detail="Project Selection is required", code=404)

        if employee_id:
            queryset = UserCredentialsSetup.objects.filter(employee_id=employee_id)
        else:
            queryset = UserCredentialsSetup.objects.filter(
                project_assignments__project=project_id
            )

        if not queryset.exists():
            raise NotFound(detail="No users found for the selected project", code=404)

        return queryset

    def list(self, request, *args, **kwargs):
        """
        Override the list method to include the data calculation for productivity.
        """
        queryset = self.filter_queryset(self.get_queryset())
        start_date = request.query_params.get('filtering_start_date')
        end_date = request.query_params.get('filtering_end_date')
        project_id = self.request.query_params.get('project_id')
        context = self.get_serializer_context()
        context.update({
            'filtering_start_date': start_date,
            'filtering_end_date': end_date,
            'filtering_project': project_id
        })

        serializer = self.get_serializer(queryset, many=True, context=context)
        return Response(serializer.data)

class EmployeeWorkedRecordsListView(generics.ListAPIView):
    serializer_class = PatientRecordSerializer
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication)

    def get_queryset(self):
        employee_id = self.request.query_params.get('employee_id')
        start_date = self.request.query_params.get('filtering_start_date')
        end_date = self.request.query_params.get('filtering_end_date')

        if not employee_id:
            raise NotFound("Employee ID is required")

        user = UserCredentialsSetup.objects.filter(employee_id=employee_id).first()
        if not user:
            raise NotFound("No user found")

        if not start_date or not end_date:
            raise ValidationError("Start and End date are required")

        start_date = timezone.make_aware(datetime.strptime(start_date, '%Y-%m-%d'))
        end_date = timezone.make_aware(datetime.strptime(end_date, '%Y-%m-%d'))

        return PatientRecords.objects.filter(
            patient_record_notes__note_writer=user,
            allocation_worked=True,
            worked_date__range=(start_date, end_date)
        )

@api_view(['POST'])
@authentication_classes((CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((permissions.AllowAny,))
def add_workflow_header(request):
    """
    Add a new field to WorkFlowHeaders table dynamically
    """
    try:
        field_name = request.data.get('field_name')
        field_type = request.data.get('field_type', 'TEXT')  # Default to TEXT
        
        if not field_name:
            return Response({'error': 'Field name is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate field name (alphanumeric and underscores only)
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', field_name):
            return Response({'error': 'Invalid field name. Use only letters, numbers, and underscores.'}, 
                          status=status.HTTP_400_BAD_REQUEST)
        
        # Check if field already exists
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns
                WHERE table_name = 'records_workflowheaders' 
                AND column_name = %s
            """, [field_name])
            if cursor.fetchone():
                return Response({'error': 'Field already exists'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Map field types to SQL
        field_type_mapping = {
            'TextField': 'TEXT',
            'CharField': 'VARCHAR(255)',
            'IntegerField': 'INTEGER',
            'DecimalField': 'DECIMAL(10,2)',
            'BooleanField': 'BOOLEAN DEFAULT FALSE',
            'DateField': 'DATE',
            'DateTimeField': 'TIMESTAMP',
        }
        
        sql_type = field_type_mapping.get(field_type, 'TEXT')
        
        # Add column to database
        with connection.cursor() as cursor:
            cursor.execute(f'ALTER TABLE records_workflowheaders ADD COLUMN {field_name} {sql_type}')
        
        return Response({
            'message': f'Field {field_name} added successfully',
            'field_name': field_name,
            'field_type': field_type
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['DELETE'])
@authentication_classes((CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((permissions.AllowAny,))
def remove_workflow_header(request, field_name):
    """
    Remove a field from WorkFlowHeaders table dynamically
    """
    try:
        # Check if field exists
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns
                WHERE table_name = 'records_workflowheaders' 
                AND column_name = %s
            """, [field_name])
            if not cursor.fetchone():
                return Response({'error': 'Field does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
        # Prevent removal of critical fields
        protected_fields = ['id']  # Add your critical fields here
        if field_name in protected_fields:
            return Response({'error': 'Cannot remove protected field'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Remove column from database
        with connection.cursor() as cursor:
            cursor.execute(f'ALTER TABLE records_workflowheaders DROP COLUMN {field_name}')
        
        return Response({
            'message': f'Field {field_name} removed successfully'
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@authentication_classes((CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication))
@permission_classes((permissions.AllowAny,))
def get_field_types(request):
    """
    Get available field types for dynamic field creation
    """
    field_types = [
        {'value': 'TextField', 'label': 'Text Field'},
        {'value': 'CharField', 'label': 'Short Text (255 chars)'},
        {'value': 'IntegerField', 'label': 'Number'},
        {'value': 'DecimalField', 'label': 'Decimal Number'},
        {'value': 'BooleanField', 'label': 'True/False'},
        {'value': 'DateField', 'label': 'Date'},
        {'value': 'DateTimeField', 'label': 'Date & Time'},
    ]
    return Response(field_types, status=status.HTTP_200_OK)

class DynamicHeadersView(APIView):
    """
    Combined view for managing dynamic headers directly from DB
    """
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication)

    def get(self, request):
        """Get all current headers with their DB types"""
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT column_name, data_type, is_nullable, character_maximum_length
                    FROM information_schema.columns
                    WHERE table_name = 'records_workflowheaders'
                    AND column_name != 'id'
                    ORDER BY ordinal_position
                """)
                columns = cursor.fetchall()

            fields_info = []
            for col_name, col_type, nullable, max_len in columns:
                fields_info.append({
                    'name': col_name,
                    'type': col_type,
                    'required': (nullable == 'NO'),
                    'max_length': max_len
                })

            return Response(fields_info, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        """Add a new header"""
        return add_workflow_header(request)

    def delete(self, request):
        """Remove a header"""
        field_name = request.data.get('field_name')
        if not field_name:
            return Response({'error': 'Field name is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Validate field name to prevent SQL injection
            # Only allow alphanumeric characters and underscores
            import re
            if not re.match (r'^[a-zA-Z][a-zA-Z0-9_]*$', field_name):
                return Response(
                    {'error': 'Invalid field name format'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check if column exists before trying to drop it
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = 'records_workflowheaders' 
                    AND column_name = %s
                """, [field_name])
                
                if not cursor.fetchone():
                    return Response(
                        {'error': f'Header {field_name} does not exist'}, 
                        status=status.HTTP_404_NOT_FOUND
                    )
                
                # Use string formatting for column name (since %s doesn't work for identifiers)
                # But field_name is validated above to prevent injection
                cursor.execute(f"ALTER TABLE records_workflowheaders DROP COLUMN `{field_name}`")
            
            return Response(
                {'message': f'Header {field_name} removed successfully'}, 
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            return Response(
                {'error': f'Failed to remove header: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )  

class TargetCorrectionCreateView(generics.CreateAPIView):
    """
    Create a new target correction request
    """
    serializer_class = CreateTargetCorrectionSerializer
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication)
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            # Get UserCredentialsSetup for the current user
            try:
                user_credentials = UserCredentialsSetup.objects.get(baseuser_ptr=request.user)
                target_correction = serializer.save(created_by=user_credentials)
            except UserCredentialsSetup.DoesNotExist:
                return Response(
                    {"error": "User credentials not found"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            response_serializer = TargetCorrectionSerializer(target_correction)
            return Response(response_serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class TargetCorrectionListView(generics.ListAPIView):
    """
    List target corrections (GET) and create new ones (POST)
    """
    serializer_class = TargetCorrectionSerializer
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication)
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return CreateTargetCorrectionSerializer
        return TargetCorrectionSerializer
    
    def get_queryset(self):
        queryset = TargetCorrection.objects.all()
        
        # Filter by project
        project_id = self.request.query_params.get('project_id')
        if project_id:
            queryset = queryset.filter(project_id=project_id)
        
        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Filter by employee
        employee_id = self.request.query_params.get('employee_id')
        if employee_id:
            queryset = queryset.filter(employee_id=employee_id)
        
        # Filter by date range
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        if start_date and end_date:
            queryset = queryset.filter(
                start_date__gte=start_date,
                end_date__lte=end_date
            )
        
        # Filter for approvers - show only corrections they need to approve
        show_pending_approvals = self.request.query_params.get('pending_approvals')
        if show_pending_approvals:
            try:
                user_credentials = UserCredentialsSetup.objects.get(user=self.request.user)
                queryset = queryset.filter(
                    models.Q(approver_1=user_credentials, status='pending') |
                    models.Q(approver_2=user_credentials, status='approved_level_1')
                )
            except UserCredentialsSetup.DoesNotExist:
                queryset = queryset.none()
        
        # Use created_at if available, otherwise use id
        try:
            return queryset.order_by('-created_at')
        except:
            return queryset.order_by('-id')
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            # Get UserCredentialsSetup for the current user
            try:
                user_credentials = UserCredentialsSetup.objects.get(baseuser_ptr=request.user)
                target_correction = serializer.save(created_by=user_credentials)
            except UserCredentialsSetup.DoesNotExist:
                return Response(
                    {"error": "User credentials not found"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            response_serializer = TargetCorrectionSerializer(target_correction)
            return Response(response_serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class TargetCorrectionListCreateView(generics.ListCreateAPIView):
    """
    List target corrections (GET) and create new ones (POST)
    """
    serializer_class = TargetCorrectionSerializer
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication)
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return CreateTargetCorrectionSerializer
        return TargetCorrectionSerializer
    
    def get_queryset(self):
        queryset = TargetCorrection.objects.all()
        
        # Filter by project
        project_id = self.request.query_params.get('project_id')
        if project_id:
            queryset = queryset.filter(project_id=project_id)
        
        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Filter by employee
        employee_id = self.request.query_params.get('employee_id')
        if employee_id:
            queryset = queryset.filter(employee_id=employee_id)
        
        # Filter by date range
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        if start_date and end_date:
            queryset = queryset.filter(
                start_date__gte=start_date,
                end_date__lte=end_date
            )
        
        # Filter for approvers - show only corrections they need to approve
        show_pending_approvals = self.request.query_params.get('pending_approvals')
        if show_pending_approvals:
            try:
                user_credentials = UserCredentialsSetup.objects.get(user=self.request.user)
                queryset = queryset.filter(
                    models.Q(approver_1=user_credentials, status='pending') |
                    models.Q(approver_2=user_credentials, status='approved_level_1')
                )
            except UserCredentialsSetup.DoesNotExist:
                queryset = queryset.none()
        
        # Use created_at if available, otherwise use id
        try:
            return queryset.order_by('-created_at')
        except:
            return queryset.order_by('-id')
    
    def perform_create(self, serializer):
        """Override perform_create to set created_by"""
        try:
            user_credentials = UserCredentialsSetup.objects.get(baseuser_ptr=self.request.user)
            serializer.save(created_by=user_credentials)
        except UserCredentialsSetup.DoesNotExist:
            raise serializers.ValidationError({"error": "User credentials not found"})

# Keep your existing TargetCorrectionCreateView for redundancy if needed
# But make sure it's properly configured in URLs

class TargetCorrectionDetailView(generics.RetrieveUpdateAPIView):
    """
    Retrieve and update target correction
    """
    queryset = TargetCorrection.objects.all()
    serializer_class = TargetCorrectionSerializer
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication)

class TargetCorrectionApprovalView(generics.GenericAPIView):
    """
    Handle approval/rejection of target corrections
    """
    queryset = TargetCorrection.objects.all()
    serializer_class = ApprovalActionSerializer
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication)
    
    def post(self, request, pk=None):
        target_correction = self.get_object()
        serializer = self.get_serializer(data=request.data)
        
        if serializer.is_valid():
            action = serializer.validated_data['action']
            comments = serializer.validated_data.get('comments', '')
            rejection_reason = serializer.validated_data.get('rejection_reason', '')
            
            # Get UserCredentialsSetup for the current user
            try:
                current_user_credentials = UserCredentialsSetup.objects.get(baseuser_ptr=request.user)
            except UserCredentialsSetup.DoesNotExist:
                return Response(
                    {"error": "User credentials not found"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            try:
                with transaction.atomic():
                    if action == 'approve':
                        self.handle_approval(target_correction, current_user_credentials, comments)
                    elif action == 'reject':
                        self.handle_rejection(target_correction, current_user_credentials, rejection_reason)
                
                response_serializer = TargetCorrectionSerializer(target_correction, context={'request': request})
                return Response(response_serializer.data, status=status.HTTP_200_OK)
                
            except PermissionDenied as e:
                return Response({"error": str(e)}, status=status.HTTP_403_FORBIDDEN)
            except Exception as e:
                return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def handle_approval(self, target_correction, current_user_credentials, comments):
        """Handle approval logic"""
        if (target_correction.status == 'pending' and 
            target_correction.approver_1 == current_user_credentials):
            # Level 1 approval
            target_correction.status = 'approved_level_1'
            target_correction.approved_by_level_1 = current_user_credentials
            target_correction.approved_at_level_1 = timezone.now()
            
            # If no second approver, mark as completed
            if not target_correction.approver_2:
                target_correction.status = 'completed'
                target_correction.approved_by_level_2 = current_user_credentials
                target_correction.approved_at_level_2 = timezone.now()
                
        elif (target_correction.status == 'approved_level_1' and 
              target_correction.approver_2 == current_user_credentials):
            # Level 2 approval
            target_correction.status = 'completed'
            target_correction.approved_by_level_2 = current_user_credentials
            target_correction.approved_at_level_2 = timezone.now()
            
        else:
            raise PermissionDenied("You are not authorized to approve this correction at this stage.")
        
        if comments:
            existing_comments = target_correction.comments or ""
            username = f"{current_user_credentials.first_name} {current_user_credentials.last_name}"
            new_comment = f"[{timezone.now().strftime('%Y-%m-%d %H:%M')} - {username}]: {comments}"
            target_correction.comments = f"{existing_comments}\n{new_comment}" if existing_comments else new_comment
        
        target_correction.save()
    
    def handle_rejection(self, target_correction, current_user_credentials, rejection_reason):
        """Handle rejection logic"""
        if not ((target_correction.status == 'pending' and target_correction.approver_1 == current_user_credentials) or
                (target_correction.status == 'approved_level_1' and target_correction.approver_2 == current_user_credentials)):
            raise PermissionDenied("You are not authorized to reject this correction.")
        
        target_correction.status = 'rejected'
        target_correction.rejected_by = current_user_credentials
        target_correction.rejected_at = timezone.now()
        target_correction.rejection_reason = rejection_reason
        target_correction.save()

class TargetCorrectionStatsView(generics.GenericAPIView):
    """
    Get statistics for target corrections
    """
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, TokenAuthentication)
    
    def get(self, request, *args, **kwargs):
        project_id = request.query_params.get('project_id')
        
        # Get UserCredentialsSetup for the current user
        try:
            user_credentials = UserCredentialsSetup.objects.get(baseuser_ptr=request.user)
        except UserCredentialsSetup.DoesNotExist:
            return Response({"error": "User credentials not found"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Base queryset
        queryset = TargetCorrection.objects.all()
        if project_id:
            queryset = queryset.filter(project_id=project_id)
        
        # Count pending approvals for current user
        pending_approvals = queryset.filter(
            models.Q(approver_1=user_credentials, status='pending') |
            models.Q(approver_2=user_credentials, status='approved_level_1')
        ).count()
        
        # Count by status
        stats = {
            'pending_approvals_for_user': pending_approvals,
            'total_pending': queryset.filter(status='pending').count(),
            'total_approved_level_1': queryset.filter(status='approved_level_1').count(),
            'total_completed': queryset.filter(status='completed').count(),
            'total_rejected': queryset.filter(status='rejected').count(),
        }
        
        return Re
    
# records/views.py






class TabTimingView(View):
    """Handle tab timing operations"""
    
    @method_decorator(login_required)
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)
    
    def post(self, request):
        """Save tab timing data"""
        try:
            data = json.loads(request.body)
            
            # Extract data from frontend
            tab_key = data.get('tab_key')
            user_id = data.get('user_id')
            patient_id = data.get('patient_id')
            tab_name = data.get('tab_name')
            sub_header = data.get('sub_header')
            tab_type = data.get('tab_type')
            opened_at = data.get('opened_at')
            closed_at = data.get('closed_at')
            total_active_time = data.get('total_active_time', 0)
            project_id = data.get('project_id')
            
            # Validate required fields
            if not all([tab_key, user_id, tab_name, opened_at, project_id]):
                return JsonResponse({
                    'success': False, 
                    'error': 'Missing required fields'
                }, status=400)
            
            # Get user object - FIXED: Handle case where user doesn't exist
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return JsonResponse({
                    'success': False, 
                    'error': f'User with ID {user_id} not found'
                }, status=404)
            except ValueError:
                return JsonResponse({
                    'success': False, 
                    'error': 'Invalid user ID format'
                }, status=400)
            
            # Convert datetime strings to datetime objects - FIXED: Better error handling
            try:
                opened_datetime = datetime.fromisoformat(opened_at.replace('Z', '+00:00'))
                closed_datetime = None
                if closed_at:
                    closed_datetime = datetime.fromisoformat(closed_at.replace('Z', '+00:00'))
            except ValueError as e:
                return JsonResponse({
                    'success': False, 
                    'error': f'Invalid datetime format: {str(e)}'
                }, status=400)
            
            # FIXED: Validate total_active_time is non-negative
            try:
                total_active_time = max(0, int(total_active_time))
            except (ValueError, TypeError):
                total_active_time = 0
            
            # OPTION 1: Always create new record for each tab opening
            with transaction.atomic():
                tab_timing = TabTiming.objects.create(
                    tab_key=tab_key,
                    user=user,
                    patient_id=patient_id,
                    tab_name=tab_name,
                    sub_header=sub_header or 'default',
                    tab_type=tab_type or 'unknown',
                    project_id=project_id or 'default',
                    opened_at=opened_datetime,
                    closed_at=closed_datetime,
                    total_active_time=total_active_time,
                )
                
                # Update daily activity summary
                self._update_daily_activity(
                    user=user,
                    project_id=project_id or 'default',
                    tab_type=tab_type or 'unknown',
                    sub_header=sub_header or 'default',
                    patient_id=patient_id,
                    total_active_time=total_active_time,
                    opened_datetime=opened_datetime
                )
            
            return JsonResponse({
                'success': True,
                'message': 'Tab timing saved successfully',
                'tab_timing_id': tab_timing.id,
                'created': True  # Always True now since we always create
            })
            
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False, 
                'error': 'Invalid JSON data'
            }, status=400)
        except Exception as e:
            logger.error(f"Error saving tab timing: {str(e)}", exc_info=True)
            return JsonResponse({
                'success': False, 
                'error': f'Internal server error: {str(e)}'
            }, status=500)
    
    def _update_daily_activity(self, user, project_id, tab_type, sub_header, patient_id, total_active_time, opened_datetime):
        """Update daily activity summary"""
        try:
            activity_date = opened_datetime.date()
            
            # Get or create daily activity record
            daily_activity, created = UserTabActivity.objects.get_or_create(
                user=user,
                date=activity_date,
                project_id=project_id,
                tab_type=tab_type,
                sub_header=sub_header,
                defaults={
                    'total_tabs_opened': 1,
                    'total_active_time': total_active_time,
                    'unique_patients_viewed': 1 if patient_id else 0,
                }
            )
            
            if not created:
                # Update existing record
                daily_activity.total_tabs_opened += 1
                daily_activity.total_active_time += total_active_time
                
                # Count unique patients for the day
                if patient_id:
                    unique_patients_count = TabTiming.objects.filter(
                        user=user,
                        project_id=project_id,
                        tab_type=tab_type,
                        sub_header=sub_header,
                        opened_at__date=activity_date,
                        patient_id__isnull=False
                    ).exclude(patient_id='').values('patient_id').distinct().count()
                    
                    daily_activity.unique_patients_viewed = unique_patients_count
                
                daily_activity.save()
                
        except Exception as e:
            logger.error(f"Error updating daily activity: {str(e)}", exc_info=True)


@login_required
@require_http_methods(["GET"])
def get_current_user(request):
    """Get current user ID"""
    try:
        return JsonResponse({
            'success': True,
            'user_id': request.user.id,
            'username': request.user.username if hasattr(request.user, 'username') else str(request.user)
        })
    except Exception as e:
        logger.error(f"Error getting current user: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to get user information'
        }, status=500)


@login_required
@require_http_methods(["GET"])
def get_user_tab_analytics(request):
    """Get user tab timing analytics"""
    try:
        user_id = request.GET.get('user_id', request.user.id)
        project_id = request.GET.get('project_id')
        date_from = request.GET.get('date_from')
        date_to = request.GET.get('date_to')
        tab_type = request.GET.get('tab_type')
        
        # Build query filters
        filters = {'user_id': user_id}
        
        if project_id:
            filters['project_id'] = project_id
        if tab_type:
            filters['tab_type'] = tab_type
            
        # Date range filtering
        if date_from:
            try:
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
                filters['opened_at__date__gte'] = date_from_obj
            except ValueError:
                pass
                
        if date_to:
            try:
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
                filters['opened_at__date__lte'] = date_to_obj
            except ValueError:
                pass
        
        # Get tab timing records
        tab_timings = TabTiming.objects.filter(**filters).select_related('user')
        
        # Calculate analytics
        total_tabs = tab_timings.count()
        total_active_time = tab_timings.aggregate(
            total_time=Sum('total_active_time')
        )['total_time'] or 0
        
        # Average time per tab
        avg_time_per_tab = total_active_time / total_tabs if total_tabs > 0 else 0
        
        # Most active tab types
        tab_type_stats = tab_timings.values('tab_type').annotate(
            count=Count('id'),
            total_time=Sum('total_active_time'),
            avg_time=F('total_time') / F('count')
        ).order_by('-total_time')[:10]
        
        # Daily activity breakdown
        daily_stats = tab_timings.extra(
            select={'date': 'DATE(opened_at)'}
        ).values('date').annotate(
            count=Count('id'),
            total_time=Sum('total_active_time')
        ).order_by('date')
        
        # Patient interaction stats
        patient_stats = tab_timings.filter(
            patient_id__isnull=False
        ).values('patient_id').annotate(
            visit_count=Count('id'),
            total_time=Sum('total_active_time')
        ).order_by('-total_time')[:20]
        
        return JsonResponse({
            'success': True,
            'analytics': {
                'summary': {
                    'total_tabs_opened': total_tabs,
                    'total_active_time_ms': total_active_time,
                    'total_active_time_formatted': _format_milliseconds(total_active_time),
                    'average_time_per_tab_ms': int(avg_time_per_tab),
                    'average_time_per_tab_formatted': _format_milliseconds(avg_time_per_tab),
                },
                'tab_type_breakdown': list(tab_type_stats),
                'daily_activity': list(daily_stats),
                'top_patients': list(patient_stats)
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting tab analytics: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to get analytics'
        }, status=500)


@login_required 
@require_http_methods(["GET"])
def get_daily_activity_summary(request):
    """Get daily activity summary for current user"""
    try:
        user_id = request.GET.get('user_id', request.user.id)
        date_str = request.GET.get('date', timezone.now().date().isoformat())
        project_id = request.GET.get('project_id')
        
        try:
            target_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            target_date = timezone.now().date()
        
        filters = {
            'user_id': user_id,
            'date': target_date
        }
        
        if project_id:
            filters['project_id'] = project_id
        
        # Get daily activities
        daily_activities = UserTabActivity.objects.filter(**filters)
        
        # Calculate totals
        total_summary = daily_activities.aggregate(
            total_tabs=Sum('total_tabs_opened'),
            total_time=Sum('total_active_time'),
            total_patients=Sum('unique_patients_viewed')
        )
        
        # Breakdown by tab type
        tab_breakdown = daily_activities.values(
            'tab_type', 'sub_header'
        ).annotate(
            tabs_opened=Sum('total_tabs_opened'),
            active_time=Sum('total_active_time'),
            patients_viewed=Sum('unique_patients_viewed')
        ).order_by('-active_time')
        
        return JsonResponse({
            'success': True,
            'date': date_str,
            'summary': {
                'total_tabs_opened': total_summary['total_tabs'] or 0,
                'total_active_time_ms': total_summary['total_time'] or 0,
                'total_active_time_formatted': _format_milliseconds(total_summary['total_time'] or 0),
                'unique_patients_viewed': total_summary['total_patients'] or 0,
            },
            'tab_breakdown': list(tab_breakdown)
        })
        
    except Exception as e:
        logger.error(f"Error getting daily activity: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to get daily activity'
        }, status=500)


def _format_milliseconds(ms):
    """Convert milliseconds to formatted time string"""
    if not ms:
        return "00:00:00"
    
    total_seconds = int(ms / 1000)
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60
    
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"