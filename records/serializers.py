import secrets
from datetime import date, datetime, timedelta
from django.contrib.auth.hashers import make_password
from django.utils import timezone

from rest_framework import serializers
from rest_framework.serializers import FileField

from rest_framework import serializers
from setups.models import Projects

from common.utils import send_default_user_credentials_email
from common.models import BaseModels

from setups.models import UserCredentialsSetup, TargetSettings, UserTypeBasedTarget, Projects

from . models import (PatientRecords, RuleVersions,
                            DeptartmentPage, RolesPage, SectorPage, ProjectPage, ClientPage, FlowChart,
                            StakePage, AppsPage, MappingRecord, PatientRecordNotes, TargetCorrection, ViewRules1, WorkFlowHeaders,
                            Codes, UserCredentials, RecordsUploadLogs)

from setups.models import Projects  # import the correct model
from .models import TabTiming


from django.contrib.auth import get_user_model
from .models import TabTiming, UserTabActivity

# FIXED: Use custom user model
User = get_user_model()
# Updated Serializer
class RecordsUploadLogsSerializer(serializers.ModelSerializer):
    created_by = serializers.SerializerMethodField(read_only=True)
    updated_by = serializers.SerializerMethodField(read_only=True)
    file_name = serializers.SerializerMethodField(read_only=True)
    failed_records_data = serializers.SerializerMethodField(read_only=True)
    total_records_count = serializers.SerializerMethodField(read_only=True)

    def get_created_by(self, obj):
        if obj.created_by and hasattr(obj.created_by, 'email'):
            return obj.created_by.email
        return 'Unknown'

    def get_updated_by(self, obj):
        if obj.updated_by and hasattr(obj.updated_by, 'email'):
            return obj.updated_by.email
        return 'Unknown'
    
    def get_file_name(self, obj):
        """Extract just the filename from the file path"""
        if obj.uploaded_file_name:
            return str(obj.uploaded_file_name).split('/')[-1]
        return 'Unknown'
    
    def get_failed_records_data(self, obj):
        """Return failed records data in a safe format"""
        if obj.failed_records and obj.failed_records_data:
            # Return the failed records data if it exists
            return obj.failed_records_data
        return None
    
    def get_total_records_count(self, obj):
        """Calculate total records processed"""
        new_count = obj.new_records_uploaded_count or 0
        updated_count = obj.updated_records_uploaded_count or 0
        failed_count = obj.failed_records_count or 0
        return new_count + updated_count + failed_count

    class Meta:
        model = RecordsUploadLogs
        fields = [
            'id',
            'uploaded_file_name',
            'file_name',
            'new_records_uploaded_count', 
            'updated_records_uploaded_count',
            'failed_records_count',
            'total_records_count',
            'failed_records', 
            'failed_records_data',
            'created_by', 
            'updated_by', 
            'created_at', 
            'updated_at',

            'project_id',
            'organization_id'
        ]
class CreateUserSerializers(serializers.ModelSerializer):
    class Meta:
        model = UserCredentials
        fields = ['pk', 'email', 'first_name', 'last_name', 'password', 'user_type', 'employee_id',
                  'departments', 'projects', 'clients', 'roles', 'sectors', 'stakes', 'apps']
        # fields = ['email', 'first_name', 'last_name', 'password', 'user_type']

    def create(self, validated_data):
        # Generate a password if it's not provided
        if not validated_data.pk and 'password' not in validated_data or not validated_data['password']:
            plaintext_password = secrets.token_urlsafe(20)
            validated_data['password'] =plaintext_password

            # send user credentials to login at creation time only with plain-text password
            send_default_user_credentials_email(validated_data['email'], plaintext_password)

        # Hash the password before saving
        validated_data['password'] = make_password(validated_data['password'])

        # Create and return the new user instance
        return super().create(validated_data)

    def to_representation(self, instance):
        # Get the default representation
        data = super().to_representation(instance)

        # Remove the password field if it exists
        data.pop('password', None)

        return data
class RolesPageSerializer(serializers.ModelSerializer):
    # used only if screens are readable not writable
    # screens = serializers.StringRelatedField(many=True, read_only=True)
    class Meta:
        model = RolesPage
        fields = ['role_id', 'role_name', 'screens']

class UserCredentialsSerializer(serializers.ModelSerializer):
    roles = RolesPageSerializer(many=True)
    class Meta:
        model = UserCredentials
        exclude = ('password',)

class PatientRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = PatientRecords
        fields = '__all__'

class DeptartmentPageSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeptartmentPage
        fields = '__all__'

class CredentialsFormSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserCredentials
        fields = '__all__'
        
class SectorPageSerializer(serializers.ModelSerializer):
    class Meta:
        model = SectorPage
        fields = '__all__'





class ClientPageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ClientPage
        fields = ['client_name']

class ProjectPageSerializer(serializers.ModelSerializer):
    # clients = ClientPageSerializer(many=True, read_only=True)

    class Meta:
        model = ProjectPage
        fields = ['project_id', 'project_name', 'clients', 'status', 'billing_system', 'organization_id']


class StakePageSerializer(serializers.ModelSerializer):
    class Meta:
        model = StakePage
        fields = '__all__'


class AppsPageSerializer(serializers.ModelSerializer):
    class Meta:
        model = AppsPage
        fields = '__all__'

    
class MappingRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = MappingRecord
        fields = '__all__'
        # extra_kwargs = {field.name: {'required': False} for field in MappingRecord._meta.get_fields()}

class ViewRules1Serializer(serializers.ModelSerializer):
    action = serializers.JSONField()
    projects = serializers.ListField(child=serializers.CharField())
    approvals = serializers.ListField(child=serializers.JSONField())
    rule_target = serializers.JSONField()

    # created_by = BaseUserSerializer()

    class Meta:
         model = ViewRules1
         fields = '__all__'


from rest_framework import serializers
from django.db import connection
from django.core.exceptions import ValidationError
import re


class WorkFlowHeadersSerializer(serializers.Serializer):
    """
    Dynamic serializer for WorkFlowHeaders that works directly with database columns
    instead of a traditional Django model since headers are managed dynamically.
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Dynamically add fields based on current database schema
        self._add_dynamic_fields()
    
    def _add_dynamic_fields(self):
        """
        Dynamically add fields based on current database columns
        """
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
            
            for col_name, col_type, nullable, max_len in columns:
                field = self._get_field_for_column_type(col_type, nullable, max_len)
                self.fields[col_name] = field
                
        except Exception as e:
            # If we can't get schema info, fall back to basic fields
            pass
    
    def _get_field_for_column_type(self, col_type, nullable, max_len):
        """
        Map database column types to appropriate serializer fields
        """
        required = (nullable == 'NO')
        
        field_mapping = {
            'text': serializers.CharField(required=required, allow_blank=not required),
            'varchar': serializers.CharField(
                required=required, 
                allow_blank=not required,
                max_length=max_len if max_len else 255
            ),
            'character varying': serializers.CharField(
                required=required, 
                allow_blank=not required,
                max_length=max_len if max_len else 255
            ),
            'integer': serializers.IntegerField(required=required, allow_null=not required),
            'decimal': serializers.DecimalField(
                required=required, 
                allow_null=not required,
                max_digits=10, 
                decimal_places=2
            ),
            'numeric': serializers.DecimalField(
                required=required, 
                allow_null=not required,
                max_digits=10, 
                decimal_places=2
            ),
            'boolean': serializers.BooleanField(required=required, allow_null=not required),
            'date': serializers.DateField(required=required, allow_null=not required),
            'timestamp': serializers.DateTimeField(required=required, allow_null=not required),
            'timestamp without time zone': serializers.DateTimeField(required=required, allow_null=not required),
        }
        
        return field_mapping.get(
            col_type.lower(), 
            serializers.CharField(required=required, allow_blank=not required)
        )
    
    def create(self, validated_data):
        """
        Create a new record in the workflow headers table
        """
        if not validated_data:
            raise serializers.ValidationError("No data provided")
        
        try:
            # Get column names and prepare SQL
            columns = list(validated_data.keys())
            placeholders = ', '.join(['%s'] * len(columns))
            column_names = ', '.join(columns)
            
            with connection.cursor() as cursor:
                cursor.execute(
                    f"INSERT INTO records_workflowheaders ({column_names}) VALUES ({placeholders}) RETURNING id",
                    list(validated_data.values())
                )
                row_id = cursor.fetchone()[0]
                
                # Fetch the created record
                cursor.execute(f"SELECT * FROM records_workflowheaders WHERE id = %s", [row_id])
                result = cursor.fetchone()
                
                # Get column names for result mapping
                cursor.execute("""
                    SELECT column_name 
                    FROM information_schema.columns
                    WHERE table_name = 'records_workflowheaders'
                    ORDER BY ordinal_position
                """)
                column_names = [col[0] for col in cursor.fetchall()]
                
                return dict(zip(column_names, result))
                
        except Exception as e:
            raise serializers.ValidationError(f"Error creating record: {str(e)}")
    
    def update(self, instance_id, validated_data):
        """
        Update an existing record in the workflow headers table
        """
        if not validated_data:
            raise serializers.ValidationError("No data provided")
        
        try:
            # Prepare UPDATE SQL
            set_clauses = ', '.join([f"{key} = %s" for key in validated_data.keys()])
            values = list(validated_data.values()) + [instance_id]
            
            with connection.cursor() as cursor:
                cursor.execute(
                    f"UPDATE records_workflowheaders SET {set_clauses} WHERE id = %s",
                    values
                )
                
                # Fetch the updated record
                cursor.execute(f"SELECT * FROM records_workflowheaders WHERE id = %s", [instance_id])
                result = cursor.fetchone()
                
                if not result:
                    raise serializers.ValidationError("Record not found")
                
                # Get column names for result mapping
                cursor.execute("""
                    SELECT column_name 
                    FROM information_schema.columns
                    WHERE table_name = 'records_workflowheaders'
                    ORDER BY ordinal_position
                """)
                column_names = [col[0] for col in cursor.fetchall()]
                
                return dict(zip(column_names, result))
                
        except Exception as e:
            raise serializers.ValidationError(f"Error updating record: {str(e)}")
    
    def to_representation(self, instance):
        """
        Convert database row to dictionary representation
        """
        if isinstance(instance, dict):
            return instance
        
        # If instance is a database row tuple, we need column names
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT column_name 
                    FROM information_schema.columns
                    WHERE table_name = 'records_workflowheaders'
                    ORDER BY ordinal_position
                """)
                column_names = [col[0] for col in cursor.fetchall()]
                
            if hasattr(instance, '__iter__') and not isinstance(instance, (str, bytes)):
                return dict(zip(column_names, instance))
            
        except Exception:
            pass
        
        return super().to_representation(instance)


class WorkFlowHeaderFieldSerializer(serializers.Serializer):
    """
    Serializer for managing individual workflow header fields
    """
    field_name = serializers.CharField(max_length=100, required=True)
    field_type = serializers.ChoiceField(
        choices=[
            ('TextField', 'Text Field'),
            ('CharField', 'Short Text (255 chars)'),
            ('IntegerField', 'Number'),
            ('DecimalField', 'Decimal Number'),
            ('BooleanField', 'True/False'),
            ('DateField', 'Date'),
            ('DateTimeField', 'Date & Time'),
        ],
        default='TextField'
    )
    
    def validate_field_name(self, value):
        """
        Validate field name format
        """
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', value):
            raise serializers.ValidationError(
                'Invalid field name. Use only letters, numbers, and underscores. Must start with a letter.'
            )
        
        # Check if field already exists
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    SELECT column_name 
                    FROM information_schema.columns
                    WHERE table_name = 'records_workflowheaders' 
                    AND column_name = %s
                """, [value])
                if cursor.fetchone():
                    raise serializers.ValidationError('Field already exists')
        except Exception as e:
            if 'Field already exists' in str(e):
                raise
            # If we can't check, let the view handle it
            pass
        
        return value


class WorkFlowHeaderInfoSerializer(serializers.Serializer):
    """
    Serializer for returning field information
    """
    name = serializers.CharField()
    type = serializers.CharField()
    required = serializers.BooleanField()
    max_length = serializers.IntegerField(allow_null=True)

class CodesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Codes
        fields = '__all__'

class GetActionCodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Codes
        fields = ['action_codes']

class RecordNotesSerializer(serializers.ModelSerializer):
    title = serializers.CharField(read_only=True)
    codes = serializers.PrimaryKeyRelatedField(queryset=Codes.objects.all(), many=True)
    worked_date = serializers.DateTimeField(read_only=True)

    # Define non-model fields for records processing
    notes_header = serializers.CharField(max_length=125, write_only=True)
    notes_sub_header = serializers.CharField(max_length=125, write_only=True)
    active_tab = serializers.CharField(max_length=125, write_only=True)

    class Meta:
        model = PatientRecordNotes
        fields = ['id', 'title', 'notes_descriptions', 'codes',
                  'patient_record', 'note_writer', 'worked_date',
                  'follow_up_date', 'created_by', 'updated_by',
                  'notes_header', 'notes_sub_header', 'active_tab']

    def create(self, validated_data):
        # Extract non-model fields
        notes_header = validated_data.pop('notes_header', None)
        notes_sub_header = validated_data.pop('notes_sub_header', None)
        active_tab = validated_data.pop('active_tab', None)
        follow_up_date = validated_data.get('follow_up_date', None)

        # Handle ManyToMany relationship before saving
        codes = validated_data.pop('codes', None)

        # Create PatientRecordNotes instance without ManyToMany data
        patient_record_note = PatientRecordNotes.objects.create(**validated_data)

        if codes:
            patient_record_note.codes.set(codes)

        # Get the patient record to update
        patient_record = validated_data['patient_record']
        
        # Ensure the record is assigned to the note writer
        if not patient_record.assigned_to.filter(id=patient_record_note.note_writer.id).exists():
            patient_record.assigned_to.add(patient_record_note.note_writer)
        
        # Update session user
        patient_record.session_user = patient_record_note.note_writer

        # Records moving tab logic
        record_moving_tabs = {
            'Maturated': 'touched',
            'Im_Maturated': 'workable'
        }

        record_moving_tabs_on_follow_up_date = (
            record_moving_tabs['Im_Maturated'] 
            if follow_up_date and follow_up_date > date.today() 
            else record_moving_tabs['Maturated']
        )

        # Logic for updating related PatientRecords model
        if notes_header and notes_sub_header:
            header_mapping = {
                'Allocation-bins': 'current_queue',
                'Review-bins': 'review_by',
                'HoldQ': 'hold',
                'Executive': 'executive_bin',
            }
            field_to_update = header_mapping.get(notes_header)
            
            if field_to_update:
                update_data = {
                    f"{field_to_update}": {notes_sub_header.lower(): record_moving_tabs_on_follow_up_date}
                }
                
                # Update the record
                PatientRecords.objects.filter(id=patient_record.id).update(
                    allocation_allocated=True,  # Mark as allocated
                    allocation_fresh=False,     # No longer fresh
                    allocation_worked=True,     # Mark as worked
                    worked_date=timezone.now(),
                    **update_data,
                )

        return patient_record_note

class FlowChartSerializer(serializers.ModelSerializer):
    project_name = serializers.SerializerMethodField(read_only=True)
    status_code = serializers.PrimaryKeyRelatedField(queryset=Codes.objects.all())
    status_code_title = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = FlowChart
        fields = ['id', 'name', 'flow_data', 'project', 'project_name', 'status_code', 'status_code_title', 'created_at', 'updated_at']

    # Note : model definition's one to one field can handle this validation
    # def validate_status_code(self, value):
    #     """Ensure status_code is not duplicated."""
    #     if FlowChart.objects.filter(status_code=value).exists():
    #         raise serializers.ValidationError("This status_code is already used by another FlowChart.")
    #     return value

    def get_status_code_title(self, obj):
        return  Codes.objects.select_related('flow_chart_status_code').filter(flow_chart_status_code=obj).values('status_code')

    def get_project_name(self, obj):
        # Assuming 'project' field in FlowChart contains the project ID (as a char field)
        try:
            return Projects.objects.filter(id=obj.project).values('project_name') # Using 'project' field value (which is the project ID)
        except Projects.DoesNotExist:
            return None

class RuleVersionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = RuleVersions
        fields = '__all__'
        
class UploadRecordsSerializer(serializers.Serializer):
    file_uploaded = FileField()
    class Meta:
        fields = ['file_uploaded']

class ReadTargetCountSerializer(serializers.ModelSerializer):
    records_target_count = serializers.IntegerField()
    total_working_hours = serializers.IntegerField()
    class Meta:
        model = TargetSettings
        fields = ['records_target_count', 'total_working_hours']

class UserTypeBasedTargetSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserTypeBasedTarget
        fields = '__all__'

class UserCredentialsSetupSerializer(serializers.ModelSerializer):
    # employee full name
    employee_name = serializers.SerializerMethodField()

    # Calculating the number of records assigned
    records_assigned_count = serializers.SerializerMethodField()

    # Calculating the number of records worked
    records_worked_count = serializers.SerializerMethodField()

    # Calculating total target productivity (assigned / worked) in user_date_of_joining to datetime.now()
    productivity = serializers.SerializerMethodField()

    # target assigned and working hours
    target = serializers.SerializerMethodField()

    final_target = serializers.SerializerMethodField()
    def get_final_target(self, obj):
        """Get final target considering any approved target corrections"""
        filtering_start_date = self.context.get('filtering_start_date')
        filtering_end_date = self.context.get('filtering_end_date')
        project_id = self.context.get('filtering_project')
        
        if not filtering_start_date or not filtering_end_date:
            return self.get_target(obj)
        
        if isinstance(filtering_start_date, str):
            filtering_start_date = datetime.strptime(filtering_start_date, '%Y-%m-%d').date()
        if isinstance(filtering_end_date, str):
            filtering_end_date = datetime.strptime(filtering_end_date, '%Y-%m-%d').date()
        
        # Check for approved target corrections in the date range
        approved_correction = TargetCorrection.objects.filter(
            employee_id=obj.employee_id,
            project_id=project_id,
            status='completed',
            start_date__lte=filtering_end_date,
            end_date__gte=filtering_start_date
        ).order_by('-created_at').first()
        
        if approved_correction:
            return approved_correction.final_target
        
        return self.get_target(obj)
    
    class Meta:
        model = UserCredentialsSetup
        fields = ['id', 'employee_id', 'employee_name', 'user_date_of_joining', 'records_assigned_count', 
                  'records_worked_count', 'productivity', 'target', 'final_target']

    def get_employee_name(self, obj):
        return f"{obj.first_name} {obj.last_name}"

    def get_computed_target_for_date_range(self, user, start_date, end_date):
        experience_field = user.experience_level.lower() + "_targets"
        total_target = 0

        for assignment in user.project_assignments.select_related('project').all():
            join_date = assignment.project_joined_date.date()

            try:
                target_setting = assignment.project.project_target_settings
            except TargetSettings.DoesNotExist:
                continue

            allocations = target_setting.target_allocation.all()

            for alloc in allocations:
                week_num = alloc.targeting_week
                week_start = join_date + timedelta(days=(week_num - 1) * 7)
                week_end = week_start + timedelta(days=6)

                # Check overlap with input date range
                if week_end < start_date or week_start > end_date:
                    continue

                percentage = getattr(alloc, experience_field, None)
                if percentage:
                    computed = int((percentage / 100) * target_setting.records_target_count)
                    total_target += computed

        return total_target

    def get_target(self, obj):
        filtering_start_date = self.context.get('filtering_start_date')
        filtering_end_date = self.context.get('filtering_end_date')

        if isinstance(filtering_start_date, str):
            filtering_start_date = datetime.strptime(filtering_start_date, '%Y-%m-%d').date()
        if isinstance(filtering_end_date, str):
            filtering_end_date = datetime.strptime(filtering_end_date, '%Y-%m-%d').date()

        if not filtering_start_date or not filtering_end_date:
            return None

        return self.get_computed_target_for_date_range(obj, filtering_start_date, filtering_end_date)

    def get_records_assigned_count(self, obj):
        filtering_start_date = self.context.get('filtering_start_date')
        filtering_end_date = self.context.get('filtering_end_date')

        if isinstance(filtering_start_date, str):
            filtering_start_date = datetime.strptime(filtering_start_date, '%Y-%m-%d')
        if isinstance(filtering_end_date, str):
            filtering_end_date = datetime.strptime(filtering_end_date, '%Y-%m-%d')

        if not filtering_start_date or not filtering_end_date:
            return None

        # Make them timezone-aware (optional based on settings.USE_TZ)
        filtering_start_date = timezone.make_aware(filtering_start_date)
        filtering_end_date = timezone.make_aware(filtering_end_date)

        return PatientRecords.objects.filter(
            assigned_to=obj,
        ).count()

    def get_records_worked_count(self, obj):
        filtering_start_date = self.context.get('filtering_start_date')
        filtering_end_date = self.context.get('filtering_end_date')

        if isinstance(filtering_start_date, str):
            filtering_start_date = datetime.strptime(filtering_start_date, '%Y-%m-%d')
        if isinstance(filtering_end_date, str):
            filtering_end_date = datetime.strptime(filtering_end_date, '%Y-%m-%d')

        if not filtering_start_date or not filtering_end_date:
            return None

        filtering_start_date = timezone.make_aware(filtering_start_date)
        filtering_end_date = timezone.make_aware(filtering_end_date)

        return PatientRecords.objects.filter(
            allocation_worked=True,
            patient_record_notes__note_writer=obj,
            patient_record_notes__worked_date__range=(filtering_start_date, filtering_end_date)
        ).distinct().count()

    def get_records_assigned_date(self, obj):
        return PatientRecords.objects.filter(
            assigned_to=obj
        ).order_by('-allocated_date').values('allocated_date').first()

    def calculate_productivity_fixed_weekly_target(
            self,
            assigned_date: str,
            filtered_days: int,
            actual_done: int,
            average_target_per_week: int,
    ):
        """
        Parameters:
            assigned_date (str): Date records were assigned in 'YYYY-MM-DD' format.
            filtered_days (int): Number of days from assigned_date to consider.
            actual_done (int): Number of records completed by the employee.
            average_target_per_week (int): Default weekly target.
        Returns:
            float: Productivity percentage
        """
        # Calculate expected work in filtered range
        expected_work = (average_target_per_week / 7) * filtered_days
        productivity = (actual_done / expected_work) * 100 if expected_work > 0 else 0
        return round(productivity, 2)

    def get_productivity(self, obj):
        filtering_start_date = self.context.get('filtering_start_date')
        filtering_end_date = self.context.get('filtering_end_date')
        assigned_date = self.get_records_assigned_date(obj)

        if isinstance(filtering_start_date, str):
            filtering_start_date = datetime.strptime(filtering_start_date, '%Y-%m-%d')
        if isinstance(filtering_end_date, str):
            filtering_end_date = datetime.strptime(filtering_end_date, '%Y-%m-%d')
        if isinstance(assigned_date, str):
            assigned_date = datetime.strptime(assigned_date, '%Y-%m-%d')

        if not filtering_start_date or not filtering_end_date:
            return 0

        filtering_start_date = timezone.make_aware(filtering_start_date)
        filtering_end_date = timezone.make_aware(filtering_end_date)

        target_count = self.get_target(obj)

        worked_count = self.get_records_worked_count(obj)

        # Calculate days between filtering range
        total_filtering_days = (filtering_end_date - filtering_start_date).days + 1  # +1 to include the end day

        if total_filtering_days <= 0:
            return 0

        # Calculate productivity ratio
        return self.calculate_productivity_fixed_weekly_target(assigned_date, total_filtering_days, worked_count, target_count)

class ShowProductivityWorkedRecordSerializer(serializers.ModelSerializer):
    # Calculating the number of records worked
    records_worked_count = serializers.SerializerMethodField()

    class Meta:
        model = UserCredentialsSetup
        fields = ['records_worked_count']

    def get_records_worked_count(self, obj):
        filtering_start_date = self.context.get('filtering_start_date')
        filtering_end_date = self.context.get('filtering_end_date')

        if isinstance(filtering_start_date, str):
            filtering_start_date = datetime.strptime(filtering_start_date, '%Y-%m-%d')
        if isinstance(filtering_end_date, str):
            filtering_end_date = datetime.strptime(filtering_end_date, '%Y-%m-%d')

        if not filtering_start_date or not filtering_end_date:
            return None

        filtering_start_date = timezone.make_aware(filtering_start_date)
        filtering_end_date = timezone.make_aware(filtering_end_date)

        return PatientRecords.objects.filter(
            allocation_worked=True,
            session_user=obj,
            worked_date__range=(filtering_start_date, filtering_end_date)
        )

class TargetCorrectionSerializer(serializers.ModelSerializer):
    created_by_name = serializers.SerializerMethodField()
    project_name = serializers.SerializerMethodField()
    project_id = serializers.SerializerMethodField()
    approver_1_name = serializers.SerializerMethodField()
    approver_2_name = serializers.SerializerMethodField()
    approved_by_level_1_name = serializers.SerializerMethodField()
    approved_by_level_2_name = serializers.SerializerMethodField()
    rejected_by_name = serializers.SerializerMethodField()
    can_approve = serializers.SerializerMethodField()
    next_approver_name = serializers.SerializerMethodField()
    
    class Meta:
        model = TargetCorrection
        fields = [
            'id', 'employee_id', 'employee_name', 'old_target', 'new_target', 
            'final_target', 'project', 'project_id', 'project_name', 'start_date', 'end_date',
            'status', 'approver_1', 'approver_1_name', 'approver_2', 'approver_2_name',
            'approved_by_level_1', 'approved_by_level_1_name', 'approved_at_level_1',
            'approved_by_level_2', 'approved_by_level_2_name', 'approved_at_level_2',
            'rejected_by', 'rejected_by_name', 'rejected_at', 'rejection_reason',
            'created_by', 'created_by_name', 'created_at', 'updated_at', 'comments',
            'can_approve', 'next_approver_name'
        ]
    
    def get_created_by_name(self, obj):
        if obj.created_by:
            return f"{obj.created_by.first_name} {obj.created_by.last_name}".strip()
        return None
        
    def get_project_name(self, obj):
        return obj.project.project_name if obj.project else None
        
    def get_project_id(self, obj):
        return obj.project.id if obj.project else None
        
    def get_approver_1_name(self, obj):
        if obj.approver_1:
            return f"{obj.approver_1.first_name} {obj.approver_1.last_name}".strip()
        return None
        
    def get_approver_2_name(self, obj):
        if obj.approver_2:
            return f"{obj.approver_2.first_name} {obj.approver_2.last_name}".strip()
        return None
        
    def get_approved_by_level_1_name(self, obj):
        if obj.approved_by_level_1:
            return f"{obj.approved_by_level_1.first_name} {obj.approved_by_level_1.last_name}".strip()
        return None
        
    def get_approved_by_level_2_name(self, obj):
        if obj.approved_by_level_2:
            return f"{obj.approved_by_level_2.first_name} {obj.approved_by_level_2.last_name}".strip()
        return None
        
    def get_rejected_by_name(self, obj):
        if obj.rejected_by:
            return f"{obj.rejected_by.first_name} {obj.rejected_by.last_name}".strip()
        return None
    
    def get_can_approve(self, obj):
        """Check if the current user (from context) can approve this correction"""
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            try:
                user_credentials = UserCredentialsSetup.objects.get(baseuser_ptr=request.user)
                return obj.can_be_approved_by(user_credentials)
            except UserCredentialsSetup.DoesNotExist:
                return False
        return False
    
    def get_next_approver_name(self, obj):
        """Get the name of the next approver"""
        if hasattr(obj, 'get_next_approver'):
            next_approver = obj.get_next_approver()
            if next_approver:
                return f"{next_approver.first_name} {next_approver.last_name}".strip()
        return None


class CreateTargetCorrectionSerializer(serializers.ModelSerializer):
    date_range = serializers.DictField(write_only=True)
    project_id = serializers.IntegerField(write_only=True)
    
    class Meta:
        model = TargetCorrection
        fields = [
            'employee_id', 'employee_name', 'old_target', 'new_target',
            'final_target', 'project_id', 'approver_1', 'approver_2',
            'date_range', 'comments'
        ]
    
    def validate_project_id(self, value):
        """Validate that the project exists"""
        try:
            Projects.objects.get(id=value)
            return value
        except Projects.DoesNotExist:
            raise serializers.ValidationError(f"Project with ID {value} does not exist")
    
    def validate_approver_1(self, value):
        """Validate that approver_1 exists"""
        try:
            # If value is already a UserCredentialsSetup instance, return it
            if isinstance(value, UserCredentialsSetup):
                return value
            # Otherwise, try to get it by ID
            user_creds = UserCredentialsSetup.objects.get(id=value)
            return user_creds
        except (UserCredentialsSetup.DoesNotExist, ValueError, TypeError):
            raise serializers.ValidationError(f"UserCredentialsSetup with ID {value} does not exist")
    
    def validate_approver_2(self, value):
        """Validate that approver_2 exists (if provided)"""
        if not value:
            return None
        try:
            # If value is already a UserCredentialsSetup instance, return it
            if isinstance(value, UserCredentialsSetup):
                return value
            # Otherwise, try to get it by ID
            user_creds = UserCredentialsSetup.objects.get(id=value)
            return user_creds
        except (UserCredentialsSetup.DoesNotExist, ValueError, TypeError):
            raise serializers.ValidationError(f"UserCredentialsSetup with ID {value} does not exist")
    
    def validate(self, attrs):
        """Additional validation"""
        # Check for duplicate pending corrections for the same employee in the same date range
        employee_id = attrs.get('employee_id')
        project_id = attrs.get('project_id')
        date_range = attrs.get('date_range', {})
        
        if employee_id and project_id and date_range:
            try:
                start_date = datetime.strptime(date_range['start_date'], '%Y-%m-%d').date()
                end_date = datetime.strptime(date_range['end_date'], '%Y-%m-%d').date()
                
                existing_pending = TargetCorrection.objects.filter(
                    employee_id=employee_id,
                    project_id=project_id,
                    start_date=start_date,
                    end_date=end_date,
                    status__in=['pending', 'approved_level_1']
                ).exists()
                
                if existing_pending:
                    raise serializers.ValidationError(
                        "There is already a pending target correction for this employee in the same date range."
                    )
            except (ValueError, KeyError) as e:
                raise serializers.ValidationError("Invalid date format in date_range")
        
        # Ensure new_target is different from old_target
        if attrs.get('new_target') == attrs.get('old_target'):
            raise serializers.ValidationError("New target must be different from old target.")
        
        # Validate target values are positive numbers
        if attrs.get('new_target', 0) < 0:
            raise serializers.ValidationError("New target must be a positive number.")
        
        if attrs.get('final_target', 0) < 0:
            raise serializers.ValidationError("Final target must be a positive number.")
        
        return attrs
        
    def create(self, validated_data):
        date_range = validated_data.pop('date_range')
        try:
            validated_data['start_date'] = datetime.strptime(date_range['start_date'], '%Y-%m-%d').date()
            validated_data['end_date'] = datetime.strptime(date_range['end_date'], '%Y-%m-%d').date()
        except (ValueError, KeyError):
            raise serializers.ValidationError("Invalid date format in date_range")
        
        # Get project instance
        project_id = validated_data.pop('project_id', None)
        if not project_id:
            raise serializers.ValidationError("Project ID is required")
            
        try:
            validated_data['project'] = Projects.objects.get(id=project_id)
        except Projects.DoesNotExist:
            raise serializers.ValidationError(f"Project with ID {project_id} does not exist")
        
        return super().create(validated_data)


class ApprovalActionSerializer(serializers.Serializer):
    ACTION_CHOICES = [
        ('approve', 'Approve'),
        ('reject', 'Reject'),
    ]
    
    action = serializers.ChoiceField(choices=ACTION_CHOICES)
    comments = serializers.CharField(required=False, allow_blank=True)
    rejection_reason = serializers.CharField(required=False, allow_blank=True)
    
    def validate(self, attrs):
        if attrs.get('action') == 'reject' and not attrs.get('rejection_reason'):
            raise serializers.ValidationError("Rejection reason is required when rejecting.")
        return attrs

class TargetCorrectionStatsSerializer(serializers.Serializer):
    """Serializer for target correction statistics"""
    pending_approvals_for_user = serializers.IntegerField()
    total_pending = serializers.IntegerField()
    total_approved_level_1 = serializers.IntegerField()
    total_completed = serializers.IntegerField()
    total_rejected = serializers.IntegerField()




class TabTimingSerializer(serializers.ModelSerializer):
    class Meta:
        model = TabTiming
        fields = [
            "tab_key",
            "user",
            "patient_id",
            "tab_name",
            "sub_header",
            "tab_type",
            "project_id",
            "opened_at",
            "closed_at",
            "total_active_time",
        ]
        extra_kwargs = {
            "patient_id": {"required": False, "allow_blank": True},
            "closed_at": {"required": False},
            "total_active_time": {"required": False},
        }

    def validate(self, data):
        """
        Custom validation for required fields and logical checks.
        """
        if not data.get("tab_key"):
            raise serializers.ValidationError({"tab_key": "Tab key is required."})
        if not data.get("tab_name"):
            raise serializers.ValidationError({"tab_name": "Tab name is required."})
        if not data.get("sub_header"):
            raise serializers.ValidationError({"sub_header": "Sub header is required."})
        if not data.get("tab_type"):
            raise serializers.ValidationError({"tab_type": "Tab type is required."})
        if not data.get("project_id"):
            raise serializers.ValidationError({"project_id": "Project ID is required."})
        if not data.get("opened_at"):
            raise serializers.ValidationError({"opened_at": "Opened time is required."})

        # Ensure closed_at >= opened_at
        if data.get("closed_at") and data["closed_at"] < data["opened_at"]:
            raise serializers.ValidationError({"closed_at": "Closed time cannot be before opened time."})

        return data


class UserTabActivitySerializer(serializers.ModelSerializer):
    class Meta:
        model = UserTabActivity
        fields = '__all__'