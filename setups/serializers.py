import secrets

from actstream.views import model
from rest_framework import serializers
from django.contrib.auth.hashers import make_password

from . models import (UserCredentialsSetup, UserProjectAssignment,
                      Apps, Organizations,Roles, ScreensChoices, ExperienceLevelChoices,
                      PIPLevels, Clients, Projects,
                      BillingSystemMappingRecord, Departments, Stakes,
                      CustomBins, UserTypeBasedTarget, TargetSettings)


from common.utils import send_default_user_credentials_email
# from common.models import BaseModels
from users.models import UserTypeChoices


from .models import Insurance


class AppsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Apps
        fields = ['id', 'app_name']

class OrganizationSerializer(serializers.ModelSerializer):
    apps = serializers.PrimaryKeyRelatedField(queryset=Apps.objects.all(), many=True)

    class Meta:
        model = Organizations
        fields = ['id', 'organization_name', 'apps']

    def create(self, validated_data):
        apps = validated_data.pop('apps', [])
        organization = Organizations.objects.create(**validated_data)
        organization.apps.set(apps)
        return organization

class RolesSerializer(serializers.ModelSerializer):
    screens = serializers.MultipleChoiceField(
        choices=[(choice.value, choice.name) for choice in ScreensChoices],
        required=True
    )

    class Meta:
        model = Roles
        fields = ['id', 'role_name', 'screens', 'organization']

    def to_internal_value(self, data):
        # Convert the list of choices back to a list of values
        screens = data.get('screens')
        if screens:
            data['screens'] = screens
        return super().to_internal_value(data)

    def to_representation(self, instance):
        # Convert the list of values back to a list of choices
        data = super().to_representation(instance)
        screens = instance.screens
        data['screens'] = [choice.value for choice in ScreensChoices if choice.value in screens]
        return data

class ClientSerializer(serializers.ModelSerializer):
    class Meta:
        model = Clients
        fields = ['id', 'client_name', 'status', 'organization']

class ProjectsSerializer(serializers.ModelSerializer):
    # clients = serializers.PrimaryKeyRelatedField(queryset=Clients.objects.all(), many=True)
    # clients = ClientSerializer(many=True)
    class Meta:
        model = Projects
        fields = ['id', 'project_name', 'status', 'clients', 'organization']


# serializers.py - Updated BillingSystemMappingSerializer

class BillingSystemMappingSerializer(serializers.ModelSerializer):
    mapping = serializers.JSONField(write_only=True, required=False, allow_null=True)
    is_cpt_level = serializers.BooleanField(default=False)  # NEW: Add CPT level field
    
    class Meta:
        model = BillingSystemMappingRecord
        fields = '__all__'
        extra_kwargs = {
            'organization': {'write_only': False},
        }

    def create(self, validated_data):
        mapping_data = validated_data.pop('mapping', {})
        is_cpt_level = validated_data.pop('is_cpt_level', False)  # NEW: Handle CPT level
        
        instance = super().create(validated_data)
        instance.is_cpt_level = is_cpt_level  # NEW: Set CPT level
        instance.save()
        
        return self._update_mapping(instance, mapping_data)

    def update(self, instance, validated_data):
        mapping_data = validated_data.pop('mapping', {})
        is_cpt_level = validated_data.pop('is_cpt_level', instance.is_cpt_level)  # NEW: Handle CPT level
        
        instance = super().update(instance, validated_data)
        instance.is_cpt_level = is_cpt_level  # NEW: Update CPT level
        instance.save()
        
        return self._update_mapping(instance, mapping_data)

    def _update_mapping(self, instance, mapping_data):
        if mapping_data:
            for field_name in self.Meta.model._meta.get_fields():
                if field_name.name in mapping_data:
                    setattr(instance, field_name.name, mapping_data[field_name.name])
            instance.save()
        return instance

class DepartmentsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Departments
        fields = '__all__'

class StakesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Stakes
        fields = '__all__'

class ListApprovalUserSerializer(serializers.ModelSerializer):
    approve_user_1_name = serializers.SerializerMethodField()
    approve_user_2_name = serializers.SerializerMethodField()

    class Meta:
        model = UserCredentialsSetup
        fields = [
            'pk',
            'first_name',
            'last_name',
            'approve_user_1_name',
            'approve_user_2_name',
            'approve_1_employee_id',
            'approve_2_employee_id'
        ]

    def get_approve_user_1_name(self, obj):
        user = getattr(obj, 'approve_user_1', None)
        if user:
            return f"{user.first_name} {user.last_name}".strip()
        return None

    def get_approve_user_2_name(self, obj):
        user = getattr(obj, 'approve_user_2', None)
        if user:
            return f"{user.first_name} {user.last_name}".strip()
        return None

class GetUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserCredentialsSetup
        fields = ['pk', 'first_name', 'last_name']

class GetApproveNamesSerializers(serializers.ModelSerializer):
    class Meta:
        model = UserCredentialsSetup
        fields = ['pk', 'first_name', 'last_name',
                  'approve_user_1', 'approve_1_employee_id',
                  'approve_user_2', 'approve_2_employee_id',]


class UserCredentialsSetupSerializers(serializers.ModelSerializer):
    roles = RolesSerializer(many=True, read_only=True)
    departments = DepartmentsSerializer(many=True, read_only=True)
    clients = ClientSerializer(many=True, read_only=True)
    organizations = OrganizationSerializer(many=True, read_only=True)
    stakes = StakesSerializer(many=True, read_only=True)
    apps = AppsSerializer(many=True, read_only=True)

    user_type = serializers.ChoiceField(
        choices=[(choice.value, choice.name) for choice in UserTypeChoices],
        required=True
    )

    experience_level = serializers.ChoiceField(
        choices=[(choice.value, choice.name) for choice in ExperienceLevelChoices],
        required=True
    )

    user_date_of_joining = serializers.DateField(required=False)

    # PIP fields
    pip_level_flag = serializers.BooleanField(default=False)
    pip_start_date = serializers.DateField(required=False, allow_null=True)
    pip_end_date = serializers.DateField(required=False, allow_null=True)
    pip_level = serializers.ChoiceField(
        choices=[(choice.value, choice.name) for choice in PIPLevels],
        required=False,
        allow_blank=True,
        allow_null=True
    )

    projects = serializers.SerializerMethodField()
    project_joined_date = serializers.DateField(required=False)

    def validate(self, data):
        pip_flag = data.get('pip_level_flag', False)

        if pip_flag:
            # These fields are required if pip_level_flag is true
            missing = []
            if not data.get('pip_level'):
                missing.append('pip_level')
            if not data.get('pip_start_date'):
                missing.append('pip_start_date')
            if not data.get('pip_end_date'):
                missing.append('pip_end_date')

            if missing:
                raise serializers.ValidationError({
                    field: 'This field is required when pip_level_flag is True.'
                    for field in missing
                })

        return data

    def get_projects(self, instance):
            """
            Retrieve project details (name and join date) from UserProjectAssignment.
            """
            return [
                {
                    "project_name": assignment.project.project_name,
                    "project_joined_date": assignment.project_joined_date
                }
                for assignment in instance.project_assignments.all()
            ]
    class Meta:
        model = UserCredentialsSetup
        fields = ['pk', 'email', 'first_name', 'last_name', 'password', 'is_superuser',
                  'user_type', 'employee_id', 'approve_user_1', 'approve_1_employee_id',
                  'approve_user_2', 'approve_2_employee_id',
                  'experience_level', 'user_date_of_joining',
                  'pip_level_flag', 'pip_start_date', 'pip_end_date', 'pip_level',
                  'project_joined_date',
                  'apps', 'organizations', 'clients', 'projects',
                  'roles', 'departments', 'stakes']


        extra_kwargs = {
            'password': {'write_only': True}
        }

    def to_internal_value(self, data):
        # Convert the list of choices back to a list of values
        user_type = data.get('user_type')
        if user_type:
            data['user_type'] = user_type
        return super().to_internal_value(data)

    def validate(self, attrs):
        errors = {}

        # Validate approval 1 employee ID
        approve_1_id = attrs.get('approve_1_employee_id')
        if approve_1_id:
            if not UserCredentialsSetup.objects.filter(employee_id=approve_1_id).exists():
                errors['approve_1_employee_id'] = "No user found with this employee ID"

        # Validate approval 2 employee ID
        approve_2_id = attrs.get('approve_2_employee_id')
        if approve_2_id:
            if not UserCredentialsSetup.objects.filter(employee_id=approve_2_id).exists():
                errors['approve_2_employee_id'] = "No user found with this employee ID"

        # Conditional PIP fields validation
        pip_flag = attrs.get('pip_level_flag')
        if pip_flag:
            if not attrs.get('pip_start_date'):
                errors['pip_start_date'] = "This field is required when PIP flag is enabled."
            if not attrs.get('pip_end_date'):
                errors['pip_end_date'] = "This field is required when PIP flag is enabled."
            if not attrs.get('pip_level'):
                errors['pip_level'] = "This field is required when PIP flag is enabled."

        # Raise combined errors if any
        if errors:
            raise serializers.ValidationError(errors)

        return attrs
    def create(self, validated_data):
        # Generate a password if it's not provided
        if 'password' not in validated_data or not validated_data['password']:
            plaintext_password = secrets.token_urlsafe(20)
            validated_data['password'] = plaintext_password

            # send user credentials to login at creation time only with plain-text password
            send_default_user_credentials_email(validated_data['email'], plaintext_password)

        # Hash the password before saving
        validated_data['password'] = make_password(validated_data['password'])

        # Create the instance
        instance = super().create(validated_data)

        # fetch selected project ids
        if 'projects' in self.context['request'].data:
            projects_to_add = self.context['request'].data['projects']
            # Create UserProjectAssignment instances for selected projects
            for project_id in projects_to_add:
                project = Projects.objects.get(id=project_id)
                UserProjectAssignment.objects.create(user=instance, project=project)

        # Handle many-to-many fields
        if 'apps' in self.context['request'].data:
            instance.apps.set(self.context['request'].data['apps'])
        if 'organizations' in self.context['request'].data:
            instance.organizations.set(self.context['request'].data['organizations'])
        if 'clients' in self.context['request'].data:
            instance.clients.set(self.context['request'].data['clients'])
        # if 'projects' in self.context['request'].data:
        #     instance.projects.set(self.context['request'].data['projects'])
        if 'roles' in self.context['request'].data:
            instance.roles.set(self.context['request'].data['roles'])
        if 'departments' in self.context['request'].data:
            instance.departments.set(self.context['request'].data['departments'])
        if 'stakes' in self.context['request'].data:
            instance.stakes.set(self.context['request'].data['stakes'])

        return instance

    def update(self, instance, validated_data):
            password = self.instance.password
            if password and not validated_data.get('password'):
                validated_data['password'] = password
            instance = super().update(instance, validated_data)

            # fetch selected project ids
            if 'projects' in self.context['request'].data:
                projects_to_add = self.context['request'].data['projects']
                UserProjectAssignment.objects.filter(user=instance).delete()
                for project_id in projects_to_add:
                    project = Projects.objects.get(id=project_id)
                    UserProjectAssignment.objects.create(user=instance, project=project)

            # Extract and set many-to-many IDs safely
            def extract_ids(field_name):
                return [
                    item['id'] if isinstance(item, dict) else item
                    for item in self.context['request'].data.get(field_name, [])
                ]

            instance.apps.set(extract_ids('apps'))
            instance.organizations.set(extract_ids('organizations'))
            instance.clients.set(extract_ids('clients'))
            instance.roles.set(extract_ids('roles'))
            instance.departments.set(extract_ids('departments'))
            instance.stakes.set(extract_ids('stakes'))

            return instance


    def to_representation(self, instance):
        # Get the default representation
        data = super().to_representation(instance)

        # Add related field names
        data['apps_names'] = [app.app_name for app in instance.apps.all()]
        data['organizations_names'] = [org.organization_name for org in instance.organizations.all()]
        data['clients_names'] = [client.client_name for client in instance.clients.all()]
        data['projects_names'] = [assignment.project.project_name for assignment in instance.project_assignments.all()]
        data['roles_names'] = [role.role_name for role in instance.roles.all()]
        data['departments_names'] = [dept.department_name for dept in instance.departments.all()]
        data['stakes_names'] = [stake.stake_name for stake in instance.stakes.all()]

        user_type = instance.user_type
        data['user_type'] = [choice.value for choice in UserTypeChoices if choice.value in user_type]
        return data

class GetUserCredentialsSerializer(serializers.ModelSerializer):
    roles = RolesSerializer(many=True, read_only=True)
    departments = DepartmentsSerializer(many=True, read_only=True)
    projects = ProjectsSerializer(many=True, read_only=True)
    clients = ClientSerializer(many=True, read_only=True)
    organizations = OrganizationSerializer(many=True, read_only=True)
    stakes = StakesSerializer(many=True, read_only=True)
    apps = AppsSerializer(many=True, read_only=True)
    class Meta:
        model = UserCredentialsSetup
        exclude = ('password',)

class CustomBinsSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomBins
        fields = '__all__'

class UserTypeBasedTargetSerializer(serializers.ModelSerializer):
    title = serializers.CharField(read_only=True)
    class Meta:
        model = UserTypeBasedTarget
        fields = ['id', 'title', 'targeting_week', 'fresher_targets', 'pip_targets', 'lateral_targets']


class TargetSettingSerializer(serializers.ModelSerializer):
    title = serializers.CharField(read_only=True)
    # Nested serializer to handle the related 'RoleBasedRecordTargetAllocation' objects
    target_allocation = UserTypeBasedTargetSerializer(many=True)

    class Meta:
        model = TargetSettings
        fields = ['id', 'title', 'records_target_count', 'total_working_hours', 'projects', 'target_allocation']

    def create(self, validated_data):
        # Extract the nested 'target_allocation' data
        target_allocation_data = validated_data.pop('target_allocation')

        # Create the RecordsTargets object
        records_target = TargetSettings.objects.create(**validated_data)

        # Now create the associated 'RoleBasedRecordTargetAllocation' objects
        for allocation_data in target_allocation_data:
            # Link each allocation to the created RecordsTargets object
            UserTypeBasedTarget.objects.create(records_target=records_target, **allocation_data)

        return records_target

    def update(self, instance, validated_data):
        # Handle the update logic if required (updating nested objects can be tricky).
        target_allocation_data = validated_data.pop('target_allocation', [])

        # Update the base RecordsTargets instance
        instance.title = validated_data.get('title', instance.title)
        instance.records_target_count = validated_data.get('records_target_count', instance.records_target_count)
        instance.projects = validated_data.get('projects', instance.projects)
        instance.save()

        # Update or create the nested UserTypeBasedTarget objects (One-to-many relationship)
        allocations = UserTypeBasedTarget.objects.filter(records_target=instance)

        for i, allocation_data in enumerate(target_allocation_data):
            # Check if there are enough allocations to update (i.e., the number of allocation data and allocations must match)
            if i < len(allocations):
                allocation = allocations[i]

                # Update the allocation with the new data or keep the old value if no new data is provided
                allocation.fresher_targets = allocation_data.get('fresher_targets', allocation.fresher_targets)
                allocation.pip_targets = allocation_data.get('pip_targets', allocation.pip_targets)
                allocation.lateral_targets = allocation_data.get('lateral_targets', allocation.lateral_targets)
                allocation.save()
            else:
                # If there are more allocation data than existing allocations, create new ones if needed
                # Optional: Create a new allocation record if needed
                UserTypeBasedTarget.objects.create(
                    records_target=instance,
                    fresher_targets=allocation_data.get('fresher_targets'),
                    pip_targets=allocation_data.get('pip_targets'),
                    lateral_targets=allocation_data.get('lateral_targets')
                )

        return instance

# Add this to your setups/serializers.py file
class InsuranceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Insurance
        fields = [
            'id',
            'insurance_name',
            'phone_no',
            'extension',
            'address',
            'open_close_time',
            'prefix',
            'claim_address',
            'appeal_address',
            'claim_tfl_days',
            'appeal_tfl_days',
            'web_page_address',
            'group_username',
            'group_password',
            'individual_username',
            'individual_password',
            'password_expiry_duration',
            'project',
            'created_at',
            'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def validate(self, data):
        """
        Check that insurance_name and phone_no are provided
        """
        if not data.get('insurance_name'):
            raise serializers.ValidationError("Insurance name is required.")
        if not data.get('phone_no'):
            raise serializers.ValidationError("Phone number is required.")
        return data