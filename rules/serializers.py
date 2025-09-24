from django.utils import timezone
from rest_framework import serializers

from .models import RulesAndTypes, RuleActions

from setups.serializers import GetApproveNamesSerializers

class RuleActionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = RuleActions
        fields = '__all__'

# creation and updating RuleAndTypes model
class RulesSerializer(serializers.ModelSerializer):
    approved_by = GetApproveNamesSerializers(read_only=True)
    created_by = GetApproveNamesSerializers(read_only=True)
    action = RuleActionsSerializer(required=False, many=False)

    def create(self, validated_data):
        # Handle nested action data
        action_data = validated_data.pop('action')
        project = validated_data.pop('project')
        action_instance = RuleActions.objects.create(**action_data)

        # Create the parent object (RulesAndTypes)
        rule = RulesAndTypes.objects.create(action=action_instance, **validated_data)

        rule.project.set(project)
        rule.save()
        return rule

    def update(self, instance, validated_data):
        # Handle nested action data (for updating)
        action_data = validated_data.pop('action', None)
        project = validated_data.pop('project')

        if action_data:
            """
            Reset All Fields to Set only one rule
            Get fields that can be set to None from model definition
            """
            nullable_fields = [f.name for f in instance.action._meta.fields
                               if f.name != 'id' and f.null]

            # Reset only nullable fields
            for field_name in nullable_fields:
                if field_name == 'reviewing_user':
                    # For FKs, explicitly set to None using both field name and _id
                    setattr(instance.action, field_name + '_id', None)
                else:
                    setattr(instance.action, field_name, None)

            instance.action.save()

            # Update the RuleActions instance
            for attr, value in action_data.items():
                setattr(instance.action, attr, value)
            instance.action.save()

        # Update the parent object (RulesAndTypes)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.project.set(project)
        instance.save()
        return instance

    class Meta:
        model = RulesAndTypes
        fields = '__all__'
        # all fields should be listed instead of __all__
        # field_names = ['authentication', 'rule_name', 'project', 'department', 'action', 'ageing_bucket', 'rule_status',
        #                'approves_1', 'approves_2', 'approved_by', 'approved_at', 'approved_status',
        #                'rule_target_apply_to_existing_records', 'rule_target_apply_to_new_records', 'rule_category']

    def to_representation(self, instance):
        # Call the parent method to get the serialized data
        data = super().to_representation(instance)

        # Filter out any fields with null or empty values
        filtered_data = {key: value for key, value in data.items() if value not in [None, '', [], {}, {}]}

        return filtered_data

# for updating approval rules status
class UpdateRulesApproveSerializer(serializers.ModelSerializer):
    class Meta:
        model = RulesAndTypes
        fields = '__all__'

    def update(self, instance, validated_data):
        """
        The update method is responsible for updating the rule fields. It should:
        - Update the approved_status to True / False.
        - Set the approved_at field to the current timestamp if approved_status is True.
        - Ensure the approved_by field is set with the user making the update.
        """
        # Check if the approved_status is being updated to True
        approved_status = validated_data.get('approved_status', instance.approved_status)

        if approved_status is True:
            # Set the approved_at to the current timestamp
            validated_data['approved_at'] = timezone.now()

        # Update fields
        instance.approved_status = approved_status
        instance.approved_by = validated_data.get('approved_by', instance.approved_by)
        instance.approved_at = validated_data.get('approved_at', instance.approved_at)

        if approved_status is False:
            instance.approved_status = False
            instance.approved_by = None
            instance.approved_at = None

        instance.save()
        return instance




class RulesAndTypesStatusUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = RulesAndTypes
        fields = ['rule_status']

    def update(self, instance, validated_data):
        instance.rule_status = validated_data.get('rule_status', instance.rule_status)
        instance.save()
        return instance


















# from django.utils import timezone
# from rest_framework import serializers
# from django.contrib.auth import get_user_model

# from .models import RulesAndTypes, RuleActions

# from setups.serializers import GetApproveNamesSerializers

# User = get_user_model()

# class RuleActionsSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = RuleActions
#         fields = '__all__'

# # creation and updating RuleAndTypes model
# class RulesSerializer(serializers.ModelSerializer):
#     approved_by = GetApproveNamesSerializers(read_only=True)
#     created_by = GetApproveNamesSerializers(read_only=True)
#     action = RuleActionsSerializer(required=False, many=False)

#     def create(self, validated_data):
#         # Handle nested action data
#         action_data = validated_data.pop('action', {})
#         project = validated_data.pop('project', [])
        
#         # Create action instance if data provided
#         action_instance = None
#         if action_data:
#             action_instance = RuleActions.objects.create(**action_data)

#         # Create the parent object (RulesAndTypes)
#         rule = RulesAndTypes.objects.create(
#             action=action_instance, 
#             **validated_data
#         )

#         # Set projects
#         if project:
#             rule.project.set(project)
        
#         rule.save()
#         return rule

#     def update(self, instance, validated_data):
#         # Handle nested action data (for updating)
#         action_data = validated_data.pop('action', None)
#         project = validated_data.pop('project', [])

#         if action_data:
#             if instance.action:
#                 # Update existing action
#                 """
#                 Reset All Fields to Set only one rule
#                 Get fields that can be set to None from model definition
#                 """
#                 nullable_fields = [f.name for f in instance.action._meta.fields
#                                    if f.name != 'id' and f.null]

#                 # Reset only nullable fields
#                 for field_name in nullable_fields:
#                     if field_name == 'reviewing_user':
#                         # For FKs, explicitly set to None using both field name and _id
#                         setattr(instance.action, field_name + '_id', None)
#                     else:
#                         setattr(instance.action, field_name, None)

#                 instance.action.save()

#                 # Update the RuleActions instance
#                 for attr, value in action_data.items():
#                     setattr(instance.action, attr, value)
#                 instance.action.save()
#             else:
#                 # Create new action if none exists
#                 instance.action = RuleActions.objects.create(**action_data)

#         # Update the parent object (RulesAndTypes)
#         for attr, value in validated_data.items():
#             setattr(instance, attr, value)
        
#         # Set projects
#         if project:
#             instance.project.set(project)
        
#         instance.save()
#         return instance

#     def validate(self, data):
#         """
#         Custom validation for rules
#         """
#         request = self.context.get('request')
#         if request and hasattr(request, 'user'):
#             user = request.user
            
#             # Validate approvers exist and are different from creator
#             approves_1 = data.get('approves_1')
#             approves_2 = data.get('approves_2')
            
#             if approves_1 and approves_1 == user:
#                 raise serializers.ValidationError("You cannot set yourself as an approver.")
            
#             if approves_2 and approves_2 == user:
#                 raise serializers.ValidationError("You cannot set yourself as an approver.")
            
#             if approves_1 and approves_2 and approves_1 == approves_2:
#                 raise serializers.ValidationError("Primary and secondary approvers must be different.")
        
#         return data

#     class Meta:
#         model = RulesAndTypes
#         fields = '__all__'

#     def to_representation(self, instance):
#         # Call the parent method to get the serialized data
#         data = super().to_representation(instance)

#         # Filter out any fields with null or empty values
#         filtered_data = {key: value for key, value in data.items() if value not in [None, '', [], {}]}

#         return filtered_data

# # for updating approval rules status
# class UpdateRulesApproveSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = RulesAndTypes
#         fields = '__all__'

#     def validate(self, data):
#         """
#         Validate approval request
#         """
#         request = self.context.get('request')
#         instance = getattr(self, 'instance', None)
        
#         if request and hasattr(request, 'user') and instance:
#             user = request.user
            
#             # Don't allow self-approval
#             if instance.created_by == user:
#                 raise serializers.ValidationError("You cannot approve your own rule.")
            
#             # Check if user is authorized approver
#             if (user != instance.approves_1 and user != instance.approves_2):
#                 raise serializers.ValidationError("You are not authorized to approve this rule.")
        
#         return data

#     def update(self, instance, validated_data):
#         """
#         The update method is responsible for updating the rule fields. It should:
#         - Update the approved_status to True / False.
#         - Set the approved_at field to the current timestamp if approved_status is True.
#         - Ensure the approved_by field is set with the user making the update.
#         """
#         # Check if the approved_status is being updated to True
#         approved_status = validated_data.get('approved_status', instance.approved_status)
#         approved_by = validated_data.get('approved_by')

#         # Get the actual user instance if approved_by is provided as ID
#         if approved_by and not isinstance(approved_by, User):
#             try:
#                 approved_by = User.objects.get(id=approved_by)
#             except User.DoesNotExist:
#                 raise serializers.ValidationError("Invalid approver user.")

#         if approved_status is True:
#             # Set the approved_at to the current timestamp
#             validated_data['approved_at'] = timezone.now()
#             validated_data['approved_by'] = approved_by
#         else:
#             # If disapproving, clear approval fields
#             validated_data['approved_at'] = None
#             validated_data['approved_by'] = None

#         # Update fields
#         instance.approved_status = approved_status
#         instance.approved_by = validated_data.get('approved_by', instance.approved_by)
#         instance.approved_at = validated_data.get('approved_at', instance.approved_at)

#         instance.save()
#         return instance

# class RulesAndTypesStatusUpdateSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = RulesAndTypes
#         fields = ['rule_status']

#     def validate(self, data):
#         """
#         Validate status update request
#         """
#         request = self.context.get('request')
#         instance = getattr(self, 'instance', None)
        
#         if request and hasattr(request, 'user') and instance:
#             user = request.user
            
#             # Check if user has permission to update status
#             if (instance.created_by != user and 
#                 instance.approves_1 != user and 
#                 instance.approves_2 != user):
#                 raise serializers.ValidationError("You don't have permission to update this rule status.")
        
#         return data

#     def update(self, instance, validated_data):
#         instance.rule_status = validated_data.get('rule_status', instance.rule_status)
#         instance.save()
#         return instance