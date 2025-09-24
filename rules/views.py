from rest_framework.exceptions import PermissionDenied
from rest_framework.generics import ListCreateAPIView, UpdateAPIView, RetrieveUpdateDestroyAPIView, ListAPIView
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.db.models import Q
import json

from .serializers import RulesSerializer, RulesAndTypesStatusUpdateSerializer, UpdateRulesApproveSerializer, RuleActionsSerializer
from . models import RulesAndTypes, RuleActions

from common.views import CsrfExemptSessionAuthentication

class GetCreateRulesView(ListCreateAPIView):
    queryset = RulesAndTypes.objects.all()
    serializer_class = RulesSerializer
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        project_id = self.request.query_params.get('project_id', None)
        
        if not project_id:
            return RulesAndTypes.objects.none()
        
        # Parse project_id if it's JSON string
        try:
            if isinstance(project_id, str) and project_id.startswith('['):
                project_id = json.loads(project_id)
                if isinstance(project_id, list) and len(project_id) > 0:
                    project_id = project_id[0]
        except (json.JSONDecodeError, IndexError):
            pass
        
        # If user is superuser, show all rules for the project
        if user.is_superuser:
            queryset = RulesAndTypes.objects.filter(project__id=project_id)
        else:
            # Filter rules based on user permissions:
            # 1. Rules created by the user
            # 2. Rules where user is an approver (approves_1 or approves_2)
            # 3. Rules in projects where user has access
            queryset = RulesAndTypes.objects.filter(
                Q(project__id=project_id) & (
                    Q(created_by=user) |
                    Q(approves_1=user) |
                    Q(approves_2=user)
                )
            ).distinct()
        
        return queryset

    def perform_create(self, serializer):
        # Ensure the created_by field is set to current user
        serializer.save(created_by=self.request.user)

class RetrieveUpdateDeleteRulesView(RetrieveUpdateDestroyAPIView):
    queryset = RulesAndTypes.objects.all()
    serializer_class = RulesSerializer
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        # Only allow access to rules created by user or where user is approver
        return RulesAndTypes.objects.filter(
            Q(created_by=user) |
            Q(approves_1=user) |
            Q(approves_2=user)
        )

    def put(self, request, *args, **kwargs):
        return self.partial_update(request, *args, **kwargs)

    def perform_update(self, serializer):
        instance = self.get_object()
        user = self.request.user
        
        # Only allow updates by rule creator or approvers
        if (instance.created_by != user and 
            instance.approves_1 != user and 
            instance.approves_2 != user):
            raise PermissionDenied("You don't have permission to update this rule.")
        
        serializer.save()

    def perform_destroy(self, instance):
        user = self.request.user
        
        # Only allow deletion by rule creator
        if instance.created_by != user:
            raise PermissionDenied("Only the rule creator can delete this rule.")
        
        instance.delete()

class UpdateRuleApproveStatusView(UpdateAPIView):
    queryset = RulesAndTypes.objects.all()
    serializer_class = UpdateRulesApproveSerializer
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'

    def get_queryset(self):
        user = self.request.user
        # Only show rules where user is an approver
        return RulesAndTypes.objects.filter(
            Q(approves_1=user) | Q(approves_2=user)
        )

    def update(self, request, *args, **kwargs):
        """
        Validate user to approve rule on PUT request
        """
        instance = self.get_object()
        approving_user = request.user
        
        # More robust authorization check using IDs
        approver_ids = []
        if instance.approves_1:
            approver_ids.append(instance.approves_1.id)
        if instance.approves_2:
            approver_ids.append(instance.approves_2.id)
        
        # Check if user is authorized approver
        if approving_user.id not in approver_ids:
            return Response(
                {"error": f"You are not authorized to approve this rule. Your ID: {approving_user.id}, Authorized approvers: {approver_ids}"}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Don't allow approving own rules
        if instance.created_by and approving_user.id == instance.created_by.id:
            return Response(
                {"error": "You cannot approve your own rule."}, 
                status=status.HTTP_403_FORBIDDEN
            )

        # Include the approving user in request data
        request.data['approved_by'] = approving_user.id

        serializer = self.get_serializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UpdateRuleStatusView(UpdateAPIView):
    queryset = RulesAndTypes.objects.all()
    serializer_class = RulesAndTypesStatusUpdateSerializer
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'

    def get_queryset(self):
        user = self.request.user
        # Allow status updates for rules created by user or where user is approver
        return RulesAndTypes.objects.filter(
            Q(created_by=user) |
            Q(approves_1=user) |
            Q(approves_2=user)
        )

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        user = self.request.user
        
        # Check permissions
        if (instance.created_by != user and 
            instance.approves_1 != user and 
            instance.approves_2 != user):
            raise PermissionDenied("You don't have permission to update this rule status.")
        
        return super().update(request, *args, **kwargs)

class RuleActionsView(ListCreateAPIView):
    queryset = RuleActions.objects.all()
    serializer_class = RuleActionsSerializer
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
    permission_classes = [IsAuthenticated]

















# from rest_framework.exceptions import PermissionDenied
# from rest_framework.generics import ListCreateAPIView, UpdateAPIView, RetrieveUpdateDestroyAPIView, ListAPIView
# from rest_framework.authentication import SessionAuthentication, BasicAuthentication
# from rest_framework.permissions import IsAuthenticated
# from rest_framework.response import Response
# from django.db.models import Q
# import json

# from .serializers import RulesSerializer, RulesAndTypesStatusUpdateSerializer, UpdateRulesApproveSerializer, RuleActionsSerializer
# from . models import RulesAndTypes, RuleActions

# from common.views import CsrfExemptSessionAuthentication

# class GetCreateRulesView(ListCreateAPIView):
#     queryset = RulesAndTypes.objects.all()
#     serializer_class = RulesSerializer
#     authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
#     permission_classes = [IsAuthenticated]

#     def get_queryset(self):
#         user = self.request.user
#         project_id = self.request.query_params.get('project_id', None)
        
#         if not project_id:
#             return RulesAndTypes.objects.none()
        
#         # Parse project_id if it's JSON string
#         try:
#             if isinstance(project_id, str) and project_id.startswith('['):
#                 project_id = json.loads(project_id)
#                 if isinstance(project_id, list) and len(project_id) > 0:
#                     project_id = project_id[0]
#         except (json.JSONDecodeError, IndexError):
#             pass
        
#         # Filter rules based on user permissions:
#         # 1. Rules created by the user
#         # 2. Rules where user is an approver (approves_1 or approves_2)
#         # 3. Rules in projects where user has access
#         queryset = RulesAndTypes.objects.filter(
#             Q(project__id=project_id) & (
#                 Q(created_by=user) |
#                 Q(approves_1=user) |
#                 Q(approves_2=user)
#             )
#         ).distinct()
        
#         return queryset

#     def perform_create(self, serializer):
#         # Ensure the created_by field is set to current user
#         serializer.save(created_by=self.request.user)

# class RetrieveUpdateDeleteRulesView(RetrieveUpdateDestroyAPIView):
#     queryset = RulesAndTypes.objects.all()
#     serializer_class = RulesSerializer
#     authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
#     permission_classes = [IsAuthenticated]

#     def get_queryset(self):
#         user = self.request.user
#         # Only allow access to rules created by user or where user is approver
#         return RulesAndTypes.objects.filter(
#             Q(created_by=user) |
#             Q(approves_1=user) |
#             Q(approves_2=user)
#         )

#     def put(self, request, *args, **kwargs):
#         return self.partial_update(request, *args, **kwargs)

#     def perform_update(self, serializer):
#         instance = self.get_object()
#         user = self.request.user
        
#         # Only allow updates by rule creator or approvers
#         if (instance.created_by != user and 
#             instance.approves_1 != user and 
#             instance.approves_2 != user):
#             raise PermissionDenied("You don't have permission to update this rule.")
        
#         serializer.save()

#     def perform_destroy(self, instance):
#         user = self.request.user
        
#         # Only allow deletion by rule creator
#         if instance.created_by != user:
#             raise PermissionDenied("Only the rule creator can delete this rule.")
        
#         instance.delete()

# class UpdateRuleApproveStatusView(UpdateAPIView):
#     queryset = RulesAndTypes.objects.all()
#     serializer_class = UpdateRulesApproveSerializer
#     authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
#     permission_classes = [IsAuthenticated]
#     lookup_field = 'pk'

#     def get_queryset(self):
#         user = self.request.user
#         # Only show rules where user is an approver
#         return RulesAndTypes.objects.filter(
#             Q(approves_1=user) | Q(approves_2=user)
#         )

#     def update(self, request, *args, **kwargs):
#         """
#         Validate user to approve rule on PUT request
#         """
#         instance = self.get_object()
#         approving_user = request.user
        
#         # More robust authorization check using IDs
#         approver_ids = []
#         if instance.approves_1:
#             approver_ids.append(instance.approves_1.id)
#         if instance.approves_2:
#             approver_ids.append(instance.approves_2.id)
        
#         # Check if user is authorized approver
#         if approving_user.id not in approver_ids:
#             return Response(
#                 {"error": f"You are not authorized to approve this rule. Your ID: {approving_user.id}, Authorized approvers: {approver_ids}"}, 
#                 status=status.HTTP_403_FORBIDDEN
#             )
        
#         # Don't allow approving own rules
#         if instance.created_by and approving_user.id == instance.created_by.id:
#             return Response(
#                 {"error": "You cannot approve your own rule."}, 
#                 status=status.HTTP_403_FORBIDDEN
#             )

#         # Include the approving user in request data
#         request.data['approved_by'] = approving_user.id

#         serializer = self.get_serializer(instance, data=request.data, partial=True)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data)
#         else:
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class UpdateRuleStatusView(UpdateAPIView):
#     queryset = RulesAndTypes.objects.all()
#     serializer_class = RulesAndTypesStatusUpdateSerializer
#     authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
#     permission_classes = [IsAuthenticated]
#     lookup_field = 'pk'

#     def get_queryset(self):
#         user = self.request.user
#         # Allow status updates for rules created by user or where user is approver
#         return RulesAndTypes.objects.filter(
#             Q(created_by=user) |
#             Q(approves_1=user) |
#             Q(approves_2=user)
#         )

#     def update(self, request, *args, **kwargs):
#         instance = self.get_object()
#         user = self.request.user
        
#         # Check permissions
#         if (instance.created_by != user and 
#             instance.approves_1 != user and 
#             instance.approves_2 != user):
#             raise PermissionDenied("You don't have permission to update this rule status.")
        
#         return super().update(request, *args, **kwargs)

# class RuleActionsView(ListCreateAPIView):
#     queryset = RuleActions.objects.all()
#     serializer_class = RuleActionsSerializer
#     authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication, SessionAuthentication)
#     permission_classes = [IsAuthenticated]