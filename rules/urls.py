from django.urls import path

from . views import GetCreateRulesView, RetrieveUpdateDeleteRulesView, UpdateRuleApproveStatusView, UpdateRuleStatusView, RuleActionsView

urlpatterns = [
    path('get_create_rules/', GetCreateRulesView.as_view(), name='rules-get-create'),
    path('retrieve_update_delete_rules/<int:pk>/', RetrieveUpdateDeleteRulesView.as_view(), name='retrieve-update-delete-rules'),
]

urlpatterns += [
    path('update_approve_status_rules_and_types/<int:pk>/approve/', UpdateRuleApproveStatusView.as_view(), name='approve-rule'),
    path('update_rule_status_rules_and_types/<int:pk>/', UpdateRuleStatusView.as_view(), name='update-rule-status'),
]

urlpatterns += [
    path('get_create_rule_actions/', RuleActionsView.as_view(), name='get-create-rule-actions')
]