from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.db import models
from users.models import BaseUser
from common.models import BaseModels
from setups.models import Projects

import random
import string
# from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from autoslug import AutoSlugField

from users.models import BaseUser
from common.models import BaseModels
from setups.models import Projects, CustomBins


from django.conf import settings

from django.contrib.auth.models import User
from setups.models import UserCredentialsSetup, Projects
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.contrib.auth import get_user_model
User = get_user_model()
def generate_unique_short_id(length=4):
    """Generate a unique short ID of given length."""
    while True:
        # Generate a random ID
        short_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

        # Check if the ID already exists in any model
        if not (DeptartmentPage.objects.filter(deptartment_id=short_id).exists() or
                RolesPage.objects.filter(role_id=short_id).exists() or
                SectorPage.objects.filter(sector_id=short_id).exists() or
                ProjectPage.objects.filter(project_id=short_id).exists() or
                StakePage.objects.filter(stake_id=short_id).exists() or
                AppsPage.objects.filter(app_id=short_id).exists() or
                ClientPage.objects.filter(client_id=short_id).exists()):
            return short_id


class RecordsUploadLogs(BaseModels):
    uploaded_file_name = models.FileField(upload_to='media/uploaded_patient_records')
    new_records_uploaded_count = models.IntegerField(blank=True, default=0)
    updated_records_uploaded_count = models.IntegerField(blank=True, default=0)
    failed_records_count = models.IntegerField(blank=True, default=0)
    failed_records = models.BooleanField(default=False)
    
    # Add these fields to track the actual records
    upload_session_id = models.CharField(max_length=100, blank=True, null=True)
    project_id = models.CharField(max_length=225, blank=True, null=True)
    organization_id = models.CharField(max_length=225, blank=True, null=True)
    
    # Store failed records data if needed
    failed_records_data = models.JSONField(default=dict, blank=True)
    
    def __str__(self):
        return f"Upload {self.id} - {self.uploaded_file_name}"

class RecordUploadTracking(models.Model):
    """
    Track which specific records were created/updated/failed during each upload
    """
    ACTION_CHOICES = [
        ('NEW', 'New Record'),
        ('UPDATED', 'Updated Record'),
        ('FAILED', 'Failed Record'),
    ]
    
    upload_log = models.ForeignKey('RecordsUploadLogs', on_delete=models.CASCADE, related_name='tracked_records')
    patient_record = models.ForeignKey('PatientRecords', on_delete=models.CASCADE, null=True, blank=True)
    action_type = models.CharField(max_length=10, choices=ACTION_CHOICES)
    error_message = models.TextField(null=True, blank=True)  # For failed records
    row_data = models.JSONField(default=dict, blank=True)  # Store original row data for failed records
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'record_upload_tracking'
        indexes = [
            models.Index(fields=['upload_log', 'action_type']),
        ]

    def __str__(self):
        return f"Upload {self.upload_log_id} - {self.action_type} - Record {self.patient_record_id}"
class PatientRecord(models.Model):
    input_source = models.TextField()
    mrn = models.TextField()
    patient_id = models.TextField()
    account_number = models.CharField(max_length=200)
    visit_number = models.TextField()
    chart_number = models.TextField()
    project_key = models.TextField()
    facility = models.TextField()
    facility_type = models.TextField()
    patient_last_name = models.TextField()
    patient_first_name = models.TextField()
    patient_phone = models.TextField()
    patient_address = models.TextField()
    patient_city = models.TextField()
    patient_state = models.TextField()
    patient_zip = models.TextField()
    patient_birthday = models.TextField()  # Converted DateField
    patient_gender = models.TextField()
    subscriber_last_name = models.TextField()
    subscriber_first_name = models.TextField()
    subscriber_relationship = models.TextField()
    subscriber_phone = models.TextField()
    subscriber_address = models.TextField()
    subscriber_city = models.TextField()
    subscriber_state = models.TextField()
    subscriber_zip = models.TextField()
    subscriber_birthday = models.TextField()  # Converted DateField
    subscriber_gender = models.TextField()
    current_billed_financial_class = models.TextField()
    current_billed_payer_name = models.TextField()
    member_id_current_billed_payer = models.TextField()
    group_number_current_billed_payer = models.TextField()
    current_billed_relationship = models.TextField()
    cob = models.TextField()
    payer_id_current_billed_payer = models.TextField()
    timely_filing_limit = models.CharField(max_length=200)  # Converted IntegerField
    appeal_limit = models.CharField(max_length=200)  # Converted IntegerField
    primary_payer_financial_class = models.TextField()
    primary_payer_name = models.TextField()
    member_id_primary_payer = models.TextField()
    group_number_primary_payer = models.TextField()
    relationship_primary_payer = models.TextField()
    cob_primary = models.TextField()
    payer_id_primary_payer = models.TextField()
    secondary_payer_financial_class = models.TextField()
    secondary_payer_name = models.TextField()
    member_id_secondary_payer = models.TextField()
    group_number_secondary_payer = models.TextField()
    relationship_secondary_payer = models.TextField()
    cob_secondary = models.TextField()
    payer_id_secondary_payer = models.TextField()
    tertiary_payer_financial_class = models.TextField()
    tertiary_payer_name = models.CharField(max_length=100)
    member_id_tertiary_payer = models.CharField(max_length=200)
    group_number_tertiary_payer = models.CharField(max_length=200)
    relationship_tertiary_payer = models.CharField(max_length=200)
    cob_tertiary = models.CharField(max_length=200)
    payer_id_tertiary_payer = models.CharField(max_length=200)
    auth_number = models.TextField()
    claim_number = models.CharField(max_length=200)
    facility_code = models.CharField(max_length=200)
    claim_frequency_type = models.CharField(max_length=200)
    signature = models.CharField(max_length=200)
    assignment_code = models.CharField(max_length=200)
    assign_certification = models.CharField(max_length=200)
    release_info_code = models.CharField(max_length=200)
    service_date = models.DateField()  # Converted DateField

    van_trace_number = models.CharField(max_length=200)
    rendering_provider_id = models.CharField(max_length=200)
    taxonomy_code = models.CharField(max_length=200)
    procedure_code = models.CharField(max_length=200)
    amount = models.CharField(max_length=200)  # Converted DecimalField
    procedure_count = models.CharField(max_length=200)  # Converted IntegerField
    tooth_code = models.CharField(max_length=200)
    procedure_code2 = models.CharField(max_length=200, blank=True, null=True)
    amount2 = models.CharField(max_length=200, blank=True, null=True)  # Converted DecimalField
    procedure_count2 = models.CharField(max_length=200, blank=True, null=True)  # Converted IntegerField
    tooth_code2 = models.CharField(max_length=200, blank=True, null=True)
    procedure_code3 = models.CharField(max_length=200, blank=True, null=True)
    amount3 = models.CharField(max_length=200, blank=True, null=True)  # Converted DecimalField
    procedure_count3 = models.CharField(max_length=200, blank=True, null=True)  # Converted IntegerField
    tooth_code3 = models.CharField(max_length=200, blank=True, null=True)
    procedure_code4 = models.CharField(max_length=200, blank=True, null=True)
    amount4 = models.CharField(max_length=200, blank=True, null=True)  # Converted DecimalField
    procedure_count4 = models.CharField(max_length=100, blank=True, null=True)  # Converted IntegerField
    tooth_code4 = models.CharField(max_length=200, blank=True, null=True)
    dx1 = models.CharField(max_length=200, blank=True, null=True)
    dx2 = models.CharField(max_length=200, blank=True, null=True)
    dx3 = models.CharField(max_length=200, blank=True, null=True)
    dx4 = models.CharField(max_length=200, blank=True, null=True)
    dx5 = models.CharField(max_length=200, blank=True, null=True)
    dx6 = models.CharField(max_length=200, blank=True, null=True)
    total_charged = models.CharField(max_length=200)  # Converted DecimalField
    check_number = models.CharField(max_length=200, blank=True, null=True)
    insurance_balance = models.CharField(max_length=200, blank=True, null=True)  # Converted DecimalField
    patient_balance = models.CharField(max_length=200, blank=True, null=True)  # Converted DecimalField
    contract_name = models.CharField(max_length=100)
    division = models.CharField(max_length=200)
    type_of_service = models.CharField(max_length=200)
    current_queue = models.JSONField(blank=True, default=dict)
    queue_days = models.CharField(max_length=200)  # Converted IntegerField
    latest_action_date = models.CharField(max_length=200)  # Converted DateField
    next_follow_up_before = models.CharField(max_length=200)  # Converted DateField
    claim_denial_date = models.CharField(max_length=200)  # Converted DateField
    claim_denial_code = models.CharField(max_length=200)
    claim_denial_description = models.CharField(max_length=200)
    latest_pay_date = models.CharField(max_length=200)  # Converted DateField
    latest_pay_amount = models.CharField(max_length=200)  # Converted DecimalField
    claim_priority = models.CharField(max_length=200)
    category = models.CharField(max_length=200)
    sub_category = models.CharField(max_length=200)
    status = models.CharField(max_length=200)
    action = models.CharField(max_length=200)
    provider_name = models.CharField(max_length=100)
    provider_npi = models.CharField(max_length=200)
    provider_location = models.CharField(max_length=100)
    assigned_to = models.ManyToManyField(BaseUser, related_name='records_assigned_to_dummy', blank=True)
    assigned_by = models.OneToOneField(BaseUser, on_delete=models.SET_NULL, null=True, blank=True)
    last_claim_status_check_date = models.CharField(max_length=200)  # Converted DateField
    last_ev_check_date = models.CharField(max_length=200)  # Converted DateField
    last_ins_disc_check_date = models.CharField(max_length=200)  # Converted DateField
    under_pay = models.CharField(max_length=200, blank=True, null=True)  # Converted DecimalField
    project_id = models.CharField(max_length=200, blank=True, null=True)
    organization_id = models.CharField(max_length=200, blank=True, null=True)
    allocation_fresh = models.BooleanField(default=True)
    allocation_allocated = models.BooleanField(default=False)
    allocation_worked = models.BooleanField(default=False)
    current_user_id = models.CharField(max_length=255, blank=True, null=True)
    allocated_date = models.DateTimeField(auto_now_add=False, blank=True, null=True)
    worked_date = models.DateTimeField(blank=True, null=True)
    ageing_bucket = models.CharField(max_length=200, blank=True, null=True)
    allocation_status = models.BooleanField(default=False)
    allocated_to = models.JSONField(blank=True, default=dict)
    hold_status = models.BooleanField(default=False)
    hold = models.JSONField(blank=True, default=dict)
    review_status = models.BooleanField(default=False)
    review_by = models.JSONField(blank=True, default=dict)
    executive_status = models.BooleanField(default=False)
    executive_bin = models.JSONField(blank=True, default=dict)
    upload_session_id = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return f'{self.patient_last_name}, {self.patient_first_name}'


class DeptartmentPage(models.Model):
    deptartment_id = models.CharField(max_length=4, primary_key=True,
                                      default=generate_unique_short_id,
                                      editable=False)
    department_name = models.CharField(max_length=200)
    organization_id = models.CharField(max_length=30, null=True, blank=True, default=None)

    def __str__(self):
        return f"{self.department_name} (ID: {self.deptartment_id})"


class RolesPage(models.Model):
    role_id = models.CharField(max_length=4, primary_key=True,
                               default=generate_unique_short_id,
                               editable=False)
    role_name = models.CharField(max_length=200)
    screens = models.JSONField(blank=True, default=list)
    organization_id = models.CharField(max_length=30, null=True, blank=True, default=None)

    def __str__(self):
        return f"{self.role_name} (ID: {self.role_id})"


class SectorPage(BaseModels):
    sector_id = models.CharField(max_length=4, primary_key=True,
                                 default=generate_unique_short_id,
                                 editable=False)
    sector_name = models.CharField(max_length=200)
    apps = models.JSONField(blank=True, default=list)

    def __str__(self):
        return f"{self.sector_name} (ID: {self.sector_id})"


class ClientPage(models.Model):
    client_id = models.CharField(max_length=4, primary_key=True,
                                 default=generate_unique_short_id,
                                 editable=False)
    client_name = models.CharField(max_length=200, default='unknown')
    status = models.CharField(max_length=200, default='unknown')
    sector_id = models.ForeignKey('SectorPage', on_delete=models.SET_NULL, null=True, blank=True,
                                  related_name='clients')
    organization_id = models.CharField(max_length=30, null=True, blank=True, default=None)

    def __str__(self):
        return f"{self.client_name} (ID: {self.client_id})"


class StakePage(models.Model):
    stake_id = models.CharField(max_length=4, primary_key=True,
                                default=generate_unique_short_id,
                                editable=False)
    stake_name = models.CharField(max_length=30, default='unknown')
    organization_id = models.CharField(max_length=30, null=True, blank=True, default=None)

    def __str__(self):
        return f"{self.stake_name} {self.stake_id}"


class AppsPage(models.Model):
    app_id = models.CharField(max_length=4, primary_key=True,
                              default=generate_unique_short_id,
                              editable=False)
    app_name = models.CharField(max_length=30, default='unknown')
    organization_id = models.CharField(max_length=30, null=True, blank=True, default=None)

    def __str__(self):
        return f"{self.app_id} {self.app_name}"


class MappingRecord(models.Model):
    id = models.BigAutoField(primary_key=True)
    billing_system_file_name = models.CharField(max_length=200)
    organization_id = models.CharField(max_length=200, null=True, blank=True, default=None)
    input_source = models.JSONField(default=dict)
    mrn = models.JSONField(default=dict)
    patient_id = models.JSONField(default=dict)
    account_number = models.JSONField(default=dict)
    visit_number = models.JSONField(default=dict)
    chart_number = models.JSONField(default=dict)
    project_key = models.JSONField(default=dict)
    facility = models.JSONField(default=dict)
    facility_type = models.JSONField(default=dict)
    patient_last_name = models.JSONField(default=dict)
    patient_first_name = models.JSONField(default=dict)
    patient_phone = models.JSONField(default=dict)
    patient_address = models.JSONField(default=dict)
    patient_city = models.JSONField(default=dict)
    patient_state = models.JSONField(default=dict)
    patient_zip = models.JSONField(default=dict)
    patient_birthday = models.JSONField(default=dict)
    patient_gender = models.JSONField(default=dict)
    subscriber_last_name = models.JSONField(default=dict)
    subscriber_first_name = models.JSONField(default=dict)
    subscriber_relationship = models.JSONField(default=dict)
    subscriber_phone = models.JSONField(default=dict)
    subscriber_address = models.JSONField(default=dict)
    subscriber_city = models.JSONField(default=dict)
    subscriber_state = models.JSONField(default=dict)
    subscriber_zip = models.JSONField(default=dict)
    subscriber_birthday = models.JSONField(default=dict)
    subscriber_gender = models.JSONField(default=dict)
    current_billed_financial_class = models.JSONField(default=dict)
    current_billed_payer_name = models.JSONField(default=dict)
    member_id_current_billed_payer = models.JSONField(default=dict)
    group_number_current_billed_payer = models.JSONField(default=dict)
    current_billed_relationship = models.JSONField(default=dict)
    cob = models.JSONField(default=dict)
    payer_id_current_billed_payer = models.JSONField(default=dict)
    timely_filing_limit = models.JSONField(default=dict)
    appeal_limit = models.JSONField(default=dict)
    primary_payer_financial_class = models.JSONField(default=dict)
    primary_payer_name = models.JSONField(default=dict)
    member_id_primary_payer = models.JSONField(default=dict)
    group_number_primary_payer = models.JSONField(default=dict)
    relationship_primary_payer = models.JSONField(default=dict)
    cob_primary = models.JSONField(default=dict)
    payer_id_primary_payer = models.JSONField(default=dict)
    secondary_payer_financial_class = models.JSONField(default=dict)
    secondary_payer_name = models.JSONField(default=dict)
    member_id_secondary_payer = models.JSONField(default=dict)
    group_number_secondary_payer = models.JSONField(default=dict)
    relationship_secondary_payer = models.JSONField(default=dict)
    cob_secondary = models.JSONField(default=dict)
    payer_id_secondary_payer = models.JSONField(default=dict)
    tertiary_payer_financial_class = models.JSONField(default=dict)
    tertiary_payer_name = models.JSONField(default=dict)
    member_id_tertiary_payer = models.JSONField(default=dict)
    group_number_tertiary_payer = models.JSONField(default=dict)
    relationship_tertiary_payer = models.JSONField(default=dict)
    cob_tertiary = models.JSONField(default=dict)
    payer_id_tertiary_payer = models.JSONField(default=dict)
    auth_number = models.JSONField(default=dict)
    claim_number = models.JSONField(default=dict)
    facility_code = models.JSONField(default=dict)
    claim_frequency_type = models.JSONField(default=dict)
    signature = models.JSONField(default=dict)
    assignment_code = models.JSONField(default=dict)
    assign_certification = models.JSONField(default=dict)
    release_info_code = models.JSONField(default=dict)
    service_date = models.JSONField(default=dict)
    van_trace_number = models.JSONField(default=dict)
    rendering_provider_id = models.JSONField(default=dict)
    taxonomy_code = models.JSONField(default=dict)
    procedure_code = models.JSONField(default=dict)
    amount = models.JSONField(default=dict)
    procedure_count = models.JSONField(default=dict)
    tooth_code = models.JSONField(default=dict)
    procedure_code2 = models.JSONField(default=dict)
    amount2 = models.JSONField(default=dict)
    procedure_count2 = models.JSONField(default=dict)
    tooth_code2 = models.JSONField(default=dict)
    procedure_code3 = models.JSONField(default=dict)
    amount3 = models.JSONField(default=dict)
    procedure_count3 = models.JSONField(default=dict)
    tooth_code3 = models.JSONField(default=dict)
    procedure_code4 = models.JSONField(default=dict)
    amount4 = models.JSONField(default=dict)
    procedure_count4 = models.JSONField(default=dict)
    tooth_code4 = models.JSONField(default=dict)
    dx1 = models.JSONField(default=dict)
    dx2 = models.JSONField(default=dict)
    dx3 = models.JSONField(default=dict)
    dx4 = models.JSONField(default=dict)
    dx5 = models.JSONField(default=dict)
    dx6 = models.JSONField(default=dict)
    total_charged = models.JSONField(default=dict)
    check_number = models.JSONField(default=dict)
    insurance_balance = models.JSONField(default=dict)
    patient_balance = models.JSONField(default=dict)
    contract_name = models.JSONField(default=dict)
    division = models.JSONField(default=dict)
    type_of_service = models.JSONField(default=dict)
    current_queue = models.JSONField(blank=True, default=dict)
    queue_days = models.JSONField(blank=True, default=dict)
    latest_action_date = models.JSONField(blank=True, default=dict)
    next_follow_up_before = models.JSONField(blank=True, default=dict)
    claim_denial_date = models.JSONField(default=dict)
    claim_denial_code = models.JSONField(default=dict)
    claim_denial_description = models.JSONField(default=dict)
    latest_pay_date = models.JSONField(blank=True, default=dict)
    latest_pay_amount = models.JSONField(blank=True, default=dict)
    claim_priority = models.JSONField(blank=True, default=dict)
    category = models.JSONField(blank=True, default=dict)
    sub_category = models.JSONField(blank=True, default=dict)
    status = models.JSONField(blank=True, default=dict)
    action = models.JSONField(blank=True, default=dict)
    provider_name = models.JSONField(blank=True, default=dict)
    provider_npi = models.JSONField(blank=True, default=dict)
    provider_location = models.JSONField(blank=True, default=dict)
    assigned_to = models.JSONField(blank=True, default=dict)
    last_claim_status_check_date = models.JSONField(blank=True, default=dict)
    last_ev_check_date = models.JSONField(blank=True, default=dict)
    last_ins_disc_check_date = models.JSONField(blank=True, default=dict)
    under_pay = models.JSONField(blank=True, default=dict)
    # for to save all csv headers in one_place
    csv_headers = models.JSONField(default=list)
    # Automatically adds the timestamp when the record is created
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.patient_last_name}, {self.patient_first_name}'


class ProjectPage(models.Model):
    project_id = models.CharField(max_length=4, primary_key=True, default=generate_unique_short_id, editable=False)
    project_name = models.CharField(max_length=200)
    clients = models.JSONField(blank=True, default=list)
    status = models.CharField(max_length=100, default='unknown')
    billing_system = models.ForeignKey('MappingRecord', on_delete=models.SET_NULL, null=True, blank=True,
                                       related_name='ProjectPage')
    organization_id = models.CharField(max_length=30, null=True, blank=True, default=None)

    def __str__(self):
        return f"{self.project_name} (ID: {self.project_id})"


class UserCredentials(BaseUser):
    employee_id = models.CharField(max_length=255, unique=True)

    departments = models.ManyToManyField(DeptartmentPage, related_name="user_credentials_departments")

    projects = models.ManyToManyField(ProjectPage, related_name="user_credentials_projects")

    clients = models.ManyToManyField(ClientPage, related_name="user_credentials_clients")

    roles = models.ManyToManyField(RolesPage, related_name="user_credentials_roles")

    sectors = models.ManyToManyField(SectorPage, related_name="user_credentials_sectors")

    stakes = models.ManyToManyField(StakePage, related_name="user_credentials_stakes")

    apps = models.ManyToManyField(AppsPage, related_name="user_credentials_apps")

    class Meta:
        verbose_name_plural = "User Credentials"


class CredentialsForm(models.Model):
    id = models.BigAutoField(primary_key=True)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField()
    password = models.CharField(max_length=128)
    # user = models.ForeignKey(User, on_delete=models.SET_NULL, related_name="crediantialform", null=True, blank=True)
    department = models.ForeignKey(DeptartmentPage, on_delete=models.SET_NULL,
                                   null=True, blank=True)
    # projects = models.ForeignKey(ProjectPage, on_delete=models.SET_NULL,
    #                              null=True, blank=True)

    project = models.ManyToManyField(ProjectPage, related_name="crediantials")

    client = models.ForeignKey(ClientPage, on_delete=models.SET_NULL,
                               null=True, blank=True)
    role = models.ForeignKey(RolesPage, on_delete=models.SET_NULL,
                             null=True, blank=True)
    sector = models.ForeignKey(SectorPage, on_delete=models.SET_NULL,
                               null=True, blank=True)
    stake = models.ForeignKey(StakePage, on_delete=models.SET_NULL,
                              null=True, blank=True)
    app = models.ForeignKey(AppsPage, on_delete=models.SET_NULL,
                            null=True, blank=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.email}) {self.department}"


class ViewRules1(BaseModels):
    view_id = models.BigAutoField(primary_key=True)
    rule_name = models.CharField(max_length=255)
    deptartment = models.CharField(max_length=255, default='unknown')
    projects = models.JSONField(blank=True, default=list)
    auth = models.CharField(max_length=10, default='unknown')
    action = models.JSONField(blank=True, default=list)
    ageing_bucket = models.CharField(max_length=255, blank=True)
    approvals = models.JSONField(blank=True, default=list)
    text_search_fields = models.JSONField(blank=True, default=list)
    range_filters = models.JSONField(blank=True, default=list)
    rule_category = models.CharField(max_length=255, blank=True)
    rule_status = models.CharField(max_length=255, default=0)  # Doggle_Button
    approval_status = models.CharField(max_length=255, default=0)  # Approved or not
    approved_at = models.DateTimeField(null=True, blank=True, default=None)

    approved_by = models.CharField(max_length=255, blank=True)
    rule_target = models.JSONField(blank=True, default=list)

    def __str__(self):
        return f"{self.rule_name} and {self.deptartment} and {self.range_filters}"


class WorkFlowHeaders(models.Model):
    id = models.BigAutoField(primary_key=True)
    source_of_status = models.TextField(default='', blank=True)
    clearing_house_comment = models.TextField(default='', blank=True)
    insurance_name = models.TextField(default='', blank=True)
    clearing_house_name = models.TextField(default='', blank=True)
    insurance_phone = models.TextField(default='', blank=True)
    rep_name = models.TextField(default='', blank=True)
    website_name = models.TextField(default='', blank=True)
    processed_date = models.DateField(null=True, blank=True)  # Allow null for existing records
    paid_date = models.DateField(null=True, blank=True)  # Allow null for existing records
    allowed_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    paid_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    deductible_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    coinsurance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    copayment = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    mode_of_payment = models.TextField(default='', blank=True)
    check_number = models.TextField(default='', blank=True)
    transaction_id = models.TextField(default='', blank=True)
    is_single_bulk_payment = models.BooleanField(default=False)
    payment_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    check_mailing_address = models.TextField(default='', blank=True)
    is_check_paid_on_correct_address = models.BooleanField(default=False)
    is_check_cashed = models.BooleanField(default=False)
    is_payment_cleared = models.BooleanField(default=False)
    encashment_date = models.DateField(null=True, blank=True)
    is_paid_date_crossed_45_days = models.BooleanField(default=False)
    tat_for_encashment_of_payment = models.IntegerField(default=0)
    rep_agrees_to_run_check_tracer = models.BooleanField(default=False)
    tat_for_check_tracer = models.IntegerField(default=0)
    reason_for_not_sending_request_for_check_tracer = models.TextField(null=True, blank=True)
    rep_agrees_to_reissue_new_check = models.BooleanField(default=False)
    rep_agrees_to_reissue_new_payment = models.BooleanField(default=False)
    tat_to_receive_new_payment = models.IntegerField(default=0)
    reason_for_not_reissuing_new_payment = models.TextField(null=True, blank=True)
    w9_form_requested = models.BooleanField(default=False)
    fax_provided = models.BooleanField(default=False)
    fax = models.TextField(null=True, blank=True)
    eob_available_on_website = models.BooleanField(default=False)
    mailing_address = models.TextField(null=True, blank=True)
    source_to_get_eob = models.TextField(default='', blank=True)
    website_name_link = models.TextField(default='', blank=True)
    additional_comment = models.TextField(null=True, blank=True)
    claim_number = models.TextField(default='', blank=True)
    call_reference = models.TextField(default='', blank=True)

    def __str__(self):
        return f"{self.id}"

# Remove RecordNotes
class RecordNotes(models.Model):
    record_id = models.CharField(max_length=255)
    notes = models.TextField()
    date = models.DateTimeField(auto_now_add=True)
    user_name = models.CharField(max_length=255)
    status_code = models.TextField(null=True, blank=True)
    action_code = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"Note by {self.user_name} on {self.date} for record {self.record_id} {self.action_code}"

class PatientRecords(models.Model):
    """
    csv records fields
    """
    upload_session_id = models.CharField(max_length=255, null=True, blank=True)

    input_source = models.TextField()
    mrn = models.TextField()
    patient_id = models.TextField()
    account_number = models.CharField(max_length=200)
    visit_number = models.TextField()
    chart_number = models.TextField()
    project_key = models.TextField()
    facility = models.TextField()
    facility_type = models.TextField()
    patient_last_name = models.TextField()
    patient_first_name = models.TextField()
    patient_phone = models.TextField()
    patient_address = models.TextField()
    patient_city = models.TextField()
    patient_state = models.TextField()
    patient_zip = models.TextField()
    patient_birthday = models.TextField()  # Converted DateField
    patient_gender = models.TextField()
    subscriber_last_name = models.TextField()
    subscriber_first_name = models.TextField()
    subscriber_relationship = models.TextField()
    subscriber_phone = models.TextField()
    subscriber_address = models.TextField()
    subscriber_city = models.TextField()
    subscriber_state = models.TextField()
    subscriber_zip = models.TextField()
    subscriber_birthday = models.TextField()  # Converted DateField
    subscriber_gender = models.TextField()
    current_billed_financial_class = models.TextField()
    current_billed_payer_name = models.TextField()
    member_id_current_billed_payer = models.TextField()
    group_number_current_billed_payer = models.TextField()
    current_billed_relationship = models.TextField()
    cob = models.TextField()
    payer_id_current_billed_payer = models.TextField()
    timely_filing_limit = models.IntegerField(default=0)
    appeal_limit = models.IntegerField(default=0)
    primary_payer_financial_class = models.TextField()
    primary_payer_name = models.TextField()
    member_id_primary_payer = models.TextField()
    group_number_primary_payer = models.TextField()
    relationship_primary_payer = models.TextField()
    cob_primary = models.TextField()
    payer_id_primary_payer = models.TextField()
    secondary_payer_financial_class = models.TextField()
    secondary_payer_name = models.TextField()
    member_id_secondary_payer = models.TextField()
    group_number_secondary_payer = models.TextField()
    relationship_secondary_payer = models.TextField()
    cob_secondary = models.TextField()
    payer_id_secondary_payer = models.TextField()
    tertiary_payer_financial_class = models.TextField()
    tertiary_payer_name = models.CharField(max_length=225)
    member_id_tertiary_payer = models.CharField(max_length=125)
    group_number_tertiary_payer = models.CharField(max_length=125)
    relationship_tertiary_payer = models.CharField(max_length=125)
    cob_tertiary = models.CharField(max_length=125)
    payer_id_tertiary_payer = models.CharField(max_length=125)
    auth_number = models.TextField()
    claim_number = models.CharField(max_length=125)
    facility_code = models.CharField(max_length=125)
    claim_frequency_type = models.CharField(max_length=125)
    signature = models.CharField(max_length=225)
    assignment_code = models.CharField(max_length=125)
    assign_certification = models.CharField(max_length=225)
    release_info_code = models.CharField(max_length=125)
    van_trace_number = models.PositiveIntegerField(default=0)
    rendering_provider_id = models.CharField(max_length=225)
    taxonomy_code = models.CharField(max_length=225)
    procedure_code = models.CharField(max_length=225)

    tooth_code = models.CharField(max_length=125)
    tooth_code2 = models.CharField(max_length=125, blank=True, null=True)
    tooth_code3 = models.CharField(max_length=125, blank=True, null=True)
    tooth_code4 = models.CharField(max_length=125, blank=True, null=True)

    procedure_count = models.IntegerField(default=0)
    procedure_count2 = models.IntegerField(default=0)
    procedure_count3 = models.IntegerField(default=0)
    procedure_count4 = models.IntegerField(default=0)
    procedure_code2 = models.CharField(max_length=200, blank=True, null=True)
    procedure_code3 = models.CharField(max_length=200, blank=True, null=True)
    procedure_code4 = models.CharField(max_length=200, blank=True, null=True)

    dx1 = models.CharField(max_length=125, blank=True, null=True)
    dx2 = models.CharField(max_length=125, blank=True, null=True)
    dx3 = models.CharField(max_length=125, blank=True, null=True)
    dx4 = models.CharField(max_length=125, blank=True, null=True)
    dx5 = models.CharField(max_length=125, blank=True, null=True)
    dx6 = models.CharField(max_length=125, blank=True, null=True)

    check_number = models.CharField(max_length=125, blank=True, null=True)

    amount = models.DecimalField(max_digits=20, decimal_places=10, default=0.0)
    amount2 = models.DecimalField(max_digits=20, decimal_places=10, default=0.0)
    amount3 = models.DecimalField(max_digits=20, decimal_places=10, default=0.0)
    amount4 = models.DecimalField(max_digits=20, decimal_places=10, default=0.0)
    total_charged = models.DecimalField(max_digits=20, decimal_places=10, default=0.0)
    insurance_balance = models.DecimalField(max_digits=20, decimal_places=10, default=0.0)
    patient_balance = models.DecimalField(max_digits=20, decimal_places=10, default=0.0)

    contract_name = models.CharField(max_length=100)
    division = models.CharField(max_length=125)
    type_of_service = models.CharField(max_length=225)
    queue_days = models.PositiveIntegerField(default=0)
    latest_action_date = models.DateField(auto_now_add=False, null=True, blank=True)
    next_follow_up_before = models.DateField(auto_now_add=False, null=True, blank=True)
    claim_denial_date = models.DateField(auto_now_add=False, null=True, blank=True)
    claim_denial_code = models.CharField(max_length=125)
    claim_denial_description = models.TextField()
    latest_pay_date = models.DateField(auto_now_add=False, null=True, blank=True)
    latest_pay_amount = models.DecimalField(max_digits=20, decimal_places=10, default=0.0)
    claim_priority = models.CharField(max_length=225)
    category = models.CharField(max_length=225)
    sub_category = models.CharField(max_length=225)
    status = models.CharField(max_length=225)
    action = models.CharField(max_length=225)
    provider_name = models.CharField(max_length=225)
    provider_npi = models.CharField(max_length=225)
    provider_location = models.CharField(max_length=455)
    last_claim_status_check_date = models.DateField(auto_now_add=False, null=True, blank=True)
    last_ev_check_date = models.DateField(auto_now_add=False, null=True, blank=True)
    last_ins_disc_check_date =models.DateField(auto_now_add=False, null=True, blank=True)
    under_pay = models.DecimalField(max_digits=20, decimal_places=10, default=0.0)

    cpt_procedures = models.JSONField(default=list, blank=True)  # Store multiple procedure codes
    is_cpt_grouped = models.BooleanField(default=False)  # Flag to identify CPT grouped records
    procedure_count_total = models.IntegerField(default=1)  # Total number of procedures
    
    """
    auto generated fields by system 
    based on rules, billing system
    """
    project_id = models.CharField(max_length=225)
    organization_id = models.CharField(max_length=225)
    session_user = models.ForeignKey(BaseUser, on_delete=models.SET_NULL, related_name='current_login_session_user', null=True, blank=True)

    """
    records work flow fields
    """
    # records assigning fields
    assigned_to = models.ManyToManyField(BaseUser, related_name='records_assigned_to_user', blank=True)
    assigned_by = models.ForeignKey(BaseUser, on_delete=models.SET_NULL, related_name='assigned_by_user', null=True, blank=True)

    # records notes adding fields
    allocation_worked = models.BooleanField(default=False)
    worked_date = models.DateTimeField(blank=True, null=True)
    service_date = models.DateField()

    # action set, records ageing
    ageing_bucket = models.CharField(max_length=225, blank=True, null=True)

    # on fresh upload
    # rule unmatched
    allocation_fresh = models.BooleanField(default=True) #also updates on records notes add
    current_queue = models.JSONField(blank=True, default=dict)

    # action: hold
    hold_status = models.BooleanField(default=False)
    hold_days = models.PositiveIntegerField(null=True, blank=True)
    hold = models.JSONField(blank=True, default=dict)
    # action: review
    review_status = models.BooleanField(default=False)
    review_by = models.ForeignKey(BaseUser, on_delete=models.SET_NULL, related_name='review_by_user', null=True, blank=True)
    review_bin_headers = models.CharField(max_length=125, null=True, blank=True)

    # action: move
    allocation_status = models.BooleanField(default=False)
    allocated_to = models.ForeignKey(BaseUser, on_delete=models.SET_NULL, related_name='allocated_to_user', null=True, blank=True)
    allocated_date = models.DateTimeField(auto_now_add=False, blank=True, null=True)
    allocation_allocated = models.BooleanField(default=False) #also updates on records notes add

    # action: custom bins
    """
    custom bins applied on records flow
    """
    custom_bin_applied_status = models.BooleanField(default=False)
    custom_bin_applied = models.ForeignKey(CustomBins, on_delete=models.SET_NULL, related_name='custom_bins_applied_records_set', null=True, blank=True)

    # updates on records assigning
    executive_status = models.BooleanField(default=False)
    executive_bin = models.CharField(max_length=125, null=True, blank=True)


    def __str__(self):
        return f'{self.patient_last_name}, {self.patient_first_name}'

class Codes(models.Model):
    status_code = models.CharField(max_length=50)  # Remove unique=True
    action_codes = models.JSONField(default=list)
    project = models.ForeignKey(Projects, on_delete=models.CASCADE, related_name='code_project')

    class Meta:
        unique_together = ('status_code', 'project')  # Allow same status_code across different projects

    def __str__(self):
        return f"{self.status_code} - {self.project.name}"  # Updated to show project context



class PatientRecordNotes(BaseModels):
    title = AutoSlugField(populate_from='get_custom_patient_notes_slug', blank=True, unique=True)
    notes_descriptions = models.TextField()

    codes = models.ManyToManyField(Codes, related_name='patient_records_code')
    patient_record = models.ForeignKey(PatientRecords, related_name='patient_record_notes', on_delete=models.CASCADE)
    note_writer = models.ForeignKey(BaseUser, on_delete=models.SET_NULL, related_name="patient_records_note_writer", null=True)

    worked_date = models.DateTimeField(auto_now=True)  # updates on each save()
    follow_up_date = models.DateField(null=True, blank=True, auto_now_add=False)

    # Custom method to generate the title
    def get_custom_patient_notes_slug(self):
        """
        for title creation using added note writer user and worked date
        cant use codes due to ManyToManyField
        """
        return f"{self.patient_record} by {self.note_writer}"

    def __str__(self):
        return self.title

class PatientRecordsLogs(BaseModels):
    patient_record = models.ForeignKey(PatientRecords, on_delete=models.SET_NULL, null=True, related_name='logs')
    record_logs_id = models.PositiveIntegerField()
    action = models.CharField(max_length=100, choices=[('ADD', 'Add'), ('UPDATE', 'Update'), ('OPTIONS', 'Options'), ('DELETE', 'Delete')])

    def __str__(self):
        return f"Log for PatientRecord {self.record_logs_id} - Action: {self.action}"

    @receiver(post_save, sender=PatientRecords)
    def create_patient_record_log(sender, instance, created, **kwargs):
        action = 'ADD' if created else 'OPTIONS'
        PatientRecordsLogs.objects.create(
            patient_record=instance,
            record_logs_id=instance.pk,
            action=action,
        )

    @receiver(post_save, sender=PatientRecordNotes)
    def create_patient_record_log(sender, instance, created, **kwargs):
        action = 'UPDATE' if created else 'OPTIONS'
        PatientRecordsLogs.objects.create(
            patient_record=instance.patient_record,
            record_logs_id=instance.patient_record.pk,
            action=action,
        )

    # Save log when a PatientRecord is deleted
    @receiver(post_delete, sender=PatientRecords)
    def delete_patient_record_log(sender, instance, **kwargs):
        PatientRecordsLogs.objects.create(
            patient_record=None,
            record_logs_id=instance.pk,
            action='DELETE',
        )

class FlowChart(BaseModels):
    name = models.CharField(max_length=100)
    flow_data = models.JSONField()
    project = models.CharField(max_length=50)
    status_code = models.ForeignKey(Codes, on_delete=models.CASCADE, related_name='flow_chart_status_code')

    def __str__(self):
        return self.name


class RuleVersions(models.Model):
    reference_id = models.IntegerField()
    approved_by = models.CharField(max_length=150)
    descripation = models.TextField(max_length=150)
    author = models.CharField(max_length=150)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.reference_id


class TargetCorrection(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved_level_1', 'Approved Level 1'),
        ('approved_level_2', 'Approved Level 2'),
        ('rejected', 'Rejected'),
        ('completed', 'Completed'),
    ]
    
    # Employee info
    employee_id = models.CharField(max_length=50)
    employee_name = models.CharField(max_length=100)
    
    # Target info
    old_target = models.FloatField()
    new_target = models.FloatField()
    final_target = models.FloatField()
    
    #  Correct Project relation
    project = models.ForeignKey(Projects, on_delete=models.CASCADE)
    
    # Date range
    start_date = models.DateField()
    end_date = models.DateField()
    
    # Workflow
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Approvers
    approver_1 = models.ForeignKey(
        UserCredentialsSetup, 
        on_delete=models.CASCADE, 
        related_name='target_corrections_as_approver_1'
    )
    approver_2 = models.ForeignKey(
        UserCredentialsSetup, 
        on_delete=models.CASCADE, 
        related_name='target_corrections_as_approver_2',
        null=True, blank=True
    )
    
    # Approval tracking
    approved_by_level_1 = models.ForeignKey(
        UserCredentialsSetup,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='approved_level_1_corrections'
    )
    approved_at_level_1 = models.DateTimeField(null=True, blank=True)
    
    approved_by_level_2 = models.ForeignKey(
        UserCredentialsSetup,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='approved_level_2_corrections'
    )
    approved_at_level_2 = models.DateTimeField(null=True, blank=True)
    
    # Rejection tracking
    rejected_by = models.ForeignKey(
        UserCredentialsSetup,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='rejected_corrections'
    )
    rejected_at = models.DateTimeField(null=True, blank=True)
    rejection_reason = models.TextField(null=True, blank=True)
    
    # Comments
    comments = models.TextField(null=True, blank=True)
    
    # ADD THESE MISSING FIELDS:
    created_by = models.ForeignKey(
        UserCredentialsSetup,
        on_delete=models.CASCADE,
        related_name='target_corrections_created',
        null=True, blank=True  # Allow null for existing records
    )
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, null=True, blank=True)

    class Meta:
        db_table = 'target_corrections'
        verbose_name = 'Target Correction'
        verbose_name_plural = 'Target Corrections'
        ordering = ['-id']  # Keep this as fallback

    def __str__(self):
        return f"Target Correction - {self.employee_name} ({self.employee_id})"

    def can_be_approved_by(self, user_credentials_setup):
        """Check if a user can approve this correction"""
        if self.status == 'pending' and self.approver_1 == user_credentials_setup:
            return True
        if self.status == 'approved_level_1' and self.approver_2 == user_credentials_setup:
            return True
        return False
    
    def get_next_approver(self):
        """Get the next approver for this correction"""
        if self.status == 'pending':
            return self.approver_1
        elif self.status == 'approved_level_1' and self.approver_2:
            return self.approver_2
        return None
    
    @property
    def is_pending_approval(self):
        """Check if this correction is pending approval"""
        return self.status in ['pending', 'approved_level_1']
    
    @property
    def is_completed(self):
        """Check if this correction is completed"""
        return self.status == 'completed'
    
    @property
    def is_rejected(self):
        """Check if this correction is rejected"""
        return self.status == 'rejected'
    
    class Meta:
        db_table = 'target_corrections'
        verbose_name = 'Target Correction'
        verbose_name_plural = 'Target Corrections'
        ordering = ['-created_at']   # ✅ now safe because field exists

    def __str__(self):
        return f"Target Correction - {self.employee_name} ({self.employee_id})"
    





class TabTiming(models.Model):
    """Model to track user tab timing and activity"""
    
    tab_key = models.CharField(max_length=255, help_text="Unique identifier for the tab")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='tab_timings')
    patient_id = models.CharField(max_length=100, null=True, blank=True, help_text="Patient ID if applicable")
    tab_name = models.CharField(max_length=255, help_text="Display name of the tab")
    sub_header = models.CharField(max_length=100, help_text="Sub header section")
    tab_type = models.CharField(max_length=100, help_text="Type of tab (e.g., 'demographics', 'insurance')")
    project_id = models.CharField(max_length=100, help_text="Associated project ID",null=True,blank=True)
    
    opened_at = models.DateTimeField(help_text="When the tab was opened")
    closed_at = models.DateTimeField(null=True, blank=True, help_text="When the tab was closed")
    total_active_time = models.IntegerField(default=0, help_text="Total active time in milliseconds")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'records_tab_timing'
        indexes = [
            models.Index(fields=['user', 'tab_type', 'created_at']),
            models.Index(fields=['patient_id', 'user']),
            models.Index(fields=['project_id', 'created_at']),
            models.Index(fields=['tab_key']),
        ]
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user} - {self.tab_name} ({self.total_active_time}ms)"
    
    @property
    def active_duration_seconds(self):
        return self.total_active_time / 1000 if self.total_active_time else 0
    
    @property
    def active_duration_formatted(self):
        total_seconds = self.active_duration_seconds
        minutes = int(total_seconds // 60)
        seconds = int(total_seconds % 60)
        return f"{minutes:02d}:{seconds:02d}"
    
    @property
    def session_duration(self):
        if self.opened_at and self.closed_at:
            return (self.closed_at - self.opened_at).total_seconds()
        return None


class UserTabActivity(models.Model):
    """Model to track daily user activity summary"""
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='daily_activities')
    date = models.DateField(default=timezone.now)
    project_id = models.CharField(max_length=100,null=True,blank=True)
    tab_type = models.CharField(max_length=100)
    sub_header = models.CharField(max_length=100)
    
    total_tabs_opened = models.IntegerField(default=0)
    total_active_time = models.IntegerField(default=0, help_text="Total active time in milliseconds")
    unique_patients_viewed = models.IntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'records_user_tab_activity'
        unique_together = ['user', 'date', 'project_id', 'tab_type', 'sub_header']
        indexes = [
            models.Index(fields=['user', 'date']),
            models.Index(fields=['project_id', 'date']),
            models.Index(fields=['date']),
        ]
        ordering = ['-date']
    
    def __str__(self):
        return f"{self.user} - {self.date} - {self.tab_type}"