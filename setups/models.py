from time import timezone

from django.conf import Settings
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from autoslug import AutoSlugField
from multiselectfield import MultiSelectField

from common.models import BaseModels
from users.models import BaseUser

class Apps(BaseModels):
    app_name = models.CharField(max_length=255)

    def __str__(self):
        return  self.app_name

class Organizations(BaseModels):
    organization_name = models.CharField(max_length=255, unique=True)
    apps = models.ManyToManyField(Apps, related_name='organization')

    def __str__(self):
        return self.organization_name

class ScreensChoices(models.TextChoices):
    ROLES = "Roles", _("Roles")
    ADMIN = "Admin", _("Admin")
    DEPARTMENTS = "Departments", _("Departments")
    PROJECTS = "Projects", _("Projects")
    CLIENTS = "Clients", _("Clients")
    ORGANIZATIONS = "Organizations", _("Organizations")
    STAKE = "Stake", _("Stake")
    APPS = "Apps", _("Apps")
    UPLOAD = "Upload", _("Upload")
    ZERO_UPLOAD = "Zero-Upload", _("Zero-Upload")
    BILLING_SYSTEM = "Billing-System", _("Billing-System")
    ALLOCATION_AR = "Allocation-Ar", _("Allocation-Ar")
    ALLOCATION_DENIALS = "Allocation-Denials", _("Allocation-Denials")
    ALLOCATION_ECT = "Allocation-Ect", _("Allocation-Ect")
    ALLOCATION_CORRESPONDING = "Allocation-Corresponding", _("Allocation-Corresponding")
    EXECUTIVE_AR = "Executive-Ar", _("Executive-Ar")
    EXECUTIVE_DENIALS = "Executive-Denials", _("Executive-Denials")
    EXECUTIVE_ECT = "Executive-Ect", _("Executive-Ect")
    EXECUTIVE_CORRESPONDING = "Executive-Corresponding", _("Executive-Corresponding")
    REVIEW_AR = "Review-Ar", _("Review-Ar")
    REVIEW_CODING = "Review-Coding", _("Review-Coding")
    REVIEW_PAYMENTS = "Review-Payments", _("Review-Payments")
    REVIEW_CORRESPONDING = "Review-Corresponding", _("Review-Corresponding")
    REVIEW_BILLING = "Review-Billing", _("Review-Billing")
    REVIEW_CREDENTIAL = "Review-Credential", _("Review-Credential")
    ORGANIZATION_RULES = "Organization-Rules", _("Organization-Rules")
    OPS_RULES = "Ops-Rules", _("Ops-Rules")
    SOP_RULES = "Sop-Rules", _("Sop-Rules")
    VIEW_RULES = "View-Rules", _("View-Rules")
    APPROVALS = "Approvals", _("Approvals")
    HOLDQ = "HoldQ", _("HoldQ")
    CREATE_CODES = "Create-Codes", _("Create-Codes")
    VIEW_SOP_RULES = "View-Sop-Rules", _("View-Sop-Rules")
    CUSTOM_BINS = "Custom-Bins", _("Custom-Bins")
    USER_ALLOCATION_BINS_RECORDS = "User-Allocation-Bins-Records", _("User-Allocation-Bins-Records")
    
    INSURANCE_INFORMATION = "Insurance-Information", _("Insurance Information")
    FLOW_SETUP = "Flow-Setup", _("Flow Setup")
    VIEW_FLOWS = "View-Flows", _("View Flows")

    Analytics_Dashboard = "Tab-Analytics-Dashboard", _("Tab-Analytics-Dashboard")
 
    SETTINGS = "Settings", _("Settings")
    
# todo : remove ORGANIZATION_RULES and OPS_RULES separately, provide separate selection

class Roles(BaseModels):
    role_name = models.CharField(max_length=255, unique=True)
    screens = MultiSelectField(choices=ScreensChoices)
    organization = models.ForeignKey(Organizations, on_delete=models.DO_NOTHING, related_name='roles_set')

    # Use a custom method to generate the slug
    def get_custom_role_slug(self):
        return f"{self.role_name} {self.organization.organization_name}"

    slug = AutoSlugField(populate_from='get_custom_role_slug', blank=True, unique=True)

    def __str__(self):
        return self.slug

class Clients(BaseModels):
    client_name = models.CharField(max_length=255)
    status = models.CharField(max_length=255)
    """
    one organization can have multiple clients, ForeignKey with no reverse relation 
    """
    organization = models.ForeignKey(Organizations, on_delete=models.CASCADE, related_name='+')

    # Use a custom method to generate the slug
    def get_custom_client_slug(self):
        return f"{self.client_name} {self.organization.organization_name}"

    slug = AutoSlugField(populate_from='get_custom_client_slug', blank=True, unique=True)

    def __str__(self):
        return self.slug

class Projects(BaseModels):
    project_name = models.CharField(max_length=255)
    status = models.CharField(max_length=255)
    clients = models.ManyToManyField(Clients, related_name='projects_set')
    """
    projects can have multiple billing system, with billing_project_set accessor
    """
    # billing_system_mapping = models.ForeignKey(BillingSystemMappingRecord, on_delete=models.DO_NOTHING, related_name='projects_set')
    """
    one organization can have multiple projects and clients, ForeignKey with no reverse relation 
    """
    organization = models.ForeignKey(Organizations, on_delete=models.CASCADE, related_name='+')
    """
    user joined to project <date field> 
    auto creates when project is assigned to users
    """

    # Use a custom method to generate the slug
    def get_custom_project_slug(self):
        return f"{self.project_name} {self.organization.organization_name}"

    slug = AutoSlugField(populate_from='get_custom_project_slug', blank=True, unique=True)

    def __str__(self):
        return self.slug

class Departments(BaseModels):
    department_name = models.CharField(max_length=255)
    """
    one organization can have multiple departments, ForeignKey with no reverse relation 
    """
    organization = models.ForeignKey(Organizations, on_delete=models.CASCADE, related_name='+')

    # Use a custom method to generate the slug
    def get_custom_department_slug(self):
        return f"{self.department_name} {self.organization.organization_name}"

    slug = AutoSlugField(populate_from='get_custom_department_slug', blank=True, unique=True)

    def __str__(self):
        return self.slug

class Stakes(BaseModels):
    stake_name = models.CharField(max_length=255)
    """
    one organization can have multiple stakes, ForeignKey with no reverse relation 
    """
    organization = models.ForeignKey(Organizations, on_delete=models.CASCADE, related_name='+')

    # Use a custom method to generate the slug
    def get_custom_stakes_slug(self):
        return f"{self.stake_name} {self.organization.organization_name}"

    slug = AutoSlugField(populate_from='get_custom_stakes_slug', blank=True, unique=True)

    def __str__(self):
        return self.slug

"""
user experience options
"""
class ExperienceLevelChoices(models.TextChoices):
    LATERAL = 'Lateral', 'Lateral'
    FRESHER = 'Fresher', 'Fresher'

"""
performance improvement program levels options
"""
class PIPLevels(models.TextChoices):
    LEVEL1 = 'Level1', 'Level1'
    LEVEL2 = 'Level2', 'Level2'
    LEVEL3 = 'Level3', 'Level3'
    LEVEL4 = 'Level4', 'Level4'

class UserCredentialsSetup(BaseUser):
    employee_id = models.CharField(max_length=255, unique=True)

    organizations = models.ManyToManyField(Organizations, related_name="users_credentials_organizations")

    apps = models.ManyToManyField(Apps, related_name="users_credentials_apps")

    clients = models.ManyToManyField(Clients, related_name="users_credentials_clients")

    # projects field
    # use the project_assignments attribute to access projects assigned to a user.

    project_joined_date = models.DateField(null=True, blank=True)


    departments = models.ManyToManyField(Departments, related_name="users_credentials_departments")

    roles = models.ManyToManyField(Roles, related_name="users_credentials_roles")

    stakes = models.ManyToManyField(Stakes, related_name="users_credentials_stakes")

    """
    Approval Users   
    """
    approve_user_1 = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='%(class)s_approval_1',
        verbose_name='Approve_User_1'
    )

    approve_1_employee_id = models.CharField(max_length=255, blank=True)

    approve_user_2 = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='%(class)s_approval_2',
        verbose_name='Approve_User_2'
    )

    approve_2_employee_id = models.CharField(max_length=255, blank=True)

    # user experience
    experience_level = models.CharField(max_length=55, choices=ExperienceLevelChoices)

    # date of user joined
    user_date_of_joining = models.DateField(auto_now_add=True)

    """
    use the project_assignments's attribute to access user project joined date.
    """

    """
    performance improvement program [PIP] fields
    """
    pip_level_flag = models.BooleanField(default=False)

    # pip issued date, start date
    pip_start_date = models.DateField(auto_now_add=False, null=True, blank=True)

    # pip issued date, end date
    pip_end_date = models.DateField(auto_now_add=False, null=True, blank=True)

    # pip level
    pip_level = models.CharField(max_length=55, choices=PIPLevels, null=True, blank=True)

    class Meta:
        verbose_name_plural = "User Credentials"

class UserProjectAssignment(models.Model):
    user = models.ForeignKey(UserCredentialsSetup, on_delete=models.CASCADE, related_name='project_assignments')
    project = models.ForeignKey(Projects, on_delete=models.CASCADE, related_name='user_assignments')
    project_joined_date = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'project')

    def __str__(self):
        return f"{self.project.project_name} - {self.user.first_name}"

class BillingSystemMappingRecord(models.Model):
    """
    Mapping Records to Store Billing system
    """
    organization = models.ForeignKey(Organizations, on_delete=models.CASCADE, related_name='+')
    """
    one organization can have multiple billing systems, ForeignKey with no reverse relation
    """

    project = models.ForeignKey(Projects, on_delete=models.CASCADE, related_name='billing_project_set', null=True, blank=True)
    """
    project can have multiple billing systems, ForeignKey reverse relation
    """
    is_cpt_level = models.BooleanField(default=False)

    
    selected_bin = models.CharField(max_length=255, blank=True, null=True)
    billing_system_file_name = models.CharField(max_length=200)
    input_source = models.JSONField(default=dict)
    mrn = models.JSONField(default=dict)
    patient_id = models.JSONField(default=dict)
    account_number = models.JSONField(default=dict)
    visit_number = models.JSONField(default=dict)
    chart_number = models.JSONField(default=dict)
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

    def __str__(self):
        return f'{self.patient_last_name}, {self.patient_first_name}'


class CustomBins(BaseModels):
    """
    custom bins for rule processing,
    organization dependent -> multiple bins can be in single organization
    one organization can have multiple custom bins,
    """
    organization = models.ForeignKey(Organizations, on_delete=models.CASCADE, related_name='+')
    title = AutoSlugField(populate_from='get_custom_bin_slug', blank=True, unique=True)
    name = models.CharField(max_length=225)
    threshold = models.CharField(max_length=255)

    # Use a custom method to generate the slug
    def get_custom_bin_slug(self):
        return f"{self.name} {self.organization.organization_name}"

    def __str__(self):
        return self.title

class TargetSettings(BaseModels):
    """
    Target settings for set records work targets
    total target duration 8 hours
    """
    title = AutoSlugField(populate_from='get_custom_target_slug', blank=True, unique=True)
    records_target_count = models.PositiveBigIntegerField(validators=[MinValueValidator(1)])
    # total no of working hours
    total_working_hours = models.PositiveSmallIntegerField(validators=[MinValueValidator(1)])
    """
    employee experience based target setting
    accessible via target_allocation relation
    """
    """
    sets target to projects  
    relation between projects
    """
    projects = models.OneToOneField(Projects, on_delete=models.CASCADE, related_name='project_target_settings')

    def get_custom_target_slug(self):
        return f"{self.projects.project_name} target:{self.records_target_count} in {self.total_working_hours} hours"

    def __str__(self):
        return self.title

class UserTypeBasedTarget(models.Model):
    """
    user role based target setting
    in percentage scale
    having one-to-many relationship with TargetSettings
    here one TargetSettings can have multiple RoleBasedRecordTargetAllocation objects no reverse relation
    """
    title = AutoSlugField(populate_from='role_based_records_allocation_slug', always_update=True, blank=True, unique=True)
    records_target = models.ForeignKey(TargetSettings, on_delete=models.CASCADE, related_name='target_allocation')
    targeting_week = models.PositiveSmallIntegerField(validators=[MinValueValidator(1), MaxValueValidator(8)])
    fresher_targets = models.PositiveSmallIntegerField(validators=[MaxValueValidator(100)], null=True, blank=True)
    pip_targets = models.PositiveSmallIntegerField(validators=[MaxValueValidator(100)], null=True, blank=True)
    lateral_targets = models.PositiveSmallIntegerField(validators=[MaxValueValidator(100)], null=True, blank=True)

    class Meta:
        ordering = ["title"]

    def role_based_records_allocation_slug(self):
        return f"{self.records_target.title}-{self.targeting_week}Week"

    def __str__(self):
        return self.title



# Add this to your setups/models.py file

class Insurance(models.Model):
    insurance_name = models.CharField(max_length=255)
    phone_no = models.CharField(max_length=20)
    extension = models.CharField(max_length=10, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    open_close_time = models.CharField(max_length=100, blank=True, null=True)
    prefix = models.CharField(max_length=10, blank=True, null=True)
    claim_address = models.TextField(blank=True, null=True)
    appeal_address = models.TextField(blank=True, null=True)
    claim_tfl_days = models.PositiveIntegerField(blank=True, null=True, help_text="Claim Time Frame Limit in days")
    appeal_tfl_days = models.PositiveIntegerField(blank=True, null=True, help_text="Appeal Time Frame Limit in days")
    web_page_address = models.URLField(max_length=500, blank=True, null=True)
    group_username = models.CharField(max_length=100, blank=True, null=True)
    group_password = models.CharField(max_length=100, blank=True, null=True)
    individual_username = models.CharField(max_length=100, blank=True, null=True)
    individual_password = models.CharField(max_length=100, blank=True, null=True)
    password_expiry_duration = models.CharField(max_length=50, blank=True, null=True)
    
    # Project relationship - assuming you have a Project model
    project = models.CharField(max_length=100)  # You can change this to ForeignKey if you have a Project model
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Insurance'
        verbose_name_plural = 'Insurance Records'
    
    def __str__(self):
        return f"{self.insurance_name} - {self.project}"