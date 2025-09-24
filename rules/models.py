from autoslug import AutoSlugField
from django.db import models
from django.utils.translation import gettext_lazy as _

from users.models import BaseUser
from common.models import BaseModels
from setups.models import Projects, Departments, UserCredentialsSetup, CustomBins

class Rules(models.Model):
    """
    Rules model for rules set [range fields]
    Fields defined to accommodate ranges and specific values.
    """

    # MRN Range
    mrn_from = models.CharField(max_length=125, blank=True)
    mrn_to = models.CharField(max_length=125, blank=True)

    # Patient IDs Range
    patient_id_from = models.CharField(max_length=125, blank=True)
    patient_id_to = models.CharField(max_length=125, blank=True)

    # Financial Balances
    insurance_balance_from = models.DecimalField(decimal_places=2, max_digits=15, default=0.00)
    insurance_balance_to = models.DecimalField(decimal_places=2, max_digits=15, default=0.00)

    patients_balance_from = models.DecimalField(decimal_places=2, max_digits=15, default=0.00)
    patients_balance_to = models.DecimalField(decimal_places=2, max_digits=15, default=0.00)

    # Other fields
    account_number_from = models.CharField(max_length=125, blank=True)
    account_number_to = models.CharField(max_length=125, blank=True)
    chart_number_from = models.CharField(max_length=125, blank=True)
    chart_number_to = models.CharField(max_length=125, blank=True)
    timely_filling_limit_from = models.CharField(max_length=125, blank=True)
    timely_filling_limit_to = models.CharField(max_length=125, blank=True)

    service_date_from = models.DateField(_("Date"), auto_now_add=False, auto_now=False, blank=True, null=True)
    service_date_to = models.DateField(_("Date"), auto_now_add=False, auto_now=False, blank=True, null=True)

    total_charged_amount_from = models.DecimalField(decimal_places=2, max_digits=15, default=0.00)
    total_charged_amount_to = models.DecimalField(decimal_places=2, max_digits=15, default=0.00)

    visit_number_from = models.CharField(max_length=125, blank=True)
    visit_number_to = models.CharField(max_length=125, blank=True)

    appeal_limit_from = models.CharField(max_length=125, blank=True)
    appeal_limit_to = models.CharField(max_length=125, blank=True)

    class Meta:
        abstract = True


class TextLookUpFields(models.Model):
    """
    text fields for exact look up
    """
    current_billed_payer_name = models.CharField(max_length=255, blank=True)
    secondary_payer_name = models.CharField(max_length=255, blank=True)
    tertiary_payer_name = models.CharField(max_length=255, blank=True)

    claim_denial_code = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=255, blank=True)

    provider_name = models.CharField(max_length=255, blank=True)
    provider_location = models.CharField(max_length=255, blank=True)
    provider_npi = models.CharField(max_length=255, blank=True)
    division = models.CharField(max_length=255, blank=True)

    procedure_code_1 = models.CharField(max_length=255, blank=True)
    procedure_code_2 = models.CharField(max_length=255, blank=True)
    procedure_code_3 = models.CharField(max_length=255, blank=True)

    dx_1 = models.CharField(max_length=255, blank=True)
    dx_2 = models.CharField(max_length=255, blank=True)
    dx_3 = models.CharField(max_length=255, blank=True)

    facility = models.CharField(max_length=255, blank=True)

    patient_first_name = models.CharField(max_length=255, blank=True)
    patient_last_name = models.CharField(max_length=255, blank=True)
    patient_city = models.CharField(max_length=255, blank=True)

    class Meta:
        abstract = True

class ReviewBinSubHeaders(models.TextChoices):
    AR = 'ar', 'AR'
    CODING = 'coding', 'Coding'
    PAYMENTS = 'payments', 'Payments'
    CORRESPONDING = 'corresponding', 'Corresponding'
    BILLING = 'billing', 'Billing'
    CREDENTIAL = 'credential', 'Credential'

class HoldQDurationOptions(models.IntegerChoices):
    SEVEN_DAYS = 7, '7 Days'
    FIFTEEN_DAYS = 15, '15 Days'
    THIRTY_DAYS = 30, '30 Days'
    SIXTY_DAYS = 60, '60 Days'
    ONE_EIGHTY_DAYS = 180, '180 Days'

class AgeingBucket(models.TextChoices):
    _0_30 = '0-30', '0-30 days'
    _31_60 = '31-60', '31-60 days'
    _61_90 = '61-90', '61-90 days'
    _91_180 = '91-180', '91-180 days'
    _181_360 = '181-360', '181-360 days'
    _360_plus = '360+', '360+ days'

class MoveBinsOptions(models.TextChoices):
    pass

class RuleActions(models.Model):
    review_bin_headers = models.CharField(max_length=25, choices=ReviewBinSubHeaders, null=True, blank=True)
    reviewing_user = models.ForeignKey(BaseUser, on_delete=models.SET_NULL, null=True, blank=True)
    hold_q = models.IntegerField(
        choices=HoldQDurationOptions.choices,
        null=True,
        blank=True
    )
    ageing_bucket = models.CharField(max_length=25, choices=AgeingBucket.choices, null=True, blank=True)
    custom_bins = models.ForeignKey(CustomBins, on_delete=models.CASCADE, related_name='rule_action_custom_bin_set', null=True, blank=True)

    # Use a custom method to generate the slug
    def get_custom_rule_slug(self):
        if self.review_bin_headers and self.reviewing_user: return f"{self.review_bin_headers} {self.reviewing_user.first_name}"
        if self.hold_q: return f"Hold Duration {self.hold_q} days"
        if self.ageing_bucket: return f"Ageing Bucket {self.ageing_bucket}"
        if self.custom_bins: return f"Custom Bin {self.custom_bins.title}"

    rule_title = AutoSlugField(populate_from='get_custom_rule_slug', always_update=True, blank=True, unique=True)

    def __str__(self):
        return self.rule_title

class RulesAndTypes(Rules, TextLookUpFields, BaseModels):

    authentication = models.BooleanField(default=False)
    rule_name = models.CharField(max_length=255, blank=False, null=False)
    project = models.ManyToManyField(Projects, related_name='rules_project_set')
    department = models.ForeignKey(Departments, on_delete=models.CASCADE)
    action = models.ForeignKey(RuleActions, on_delete=models.CASCADE, related_name='rule_actions')

    rule_status = models.BooleanField(default=True)

    # FIXED: Changed from OneToOneField to ForeignKey to allow same user for multiple rules
    approves_1 = models.ForeignKey(UserCredentialsSetup, on_delete=models.SET_NULL, related_name='rules_approve_1_set', null=True, blank=True)
    approves_2 = models.ForeignKey(UserCredentialsSetup, on_delete=models.SET_NULL, related_name='rules_approve_2_set', null=True, blank=True)
    approved_by = models.ForeignKey(UserCredentialsSetup, on_delete=models.SET_NULL, related_name='rules_approved_by_set', null=True, blank=True)
    
    approved_at = models.DateTimeField(auto_now_add=False, blank=True, null=True)
    approved_status = models.BooleanField(default=False)

    rule_target_apply_to_existing_records = models.BooleanField(default=False)
    rule_target_apply_to_new_records = models.BooleanField(default=True)
    rule_category = models.CharField(max_length=255, blank=False)