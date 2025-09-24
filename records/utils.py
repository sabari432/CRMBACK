import json
import logging
import pandas as pd
from datetime import date
from rules.models import RulesAndTypes

# Configure the logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)  # Set to DEBUG for more detailed logs
handler = logging.StreamHandler()  # You can also use FileHandler for file logs
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

text_lookup_field_names = [
    "current_billed_payer_name",
    "secondary_payer_name",
    "tertiary_payer_name",
    "claim_denial_code",
    "status",
    "provider_name",
    "provider_location",
    "provider_npi",
    "division",
    "procedure_code_1",
    "procedure_code_2",
    "procedure_code_3",
    "dx_1",
    "dx_2",
    "dx_3",
    "facility",
    "patient_first_name",
    "patient_last_name",
    "patient_city"
]

range_filters_field_names = [
    'mrn_from',
    'mrn_to',
    'patient_id_from',
    'patient_id_to',
    'insurance_balance_from',
    'insurance_balance_to',
    'patients_balance_from',
    'patients_balance_to',
    'account_number_from',
    'account_number_to',
    'chart_number_from',
    'chart_number_to',
    'timely_filling_limit_from',
    'timely_filling_limit_to',
    'service_date_from',
    'service_date_to',
    'total_charged_amount_from',
    'total_charged_amount_to',
    'visit_number_from',
    'visit_number_to',
    'appeal_limit_from',
    'appeal_limit_to'
]

def mapColumns(mapping_data_instance, mapping_data_column_names):
    """maps csv columns with mapping records model fields"""
    dynamic_values = {}
    for column in mapping_data_column_names:
        dynamic_values[column] = getattr(mapping_data_instance, column, {}).get('value', '')
    return dynamic_values


def remove_unnecessary_keys(*rule):
    """Remove unnecessary keys from a rule dictionary."""
    keys_to_exclude = [
        'view_id',      
        'rule_name',     
        'deptartment',   
        'approvals',    
        'projects',      
        'created_by',    
        'created_at',    
        'rule_category', 
        'rule_status',   
        'approval_status', 
        'rule_target'   
    ]
    
    for each_rule in rule:
        if isinstance(each_rule, dict):
            for key in keys_to_exclude:
                each_rule.pop(key, None) 
    return rule
    
def removeEmptyfields(data):
    """Remove empty fields from rules"""
    if isinstance(data, dict):
        return {k: removeEmptyfields(v) for k, v in data.items() if v not in ("", None, [], {}) and k not in ['id', 'created_at', 'updated_at']}
    elif isinstance(data, list):
        return [removeEmptyfields(item) for item in data if item not in ("", None, [], {}) and item not in ['id', 'created_at', 'updated_at']]
    else:
        # remove_unnecessary_keys(data)
        return data
 
    
class RuleChecker:
    def __init__(self, records, rules):
        self.records = records
        self.rules = rules

    def match_field(self, record_field, expected_value):
        """Match field values considering different data types."""
        
        # Case 1: Both are dictionaries - compare recursively
        if isinstance(record_field, dict) and isinstance(expected_value, dict):
            for sub_key, sub_value in expected_value.items():
                # If sub_key doesn't exist or values do not match, return False
                if sub_key not in record_field or not self.match_field(record_field[sub_key], sub_value):
                    return False
            return True
        
        # Case 2: Both are lists - check each element
        if isinstance(record_field, list) and isinstance(expected_value, list):
            if len(record_field) != len(expected_value):
                return False
            # Check each element in the list
            for i in range(len(record_field)):
                if not self.match_field(record_field[i], expected_value[i]):
                    return False
            return True
        
        # Case 3: Case-insensitive comparison for strings
        if isinstance(record_field, str) and isinstance(expected_value, str):
            if record_field.casefold() in [expected_value.casefold()]: return True
        
        # Case 4: If they're other data types (e.g., integers, floats), just compare them directly
        return record_field == expected_value


    def check_text_search_fields(self, rule):
        """Check the text_search_fields of a rule."""
        try:
            test_lookup_values = {key: val for key, val in rule.items() if key in text_lookup_field_names}
            for field, expected_value in test_lookup_values.items():

                return self.match_field(self.records[field], expected_value) if field in self.records else False
                    # logger.warning(
                    # f"Field {field} is missing in the record."))
        except KeyError as e:
            logger.error(f"text to search fields is not found in applied rules")
            return  True

    def check_range_filters(self, rule):
        """Check the range_filters of a rule."""
        try:
            range_filters = {key: val for key, val in rule.items() if key in range_filters_field_names}
            for field, condition in range_filters.items():
                if condition in ('', {}, []):
                    continue
                try:
                    if field in self.records:
                        from_val = condition.get('from', None)
                        to_val = condition.get('to', None)
                        record_val = self.records[field]

                        # Convert the record value if it's a digit string
                        if isinstance(record_val, str) and record_val.isdigit():
                            record_val = int(record_val)

                        if from_val is not None and record_val < int(from_val):
                            logger.warning(f"Field {field} is less than 'from' value. Found: {record_val}, Required: >= {from_val}")
                            return False
                        if to_val is not None and record_val > int(to_val):
                            logger.warning(f"Field {field} is greater than 'to' value. Found: {record_val}, Required: <= {to_val}")
                            return False
                    else:
                        logger.warning(f"Field {field} is missing in the record.")
                        return False
                except Exception as e:
                    pass
        except KeyError as e:
            logger.error(f"range filters not found in applied rules")
            return True

    def check_other_fields(self, rule):
        """Check other fields that are not part of text_search_fields or range_filters."""
        # other_fields = ['auth', 'approvals', 'rule_status', 'created_at', 'text_search_fields', 'range_filters']
        other_fields = ['auth', 'action', 'ageing_bucket',
                             'approvals', 'range_filters', 'text_search_fields']
        for field, expected_value in rule.items():
            if (field not in  other_fields) and (expected_value not in ('', {}, [])):
                if (field in self.records) and (self.records[field] != expected_value):
                    logger.warning(f"Field {field} doesn't match. Expected: {expected_value}, Found: {self.records[field]}")
                    return False
                else:
                    logger.warning(f"Field {field} is missing in the record.")
                    return False
        return True

    def check_records(self):
        """Main method to check all records against rules."""
        # rule_match_status = []  # Create an empty list to store statuses

        for rule in self.rules:
            # 1: Validate text_search_fields

            # 2: Validate range_filters

            # 3: Validate other fields
            rule_status = {'text_field_filter': self.check_text_search_fields(rule),
                           # 'range_field_filter': self.check_range_filters(rule),
                           # 'other_field_filter': self.check_other_fields(
                           #     rule)
                           }
            return rule_status

class RuleApplier:
    def __init__(self, evaluated_rules, cleaned_records, project_id, selected_bin):
        self.evaluated_rules = evaluated_rules
        self.cleaned_records = cleaned_records
        self.selected_bin = selected_bin
        self.project_id = project_id

    def check_record_against_rules(self, record, rules):
        """Determine if a rule applies to the given record."""
        # create instance of RuleChecker[utils]
        rule_checker = RuleChecker(record, rules)
        # validate records against rules
        rule_matcher = rule_checker.check_records()
        return rule_matcher

    def apply_rules(self):
        results = []
        for record in self.cleaned_records:
            if not self.match_and_apply_rule(record):
                self.apply_default_allocation(record)
            results.append(record)
        return results

    def match_and_apply_rule(self, record):
        # match record against evaluated rules
        match_statuses = self.check_record_against_rules(record, self.evaluated_rules)

        text_lookup_field_match_status = match_statuses['text_field_filter']
        # range_filters_field_match_status = match_statuses['range_field_filter']
        # other_field_match_status = match_statuses['other_field_filter']

        # Execute specific actions based on the matched rule
        # return self.execute_rule_action(record) if text_lookup_field_match_status or range_filters_field_match_status or other_field_match_status else False
        return self.execute_rule_action(record) if text_lookup_field_match_status else False

    def execute_rule_action(self, record):
        try:
            # Fetch all relevant actions at once
            action_entries = RulesAndTypes.objects.select_related('action').filter(
                project__id=self.project_id
            )

            action_applied = False
            for entry in action_entries:
                if entry.action.reviewing_user:
                    record['review_by'] = entry.action.reviewing_user
                    record['review_bin_headers'] = entry.action.review_bin_headers
                    record['latest_action_date'] = date.today()
                    record['current_queue'] = {self.selected_bin: 'review'}
                    record['custom_bin_applied'] = None
                    record['hold_days'] = 0

                    # status fields
                    record['allocation_worked'] = False
                    record['allocation_fresh'] = False
                    record['hold_status'] = False
                    record['review_status'] = True
                    record['allocation_status'] = False
                    record['allocation_allocated'] = False
                    record['executive_status'] = False
                    record['custom_bin_applied_status'] = False
                    action_applied = True

                if entry.action.hold_q:
                    record['hold_days'] = entry.action.hold_q
                    record['latest_action_date'] = date.today()
                    record['current_queue'] = {self.selected_bin: 'hold'}
                    record['custom_bin_applied'] = None

                    # status fields
                    record['allocation_worked'] = False
                    record['allocation_fresh'] = False
                    record['hold_status'] = True
                    record['review_status'] = False
                    record['allocation_status'] = False
                    record['allocation_allocated'] = False
                    record['executive_status'] = False
                    record['custom_bin_applied_status'] = False
                    action_applied = True

                if entry.action.custom_bins:
                    # apply custom allocation rule specific fields
                    record['current_queue'] = {entry.action.custom_bins.title: 'custom_fresh'}
                    record['custom_bin_applied'] = entry.action.custom_bins # custom bins applied foreign key reference
                    record['latest_action_date'] = date.today()
                    record['review_by'] = None
                    record['review_bin_headers'] = ''
                    record['hold_days'] = 0

                    # custom bins related status fields
                    record['custom_bin_applied_status'] = True
                    record['allocation_worked'] = False
                    record['allocation_fresh'] = False
                    record['hold_status'] = False
                    record['review_status'] = False
                    record['allocation_status'] = True
                    record['allocation_allocated'] = False
                    record['executive_status'] = False
                    action_applied = True

            return action_applied
        except KeyError as e:
            logger.error(f"Missing key in action data: {str(e)}")
            return False
        except Exception as e:
            logger.exception("Error executing rule actions")
            return False

    def apply_default_allocation(self, record):
        # apply default allocation
        record['current_queue'] = {self.selected_bin: 'fresh'}
        record['latest_action_date'] = date.today()
        record['review_by'] = None
        record['review_bin_headers'] = ''
        record['hold_days'] = 0
        record['custom_bin_applied'] = None

        # status fields
        record['allocation_worked'] = False
        record['allocation_fresh'] = True
        record['hold_status'] = False
        record['review_status'] = False
        record['allocation_status'] = True
        record['allocation_allocated'] = False
        record['executive_status'] = False
        record['custom_bin_applied_status'] = False

# Process cleaned records and calculate ageing bucket
class ProcessData:
    def calculate_ageing_bucket(self, service_date):
        """Calculate the ageing bucket based on the service date"""
        try:
            # Parse service date into datetime
            # service_date = pd.to_datetime(service_date_str, errors='raise')
            ageing_bucket_days = (date.today() - service_date.date()).days if service_date else None
            if ageing_bucket_days:
                if ageing_bucket_days <= 30:
                    return "0-30"
                elif ageing_bucket_days <= 60:
                    return "31-60"
                elif ageing_bucket_days <= 90:
                    return "61-90"
                elif ageing_bucket_days <= 180:
                    return "91-180"
                elif ageing_bucket_days <= 360:
                    return "181-360"
                else:
                    return "360 and above"
            else:
                return None
        except Exception as e:
            return e

    def process_records(self, df_filtered, mapping_dict):
        """Process the records in the filtered DataFrame"""
        records = []
        try:
            for _, row in df_filtered.iterrows():
                record = {key: row[val] for key, val in mapping_dict.items() if val in df_filtered.columns}
                service_date_str = record['service_date'] if len(record) > 0 and record['service_date'] else ''
                service_date = pd.to_datetime(service_date_str, errors='raise')
                if service_date:
                    ageing_bucket = self.calculate_ageing_bucket(service_date)
                    if ageing_bucket: record['ageing_bucket'] = ageing_bucket
                    records.append(record)
            return records
        except Exception as e:
            return e

mapping_csv_headers = [
    'account_number', 'action', 'ageing_bucket', 'allocated_date', 'allocated_to', 'assigned_by',
    'assigned_to', 'allocation_allocated', 'allocation_fresh', 'allocation_status', 'allocation_worked',
    'amount', 'amount2', 'amount3', 'amount4', 'appeal_limit', 'assign_certification', 'assigned_to',
    'assignment_code', 'auth_number', 'category', 'chart_number', 'check_number', 'claim_denial_code',
    'claim_denial_date', 'claim_denial_description', 'claim_frequency_type', 'claim_number', 'claim_priority',
    'cob', 'cob_primary', 'cob_secondary', 'cob_tertiary', 'contract_name', 'created_at', 'current_billed_financial_class',
    'current_billed_payer_name', 'current_billed_relationship', 'current_queue', 'session_user',
    'division', 'dx1', 'dx2', 'dx3', 'dx4', 'dx5', 'dx6', 'executive_bin', 'executive_status', 'facility',
    'facility_code', 'facility_type', 'group_number_current_billed_payer', 'group_number_primary_payer',
    'group_number_secondary_payer', 'group_number_tertiary_payer', 'hold', 'hold_status', 'id', 'input_source',
    'insurance_balance', 'last_claim_status_check_date', 'last_ev_check_date', 'last_ins_disc_check_date',
    'latest_action_date', 'latest_pay_amount', 'latest_pay_date', 'member_id_current_billed_payer', 'member_id_primary_payer',
    'member_id_secondary_payer', 'member_id_tertiary_payer', 'mrn', 'next_follow_up_before', 'organization_id',
    'patient_address', 'patient_balance', 'patient_birthday', 'patient_city', 'patient_first_name', 'patient_gender',
    'patient_id', 'patient_last_name', 'patient_phone', 'patient_state', 'patient_zip', 'payer_id_current_billed_payer',
    'payer_id_primary_payer', 'payer_id_secondary_payer', 'payer_id_tertiary_payer', 'primary_payer_financial_class',
    'primary_payer_name', 'procedure_code', 'procedure_code2', 'procedure_code3', 'procedure_code4', 'procedure_count',
    'procedure_count2', 'procedure_count3', 'procedure_count4', 'project_id', 'project_key', 'provider_location',
    'provider_name', 'provider_npi', 'queue_days', 'relationship_primary_payer', 'relationship_secondary_payer',
    'relationship_tertiary_payer', 'release_info_code', 'rendering_provider_id', 'review_by', 'review_status',
    'secondary_payer_financial_class', 'secondary_payer_name', 'service_date', 'signature', 'status', 'sub_category',
    'subscriber_address', 'subscriber_birthday', 'subscriber_city', 'subscriber_first_name', 'subscriber_gender',
    'subscriber_last_name', 'subscriber_phone', 'subscriber_relationship', 'subscriber_state', 'subscriber_zip',
    'taxonomy_code', 'tertiary_payer_financial_class', 'tertiary_payer_name', 'timely_filing_limit', 'tooth_code',
    'tooth_code2', 'tooth_code3', 'tooth_code4', 'total_charged', 'type_of_service', 'under_pay', 'van_trace_number',
    'visit_number', 'worked_date'
]

mapping_db_headers = [
    "input_source", "mrn", "patient_id", "account_number", "visit_number",
    "chart_number", "project_key", "facility", "facility_type",
    "patient_last_name", "patient_first_name", "patient_phone", "patient_address",
    "patient_city", "patient_state", "patient_zip", "patient_birthday",
    "patient_gender", "subscriber_last_name", "subscriber_first_name",
    "subscriber_relationship", "subscriber_phone", "subscriber_address",
    "subscriber_city", "subscriber_state", "subscriber_zip", "subscriber_birthday",
    "subscriber_gender", "current_billed_financial_class", "current_billed_payer_name",
    "member_id_current_billed_payer", "group_number_current_billed_payer",
    "current_billed_relationship", "cob", "payer_id_current_billed_payer",
    "timely_filing_limit", "appeal_limit", "primary_payer_financial_class",
    "primary_payer_name", "member_id_primary_payer", "group_number_primary_payer",
    "relationship_primary_payer", "cob_primary", "payer_id_primary_payer",
    "secondary_payer_financial_class", "secondary_payer_name",
    "member_id_secondary_payer", "group_number_secondary_payer",
    "relationship_secondary_payer", "cob_secondary", "payer_id_secondary_payer",
    "tertiary_payer_financial_class", "tertiary_payer_name",
    "member_id_tertiary_payer", "group_number_tertiary_payer",
    "relationship_tertiary_payer", "cob_tertiary", "payer_id_tertiary_payer",
    "auth_number", "claim_number", "facility_code", "claim_frequency_type",
    "signature", "assignment_code", "assign_certification", "release_info_code",
    "service_date", "van_trace_number", "rendering_provider_id", "taxonomy_code",
    "procedure_code", "amount", "procedure_count", "tooth_code", "procedure_code2",
    "amount2", "procedure_count2", "tooth_code2", "procedure_code3", "amount3",
    "procedure_count3", "tooth_code3", "procedure_code4", "amount4",
    "procedure_count4", "tooth_code4", "dx1", "dx2", "dx3", "dx4", "dx5", "dx6",
    "total_charged", "check_number", "insurance_balance", "patient_balance",
    "contract_name", "division", "type_of_service", "claim_denial_date",
    "claim_denial_code", "claim_denial_description", "latest_pay_date",
    "latest_pay_amount", "claim_priority", "provider_name", "provider_npi",
    "provider_location", "last_claim_status_check_date", "last_ev_check_date",
    "last_ins_disc_check_date", "under_pay"
]

auto_mapping_db_headers = [
    "current_queue", "queue_days", "latest_action_date", "next_follow_up_before",
    "category", "sub_category", "status", "action", "assigned_to",
    "project_id", "organization_id", "allocation_fresh", "allocation_allocated",
    "allocation_worked", "session_user", "allocated_date", "worked_date",
    "ageing_bucket", "allocation_status", "allocated_to", "hold_status",
    "hold", "review_status", "review_by", "executive_status", "executive_bin",
    "created_at"
]