from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

# Define the headers as a list of field names
HEADER_FIELD_NAMES = [
    "source_of_status",
    "clearing_house_comment",
    "insurance_name",
    "clearing_house_name",
    "insurance_phone",
    "rep_name",
    "website_name",
    "processed_date",
    "paid_date",
    "allowed_amount",
    "paid_amount",
    "deductible_amount",
    "coinsurance",
    "copayment",
    "mode_of_payment",
    "check_number",
    "transaction_id",
    "is_single_bulk_payment",
    "payment_amount",
    "check_mailing_address",
    "is_check_paid_on_correct_address",
    "is_check_cashed",
    "is_payment_cleared",
    "encashment_date",
    "is_paid_date_crossed_45_days",
    "tat_for_encashment_of_payment",
    "rep_agrees_to_run_check_tracer",
    "tat_for_check_tracer",
    "reason_for_not_sending_request_for_check_tracer",
    "rep_agrees_to_reissue_new_check",
    "rep_agrees_to_reissue_new_payment",
    "tat_to_receive_new_payment",
    "reason_for_not_reissuing_new_payment",
    "w9_form_requested",
    "fax_provided",
    "fax",
    "eob_available_on_website",
    "mailing_address",
    "source_to_get_eob",
    "website_name_link",
    "additional_comment",
    "claim_number",
    "call_reference"
]

@api_view(['GET'])
def get_workflow_header_names(request):
    try:
        return Response(HEADER_FIELD_NAMES, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
