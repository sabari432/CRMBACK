from pydantic import BaseModel, Field
from django.core.exceptions import ValidationError

class FieldSchema(BaseModel):
    value: str
    unique: bool = False
    required: bool = False

def validate_mapping(data):
    """
    Validates the field mapping data based on the Pydantic model.
    This can be used for validating any nested or structured data.
    """
    for field_name, field_data in data.items():
        try:
            # Validate each field's data using the FieldSchema Pydantic model
            FieldSchema(**field_data)
        except Exception as e:
            # If validation fails, raise a Django ValidationError with specific field errors
            raise ValidationError(f"Invalid data for {field_name}: {str(e)}")
