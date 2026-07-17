import re

from django.core.exceptions import ValidationError

MIN_JUSTIFICATION_LENGTH = 10
MAX_JUSTIFICATION_LENGTH = 1000


def normalize_justification(value):
    justification = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(justification) < MIN_JUSTIFICATION_LENGTH:
        raise ValidationError(
            "A business justification of at least "
            f"{MIN_JUSTIFICATION_LENGTH} characters is required."
        )
    if len(justification) > MAX_JUSTIFICATION_LENGTH:
        raise ValidationError(
            f"The business justification cannot exceed {MAX_JUSTIFICATION_LENGTH} characters."
        )
    return justification
