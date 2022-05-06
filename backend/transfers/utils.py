from django.template.loader import render_to_string
from transfers.models import TransferConfirmation


def get_transfer_confirmation_html_content(transfer):
    return render_to_string(
        "transfers/templates/transfers/transfer_confirmation.html",
        {
            "transfer_date": transfer.date_confirmed,
            "sender": transfer.sender_account.account_number,
            "recipient": transfer.recipient.account_number,
            "amount": transfer.amount,
        }
        # _get_email_context(patient_notification),
    )
