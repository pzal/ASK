import secrets
from django.utils import timezone
from iksde_bank.celery import app as celery
from transfers.models import Transfer, TransferConfirmation, get_private_upload_path
from users.models import Account
from utils.logging import log, error, exception
from transfers.utils import get_transfer_confirmation_html_content
import pdfkit
from django.core.files import File
from django.db import transaction
from celery import Task


class LogErrorsTask(Task):
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        exception('Celery task exception!', exc_info=exc)
        super(LogErrorsTask, self).on_failure(exc, task_id, args, kwargs, einfo)


@celery.task(base=LogErrorsTask)
def settle_transfers_task():
    log("Running transfer settling…")

    def is_valid(transfer):
        if t.sender_account.balance - t.amount < 0:
            return False

        if not Account.objects.filter(
            account_number=t.recipient.account_number
        ).exists():
            return False

        return True

    for t in Transfer.objects.for_settling():
        with transaction.atomic():
            # TODO implement, assign recipient_user
            log("Transfer settling", {"pk": t.pk})
            if not is_valid(t):
                t.failed = True
            else:
                recipient_account = Account.objects.filter(
                    account_number=t.recipient.account_number
                ).first()
                t.recipient_account = recipient_account
                t.recipient_user = recipient_account.user
                t.sender_account.balance -= t.amount
                t.sender_account.save()
                t.recipient_account.balance += t.amount
                t.recipient_account.save()

            t.date_confirmed = timezone.now()
            t.pending = False
            t.frozen_account_number = t.recipient.account_number
            t.save()


@celery.task(base=LogErrorsTask)
def generate_confirmations_task():
    log("Running transfer confirmation generation…")

    for t in Transfer.objects.for_confirmation_generation():
        with transaction.atomic():
            log("Generating transfer confirmation…", {"pk": t.pk})
            transfer_confirmation = TransferConfirmation.objects.create(transfer=t)
            # path = get_private_upload_path(
            #     transfer_confirmation, f"confirmation_{t.pk}.pdf"
            # )
            html_pdf_content = get_transfer_confirmation_html_content(t)
            tmp_path = "/tmp/" + secrets.token_urlsafe()
            pdfkit.from_string(
                html_pdf_content, tmp_path,
            )
            with open(tmp_path, "rb") as f:
                transfer_confirmation.file.save(f"confirmation_{t.pk}.pdf", File(f))
