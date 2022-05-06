from django.db import models


class BaseModelManager(models.Manager):
    def __init__(self, *args, **kwargs):
        self.archived_too = kwargs.pop("archived_too", False)
        super(BaseModelManager, self).__init__(*args, **kwargs)

    def get_queryset(self):
        if self.archived_too:
            return super().get_queryset()

        return super().get_queryset().filter(is_archived=False)


class BaseModel(models.Model):
    date_created = models.DateTimeField(auto_now_add=True)
    date_changed = models.DateTimeField(auto_now=True)
    is_archived = models.BooleanField(default=False)

    objects = BaseModelManager()
    # all_objects = BaseModelManager(archived_too=True)

    class Meta:
        abstract = True

    def delete(self):
        self.is_archived = True
        self.save()
