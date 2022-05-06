from storages.backends.s3boto3 import S3Boto3Storage


class PrivateFileStorage(S3Boto3Storage):
    location = None
    default_acl = "private"
    file_overwrite = False
    custom_domain = False
