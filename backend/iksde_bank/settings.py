import os
import sys
from celery.schedules import crontab
import sentry_sdk
from corsheaders.defaults import default_headers
from sentry_sdk.integrations.django import DjangoIntegration

RELEASE = "0.5.0"

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SECRET_KEY = os.environ["SECRET_KEY"]

DEBUG = os.environ["ENVIRONMENT"] != "production"
TESTING = sys.argv[1:2] == ["test"]

AUTH_USER_MODEL = "users.User"

# ALLOWED_HOSTS = os.environ["ALLOWED_HOSTS"].split(",")
ALLOWED_HOSTS = ["localhost"]
# ALLOWED_HOSTS = ["*"]
SESSION_COOKIE_DOMAIN = ".localhost"
CORS_ALLOW_CREDENTIALS = True
CSRF_USE_SESSIONS = True
# CORS_ORIGIN_WHITELIST = [os.environ["LANDING_ENDPOINT"], os.environ["APP_ENDPOINT"]]
CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOW_HEADERS = list(default_headers) + [
    "sentry-trace",
]

# Application definition

THIRD_PARTY_APPS = [
    "corsheaders",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django_extensions",
    "django_filters",
    "django_inlinecss",
    "rest_framework",
    "rest_framework.authtoken",
    # "rest_framework_filters",
    "social_django",
    "storages",
]

LOCAL_APPS = [
    "development",
    "transfers",
    "users",
    "utils",
]

INSTALLED_APPS = THIRD_PARTY_APPS + LOCAL_APPS

if os.environ["SERVER_SENTRY_DSN"] and not TESTING:
    sentry_sdk.init(
        dsn=os.environ["SERVER_SENTRY_DSN"],
        integrations=[DjangoIntegration()],
        release=RELEASE,
        environment=os.environ["ENVIRONMENT"],
        in_app_include=LOCAL_APPS,
        # Set traces_sample_rate to 1.0 to capture 100%
        # of transactions for performance monitoring.
        # We recommend adjusting this value in production,
        traces_sample_rate=1.0,
        # If you wish to associate users to errors (assuming you are using
        # django.contrib.auth) you may enable sending PII data.
        send_default_pii=True,
    )
else:
    print("Skipping sentry initialization.")

EMAIL_HOST = "smtp.sendgrid.net"
EMAIL_HOST_USER = "apikey"
EMAIL_HOST_PASSWORD = os.environ["SENDGRID_API_KEY"] if not TESTING else None
EMAIL_PORT = 587
EMAIL_USE_TLS = True

DEFAULT_FROM_EMAIL = os.environ["DEFAULT_FROM_EMAIL"]

SENGRID_API_KEY = os.environ["SENDGRID_API_KEY"] if not TESTING else None

CELERY_BROKER_URL = f'redis://{os.environ["REDIS_HOST"]}:{os.environ["REDIS_PORT"]}'
CELERY_IMPORTS = []
CELERY_BEAT_SCHEDULE = {
    "debug_task_every_minute": {"task": "development.tasks.debug_task", "schedule": 60},
    "debug_task_every_friday": {
        "task": "development.tasks.debug_task",
        "schedule": crontab(hour=16, minute=0, day_of_week="friday"),
    },
    "transfer_settling_task": {
        "task": "transfers.tasks.settle_transfers_task",
        "schedule": 30,
    },
    "generate_confirmations_task": {
        "task": "transfers.tasks.generate_confirmations_task",
        "schedule": 30,
    },
}

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "development.middlewares.SleepMiddleware",
]

ROOT_URLCONF = "iksde_bank.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [
            BASE_DIR,  # allows for "absolute" path (from project root) to template
        ],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "iksde_bank.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ["POSTGRES_DB_NAME"],
        "USER": os.environ["POSTGRES_DB_USER"],
        "PASSWORD": os.environ["POSTGRES_DB_PASSWORD"],
        "HOST": os.environ["POSTGRES_HOST"],
        "PORT": os.environ["POSTGRES_PORT"],
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

REST_FRAMEWORK = {
    "DEFAULT_FILTER_BACKENDS": ("django_filters.rest_framework.DjangoFilterBackend",),
    # "DEFAULT_FILTER_BACKENDS": ("rest_framework_filters.backends.RestFrameworkFilterBackend",),
    "DEFAULT_AUTHENTICATION_CLASSES": (
        # "rest_framework.authentication.TokenAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "EXCEPTION_HANDLER": "utils.exceptions.custom_exception_handler",
}

ELK_STACK_ON = os.environ["ELK_STACK_ON"] == "true"

# Social auth
SOCIAL_AUTH_JSONFIELD_ENABLED = True
AUTHENTICATION_BACKENDS = (
    "social_core.backends.keycloak.KeycloakOAuth2",
    "django.contrib.auth.backends.ModelBackend",
)
SOCIAL_AUTH_KEYCLOAK_KEY = "django-oidc"
SOCIAL_AUTH_KEYCLOAK_SECRET = "jD7qAc3IOLecQNxyrrM5PFets3D02bJK"
SOCIAL_AUTH_KEYCLOAK_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgKfPbqFx5BYl6sxgsmiJZ4w5hIkAGOBld7UvaW+0vH/mAT+ngU8WI9OryN2NvEXcSNwAsbkd4bd9fOkVGaHt1KXGZUsyajy5A4tZrq9vVxY0aSGAKYHstzfiuJiznIP1TlInv3kngclbVUHFZ5CXUMpkZIEsbBdkmGhUTR3ZdTBWjq56fCSbq6B7md91R7I2VSm4hhJ2t+77WS4y+dwenzV0zpLU+Sygl2br0SvBV0Yc15SYHCt5JRXdxOQ4rZbbhhGruNsoWg4s2dqDLCDooyfu06fIYIsv1mNLvnJKpU2tEfxLzrR4lltNyil581tRmhXbss9Kt7nLde+5mxxbowIDAQAB"
SOCIAL_AUTH_KEYCLOAK_AUTHORIZATION_URL = (
    "http://localhost:8080/realms/myrealm/protocol/openid-connect/auth"
)
SOCIAL_AUTH_KEYCLOAK_ACCESS_TOKEN_URL = (
    "http://keycloak:8080/realms/myrealm/protocol/openid-connect/token"
)
SOCIAL_AUTH_ALLOWED_REDIRECT_HOSTS = ["localhost:8000", "localhost:3000"]


def custom_create_user(*args, **kwargs):
    from social_core.pipeline.user import create_user
    from users.models import Account
    from time import time
    from faker import Faker

    data = create_user(*args, **kwargs)

    if not data["is_new"]:
        print("here not new")
        return data

    user = data["user"]

    # Setup
    fake = Faker()
    Faker.seed(time())
    Account.objects.create(user=user, balance=1000000, account_number=fake.iban())

    return data


SOCIAL_AUTH_PIPELINE = (
    # Get the information we can about the user and return it in a simple
    # format to create the user instance later. In some cases the details are
    # already part of the auth response from the provider, but sometimes this
    # could hit a provider API.
    "social_core.pipeline.social_auth.social_details",
    # Get the social uid from whichever service we're authing thru. The uid is
    # the unique identifier of the given user in the provider.
    "social_core.pipeline.social_auth.social_uid",
    # Verifies that the current auth process is valid within the current
    # project, this is where emails and domains whitelists are applied (if
    # defined).
    "social_core.pipeline.social_auth.auth_allowed",
    # Checks if the current social-account is already associated in the site.
    "social_core.pipeline.social_auth.social_user",
    # Make up a username for this person, appends a random string at the end if
    # there's any collision.
    "social_core.pipeline.user.get_username",
    # Send a validation email to the user to verify its email address.
    # Disabled by default.
    # 'social_core.pipeline.mail.mail_validation',
    # Associates the current social details with another user account with
    # a similar email address. Disabled by default.
    # 'social_core.pipeline.social_auth.associate_by_email',
    # Create a user account if we haven't found one yet.
    "iksde_bank.settings.custom_create_user",
    # Create the record that associates the social account with the user.
    "social_core.pipeline.social_auth.associate_user",
    # Populate the extra_data field in the social record with the values
    # specified by settings (and the default ones like access_token, etc).
    "social_core.pipeline.social_auth.load_extra_data",
    # Update the user record with any changed info from the auth service.
    "social_core.pipeline.user.user_details",
)


LOGIN_REDIRECT_URL = "/development/whoami"
LOGOUT_REDIRECT_URL = "/development/whoami"


LOGGING = {
    "version": 1,
    "handlers": {
        "logstash": {
            "level": "DEBUG",
            "class": "logstash.LogstashHandler",
            "host": "logstash",
            "port": 5000,
            "version": 1,  # Version of logstash event schema. Default value: 0 (for backward compatibility of the library)
            "message_type": "logstash",  # 'type' field in logstash message. Default value: 'logstash'.
            "fqdn": False,  # Fully qualified domain name. Default value: false.
            #   'tags': ['tag1', 'tag2'], # list of tags. Default: None.
        }
        if ELK_STACK_ON
        else {
            "level": "DEBUG",
            "class": "logging.StreamHandler",
        },
    },
    "loggers": {
        "django.request": {
            "handlers": ["logstash"],
            "level": "DEBUG",
            "propagate": True,
        },
        "logstash-logger": {
            "handlers": ["logstash"],
            "level": "INFO",
            "propagate": True,
        },
    },
}

if TESTING:
    print("Emptying LOGGING setting because we're testing.")
    LOGGING = {}

# Internationalization
# https://docs.djangoproject.com/en/3.0/topics/i18n/
LANGUAGE_CODE = "pl"
TIME_ZONE = "Europe/Warsaw"
USE_I18N = True
USE_L10N = True
USE_TZ = True

MEDIA_URL = "/uploads/"
MEDIA_ROOT = os.path.join(BASE_DIR, "uploads")
STATIC_URL = "/static/"
STATIC_ROOT = os.path.join(BASE_DIR, "static")

DEBUG_MAIL_RECIPIENT = os.environ["DEBUG_MAIL_RECIPIENT"]

SLEEP_TIME = 0.5
if TESTING:
    SLEEP_TIME = 0
