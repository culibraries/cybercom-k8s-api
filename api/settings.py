"""
Django settings for api project.

Generated by 'django-admin startproject' using Django 2.1.7.

For more information on this file, see
https://docs.djangoproject.com/en/2.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.1/ref/settings/
"""
from datetime import timedelta
from api import config
import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Cybercom config settings
APPLICATION_TITLE = config.APPLICATION_TITLE
API_VERSION = '2.0'

# EMAIL
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.colorado.edu'
#EMAIL_HOST = 'smtp.gmail.com'
#EMAIL_PORT = 587
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD')
EMAIL_USE_TLS = True

# ADMIN Error Notification by email
ADMINS = [('Admin', 'libnotify@colorado.edu')]


# Session cookies
# https://docs.djangoproject.com/en/2.2/ref/settings/#session-cookie-domain
# wild card '*.example.edu'
SESSION_COOKIE_DOMAIN = None
CSRF_COOKIE_DOMAIN = None

# If you want to mount API with nginx with location other than /
# Change to desired url - '/api/'
FORCE_SCRIPT_NAME = '/'


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.1/howto/deployment/checklist/

SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY',
                       'thisIsDevelopmentSecretKeyProductionUseENV')

# SECURITY WARNING: don't run with debug turned on in production!
# Default to False unless API_DEBUG is True
DEBUG = True if os.getenv('API_DEBUG') == 'True' else False

ALLOWED_HOSTS = ['test-libapps.colorado.edu',
                 'cubl-load-balancer-103317816.us-west-2.elb.amazonaws.com']

CORS_ORIGIN_WHITELIST = (
    'libapps.colorado.edu',
    'test-libapps.colorado.edu',
    'cubl-load-balancer-103317816.us-west-2.elb.amazonaws.com'
)

# Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': os.getenv('DJANGO_LOG_LEVEL', 'INFO'),
        },
    },
}

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework.authtoken',
    'rest_framework_simplejwt.token_blacklist',
    'data_store',
    'catalog',
    'cybercom_queue',
    'counter'
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'api.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': ['templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django_settings_export.settings_export',
            ],
        },
    },
]


SETTINGS_EXPORT_VARIABLE_NAME = 'my_settings'
SETTINGS_EXPORT = [
    'APPLICATION_TITLE',
    'API_VERSION',
]

WSGI_APPLICATION = 'api.wsgi.application'

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        # 'rest_framework.authentication.BasicAuthentication',
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGINATE_BY': 50,
    'PAGINATE_BY_PARAM': 'page_size',
    'MAX_PAGINATE_BY': 1000000
}

# Customize JWT
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': False,
    'BLACKLIST_AFTER_ROTATION': True,

    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,

    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_FIELD': 'username',
    'USER_ID_CLAIM': 'username',

    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',

    'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
    'SLIDING_TOKEN_LIFETIME': timedelta(minutes=5),
    'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(days=1),
}

# Database
# https://docs.djangoproject.com/en/2.1/ref/settings/#databases

# DATABASES = {
#    'default': {
#        'ENGINE': 'django.db.backends.sqlite3',
#        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
#    }
# }

# RDS database setup
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': os.getenv('DEFAULT_DB_NAME'),
        'HOST': os.getenv('DEFAULT_DB_HOST'),
        'USER': os.getenv('DEFAULT_DB_USER'),
        'PASSWORD': os.getenv('DEFAULT_DB_PASSWORD'),
    },
    'counter': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'counter',
        'HOST': os.getenv('DEFAULT_DB_HOST'),
        'USER': os.getenv('DEFAULT_DB_USER'),
        'PASSWORD': os.getenv('DEFAULT_DB_PASSWORD'),
    }
}

DATABASE_ROUTERS = ['counter.database_router.counterRouter']

# Password validation
# https://docs.djangoproject.com/en/2.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/2.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'US/Mountain'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.1/howto/static-files/


STATIC_URL = 'https://cubl-static.s3-us-west-2.amazonaws.com/djangorest/'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static"),
]

AUTHENTICATION_BACKENDS = [
    'django_saml2_pro_auth.auth.Backend'
]

SAML_ROUTE = 'sso/saml/'

SAML_REDIRECT = '/'

SAML_FAIL_REDIRECT = '/login_failed'

SAML_USERS_MAP = [{
    "MyProvider": {
        "email": dict(key="Email", index=0),
        "name": dict(key="Username", index=0)
    }

}]


SAML_PROVIDERS = [{
    "MyProvider": {
        "strict": True,
        "debug": False,
        "custom_base_path": "",
        "sp": {
            "entityId": "https://test-libapps.colorado.edu/api/api-saml/sso/saml/metadata",
            "assertionConsumerService": {
                "url": "https://test-libapps.colorado.edu/api/api-saml/sso/saml/?acs",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            },
            "singleLogoutService": {
                "url": "https://test-libapps.colorado.edu/api/api-saml/sso/saml/?sls",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            # For the cert/key you can place their content in
            # the x509cert and privateKey params
            # as single-line strings or place them in
            # certs/sp.key and certs/sp.crt or you can supply a
            # path via custom_base_path which should contain
            ## sp.crt and sp.key
            "x509cert": open(os.path.join(BASE_DIR, 'api/certs/sp-cert.pem'), 'r').read(),
            "privateKey": open(os.path.join(BASE_DIR, 'api/certs/sp-key.pem'), 'r').read()
        },
        "idp": {
            "entityId": "https://fedauth-test.colorado.edu/idp/shibboleth",
            "singleSignOnService": {
                "url": "https://fedauth-test.colorado.edu/idp/profile/SAML2/Redirect/SSO",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "singleLogoutService": {
                "url": "https://fedauth-test.colorado.edu/idp/profile/SAML2/Redirect/SLO",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "x509cert": open(os.path.join(BASE_DIR, 'api/certs/idp-cert.pem'), 'r').read(),
        },
        "organization": {
            "en-US": {
                "name": "University of Colorado - Boulder - Libraries",
                "displayname": "UC Boulder - Libraries",
                "url": "https://www.colorado.edu/libraries/"
            }
        },
        "contact_person": {
            "technical": {
                "given_name": "LIT UC - Boulder",
                "email_address": "libnotify@colorado.edu"
            }
        },
        "security": {
            "nameIdEncrypted": False,
            "authnRequestsSigned": True,
            "logoutRequestSigned": False,
            "logoutResponseSigned": False,
            "signMetadata": False,
            "wantMessagesSigned": False,
            "wantAssertionsSigned": True,
            "wantNameId": True,
            "wantNameIdEncrypted": False,
            "wantAssertionsEncrypted": True,
            "signatureAlgorithm": "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            "digestAlgorithm": "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        }

    }
}]
