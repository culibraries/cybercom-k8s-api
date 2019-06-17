from django.contrib import admin
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import Permission
from django.db import connection
# Register your models here.
from api import config
from .models import catalogModel
from pymongo import MongoClient

def setpermissions(app_label,codename,name):
    ct = ContentType.objects.get_for_model(catalogModel)
    #ct=ContentType.objects.get(app_label=app_label)
    Permission.objects.get_or_create(codename=codename, name=name, content_type=ct)

# Set to allow migrations when django_content_type table is not present
if 'django_content_type' in connection.introspection.table_names():
    #Catalog Permissions
    db = MongoClient(host=config.CATALOG_URI)
    for catalog in config.CATALOG_INCLUDE:
        for col in db[catalog].collection_names():
            if not (col in config.CATALOG_EXCLUDE):
                for method in [('post','ADD'),('put','UPDATE'),('delete','DELETE'),('safe','SAFE METHODS')]:
                    codename= "{0}_{1}_{2}".format(catalog,col,method[0])
                    name = "{0} {1} {2}".format(catalog,col,method[1])
                    setpermissions('catalog',codename,name)

    #Create Admin Permissions
    setpermissions('catalog','catalog_admin','Catalog Admin')
