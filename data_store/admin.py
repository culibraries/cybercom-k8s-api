from django.contrib import admin
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import Permission
# Register your models here.
from api import config
from .models import dataStore
from pymongo import MongoClient

def setpermissions(app_label,codename,name):
    try:
        ct = ContentType.objects.get_for_model(dataStore)
        #ct=ContentType.objects.get(app_label=app_label)
        Permission.objects.get_or_create(codename=codename, name=name, content_type=ct)
    except Exception as error:
        print("Unable to create {0} permission.".format(codename))
        print("An exception occurred:", type(error).__name__, "-", error)

#data Store Permissions
db = MongoClient(host=config.DATA_STORE_MONGO_URI)
for database in db.database_names():
    if not (database in config.DATA_STORE_EXCLUDE):
        for col in db[database].collection_names():
            if not (col in config.DATA_STORE_EXCLUDE):
                for method in [('post','ADD'),('put','UPDATE'),('delete','DELETE'),('safe','SAFE METHODS')]:
                    codename= "{0}_{1}_{2}".format(database,col,method[0])
                    name = "Data Store {0} {1} {2}".format(database,col,method[1])
                    setpermissions('data_store',codename,name)

#create admin permissions
setpermissions('data_store','datastore_admin',"Data Store Admin")
