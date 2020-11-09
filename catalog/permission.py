from rest_framework import permissions
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import Permission
from api import config

class CatalogPermission(permissions.BasePermission):
    """
    DataStore Detail View Permissions.
    SAFE_METHODS always TRUE
    UNSAFE need appropriate Permissions
    """
    def __init__(self,anonymous=config.CATALOG_ANONYMOUS,read_perm_required=config.SAFE_METHOD_PERM_REQUIRED):
        self.anonymous = anonymous
        self.read_perm_required = read_perm_required

    def has_permission(self, request, view):
        django_app = 'catalog'
        admin_perm = 'catalog.catalog_admin'
        database = view.kwargs['database'] 
        collection = view.kwargs['collection']
        perms=list(request.user.get_all_permissions())
        #print(perms)
        if request.method in permissions.SAFE_METHODS:
            code_perm= "{0}.{1}_{2}_{3}".format(django_app,database,collection,'safe')
            #print(code_perm)
            #print perms, admin_perm,code_perm
            if "{0}_{1}".format(database,collection) in self.read_perm_required:
                if code_perm in perms:
                    return True
                else:
                    return False
            if self.anonymous or admin_perm in perms or code_perm in perms:
                return True
            else:
                return False
        else:
            code_perm= "{0}.{1}_{2}_{3}".format(django_app,database,collection,request.method.lower())
            # print(code_perm)
            if request.user.is_superuser or admin_perm in perms or code_perm in perms:
                return True
            else:
                return False

class createCatalogPermission(permissions.BasePermission):
    """
    Create Database and Collections permissions.
    """

    def has_permission(self, request, view):
        
        if request.method in permissions.SAFE_METHODS:
            return True
        else:
            django_app = 'catalog'
            admin_perm = 'catalog.catalog_admin'
            #Control catalog names per api_config
            path=request.path.split('/')
            if len(path)-(path.index(django_app))==3:
                return False 
            perms=list(request.user.get_all_permissions())
            if request.user.is_superuser or admin_perm in perms: #or code_perm in perms:
                return True
            else:
                return False

