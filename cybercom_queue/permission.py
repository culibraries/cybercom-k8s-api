from rest_framework import permissions
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import Permission

class cybercomTaskPermission(permissions.BasePermission):
    """
    Cybercom task permissions
    """

    def has_permission(self, request, view):
        perms=list(request.user.get_all_permissions()) 
        #for itm in perms:
        #    print itm
        if request.method in permissions.SAFE_METHODS:
            return True
        else:
            django_app = 'cybercom_queue'
            admin_perm = 'cybercom_queue.task_admin'
            task_name = view.kwargs['task_name']
            if not task_name:
                task_name = request.data.get('function', 'error')
            code_perm= "{0}.{1}".format(django_app,task_name.replace('.','_'))
            perms=list(request.user.get_all_permissions())
            if request.user.is_superuser or admin_perm in perms or code_perm in perms:
                return True
            else:
                return False 
