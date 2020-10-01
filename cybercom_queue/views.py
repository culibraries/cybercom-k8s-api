# Create your views here.
from rest_framework.settings import api_settings
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework.permissions import IsAuthenticatedOrReadOnly, DjangoModelPermissionsOrAnonReadOnly, AllowAny, IsAdminUser
from rest_framework.views import APIView
from cybercom_queue.models import taskModel
from rest_framework_xml.renderers import XMLRenderer
from rest_framework_yaml.renderers import YAMLRenderer
from rest_framework_jsonp.renderers import JSONPRenderer
from rest_framework.renderers import JSONRenderer
from rest_framework.parsers import JSONParser, MultiPartParser, FormParser, FileUploadParser
from cybercom_queue.util import trim
from rest_framework.authtoken.models import Token
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.shortcuts import redirect

# Setup Task Permissions
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import Permission
from rest_framework.renderers import TemplateHTMLRenderer
# Local Imports
from .permission import cybercomTaskPermission
from .celery_queue import QueueTask
import os


class Queue(APIView):

    permission_classes = (IsAuthenticatedOrReadOnly,)

    def __init__(self, *args, **kwargs):
        self.q = QueueTask()
        self.task_list = None
        super(Queue, self).__init__(*args, **kwargs)

    @property
    def task(self):
        return self.q.list_tasks()['available_tasks']

    @property
    def queues(self):
        return self.q.list_tasks()["available_queues"]

    def get(self, request, format=None):
        if not self.task_list:
            self.task_list = []
            for task in self.task:
                # add task url to view
                self.task_list.append(
                    reverse('run-main', kwargs={'task_name': task}, request=request))

                # Need to wait until task queue is ready. Admin usr must Initialize permissions. I will
                # probably find a better place for this code. For now it lives here. Admin user has to
                # double check tasks and run view to set any new permissions. Only one time required or
                # when new task is added!
                if request.user.is_superuser:
                    ct = ContentType.objects.get_for_model(taskModel)
                    codename = task.replace('.', '_')
                    perm_name = "Can Run {0}".format(task)
                    Permission.objects.get_or_create(
                        codename=codename, name=perm_name, content_type=ct)
            if not self.task_list:
                self.task_list.append(
                    "ERROR: Celery Workflow Tasks are currently loading or Celery Worker is down. Please check back or contact System Administrator.")
        data = {
            'Tasks': self.task_list,
            'Task History': reverse('queue-user-tasks', request=request),
            'Task Queues': self.queues,
        }
        if request.user.is_superuser:
            data['Admin Tasks'] = {"Clear Memcache": reverse(
                'flush-memcache', request=request)}
        return Response(data)


class flushMemcache(APIView):
    permission_classes = (IsAdminUser,)

    def __init__(self, *args, **kwargs):
        self.q = QueueTask()

    def get(self, request, format=None):
        qtlists = self.q.reset_tasklist()
        return Response({
            'Memcache': 'Cleared',
            'Return': reverse('queue-main', request=request),
        })


class Run(APIView):
    permission_classes = (cybercomTaskPermission,)
    model = taskModel
    parser_classes = (JSONParser,)
    name = "Run Task"

    def __init__(self,  *args, **kwargs):
        self.q = QueueTask()
        self.tasks_queues = self.q.list_tasks()
        super(Run, self).__init__(*args, **kwargs)

    def get_username(self, request):

        username = "guest"
        if request.user.is_authenticated:
            username = request.user.username
        return username

    def get(self, request, task_name=None, format=None):

        docstring = trim(self.q.task_docstring(task_name))
        curl_url = reverse(
            'run-main', kwargs={'task_name': task_name}, request=request)
        username = self.get_username(request)
        if not username == "guest":
            token = Token.objects.get_or_create(user=self.request.user)
            auth_token = str(token[0])
        else:
            auth_token = "< authorized-token > "
        data = {'task_name': task_name, 'task_docstring': docstring,
                'queue': 'celery', 'auth_token': auth_token, 'task_url': curl_url}
        return Response(data)

    def post(self, request, task_name=None, format=None):

        if not task_name:
            task_name = request.data.get('function', None)
        if task_name not in self.tasks_queues['available_tasks']:
            raise Exception("%s Task is not available" % (task_name))
        queue = request.data.get('queue', 'celery')
        if queue not in self.tasks_queues['available_queues']:
            raise Exception("%s Queue is not available" % (queue))
        args = request.data.get('args', [])
        kwargs = request.data.get('kwargs', {})
        if type(kwargs) is not dict:
            return Response({'error': 'kwargs must be a JSON object'})
        tags = request.data.get('tags', [])
        result = self.q.run(task_name, args, kwargs, queue,
                            self.get_username(request), tags)
        result['result_url'] = reverse(
            'queue-task-result', kwargs={'task_id': result['task_id']}, request=request)
        return Response(result)


class UserResult(APIView):

    permission_classes = (IsAuthenticatedOrReadOnly,)
    model = taskModel
    parser_classes = (JSONParser,)

    def __init__(self, *args, **kwargs):
        self.q = QueueTask()  # q
        super(UserResult, self).__init__(*args, **kwargs)

    def get(self, request, task_id=None, format=None):
        if task_id:
            try:
                data = self.q.task(task_id)
            except Exception as inst:
                data = {'task_id': task_id,
                        'status': "PENDING", 'error': str(inst)}
            return Response(data)


class UserTasks(APIView):

    model = taskModel

    def __init__(self,  *args, **kwargs):
        self.q = QueueTask()
        super(UserTasks, self).__init__(*args, **kwargs)

    def get_username(self, request):
        username = "guest"
        if request.user.is_authenticated:
            username = request.user.username
        return username

    def get(self, request, format=None, **kwargs):
        result = {'count': 0, 'next': None, 'previous': None, 'results': []}
        page_parm = api_settings.user_settings.get(
            'PAGINATE_BY_PARAM', 'page_size')
        if page_parm in request.GET:
            limit = request.GET.get(page_parm, 10)
        else:
            limit = api_settings.user_settings.get('PAGINATE_BY', 10)
        # Set page to 1 or page GET
        page = request.GET.get('page', 1)
        try:
            page = int(page)
        except:
            page = 1
        task_name = request.GET.get('taskname', None)
        username = self.get_username(request)
        data = self.q.history(username, task_name=task_name,
                              page=page, limit=limit, request=request)
        return Response(data)
