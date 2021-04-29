__author__ = 'mstacy'
from rest_framework import permissions
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework import serializers, generics
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
# from .models import AuthtokenToken, AuthUser
from django.contrib.auth.decorators import login_required
from hashlib import md5
from django.contrib.auth.models import Group
# logout request
import requests
import os
import json
from django.contrib.auth import logout

from rest_framework.parsers import FileUploadParser, MultiPartParser
from rest_framework.renderers import JSONRenderer

default_user_group = os.getenv('DEFAULT_USER_GROUP','cubl-default-login')
# from rest_framework import viewsets
# from rest_framework.permissions import AllowAny
# from .permissions import IsStaffOrTargetUser

# Login required mixin
""" class LoginRequiredMixin(object):
    @classmethod
    def as_view(cls, **initkwargs):
        view = super(LoginRequiredMixin, cls).as_view(**initkwargs)
        return login_required(view) """


class APIRoot(APIView):
    permission_classes = (IsAuthenticatedOrReadOnly,)

    def get(self, request, format=None):
        print('debug')
        try:
            print(request.session['samlUserdata'])
        except:
            print('error')

        return Response({
            'Queue': {'Tasks': reverse('queue-main', request=request),
                      'Tasks History': reverse('queue-user-tasks', request=request)},
            'Catalog': {'Data Source': reverse('catalog-list', request=request),
                        'Ark Server': reverse('ark-list', request=request)},
            'Data Store': {'Mongo': reverse('data-list', request=request),
                           'Counter': [reverse('platform-list', request=request),
                                       reverse('publication-list',
                                               request=request),
                                       reverse('filter-list', request=request),
                                       reverse('title-list', request=request)],
                           'S3': [reverse('buckets-list', request=request),
                                  reverse('objects-list', request=request),
                                  reverse('object-upload', request=request)]},
            'User Profile': {'User': reverse('user-list', request=request)},

        })


class UserSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=100)
    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=50)
    last_name = serializers.CharField(max_length=50)


class samlLogout(APIView):

    def get(self, request, id=None, format=None):
        """
        Logout of django and SAML post for CU Boulder Idp logout
        """
        requests.post(
            "https://fedauth-test.colorado.edu/idp/profile/Logout/", data="_eventId=propagate")
        requests.post(
            "https://fedauth-test.colorado.edu/idp/profile/SAML2/Redirect/SLO")
        logout(request)


class UserProfile(APIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = UserSerializer
    fields = ('username', 'first_name', 'last_name', 'email')
    model = User

    def get(self, request, id=None, format=None):
        data = User.objects.get(pk=self.request.user.id)
        serializer = self.serializer_class(data, context={'request': request})
        tok = Token.objects.get_or_create(user=self.request.user)
        user_groups = []
        for g in request.user.groups.all():
            user_groups.append(g.name)
        if default_user_group not in user_groups:
            my_group = Group.objects.get(name=default_user_group) 
            my_group.user_set.add(request.user)
            user_groups.append(default_user_group)
        # Additional groups from grouper
        if 'samlUserdata' in request.session:
            samlUserdata = request.session['samlUserdata']
            print(samlUserdata)
            if "urn:oid:1.3.6.1.4.1.632.11.2.200" in samlUserdata:
                grouper = samlUserdata['urn:oid:1.3.6.1.4.1.632.11.2.200']
                user_groups = list(set(user_groups+grouper))
        user_groups.sort()
        rdata = serializer.data
        rdata['name'] = data.get_full_name()
        rdata['gravator_url'] = "{0}://www.gravatar.com/avatar/{1}".format(
            request.scheme, md5(rdata['email'].lower().strip(' \t\n\r').encode('utf-8')).hexdigest())
        rdata['groups'] = user_groups
        authscheme = {'auth-token': str(tok[0]),
                      #   'jwt-auth': {'obtain-token': reverse('token_obtain_pair', request=request),
                      #                'refresh-token': reverse('token_refresh', request=request),
                      #                'verify-token': reverse('token_verify', request=request)},
                      }
        rdata['authentication'] = authscheme
        return Response(rdata)

    def post(self, request, format=None):
        user = User.objects.get(pk=self.request.user.id)
        password = request.data.get('password', None)
        if password:
            user.set_password(password)
            user.save()
            data = {"password": "Successfully Updated"}
            return Response(data)
        auth_tok = request.data.get('auth-token', None)
        if str(auth_tok).lower() == "update":
            tok = Token.objects.get(user=user)
            tok.delete()
            tok = Token.objects.get_or_create(user=self.request.user)
            data = {"auth-token": str(tok[0])}
            return Response(data)
        else:
            user.first_name = request.data.get('first_name', user.first_name)
            user.last_name = request.data.get('last_name', user.last_name)
            user.email = request.data.get('email', user.email)
            serializer = self.serializer_class(
                user, context={'request': request})
            data = serializer.data
            user.save()
            tok = Token.objects.get_or_create(user=self.request.user)
            data['name'] = user.get_full_name()
            data['gravator_url'] = "{0}://www.gravatar.com/avatar/{1}".format(
                request.scheme, md5(data['email'].strip(' \t\n\r').encode('utf-8')).hexdigest())
            data['auth-token'] = str(tok[0])
            return Response(data)


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    """

    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions are only allowed to the owner of the snippet.
        return obj.owner == request.user


class fileDataUploadView(APIView):
    permission_classes = (IsAuthenticated,)
    #parser_classes = (MultiPartParser, FormParser,FileUploadParser,)
    parser_classes = (MultiPartParser, FileUploadParser,)
    renderer_classes = (JSONRenderer,)

    def post(self, request, uploadDirectory="/data/file_upload", format=None):
        # check if uploadDirectory exists
        if not os.path.isdir(uploadDirectory):
            os.makedirs(uploadDirectory)
        results = []
        # upload files submitted

        print(request.data)
        file_obj = request.data['file']
        print(dir(file_obj))
        filename = file_obj.name
        local_file = "{0}/{1}".format(uploadDirectory, filename)
        self.handle_file_upload(request.data['file'], local_file)
        result = {}
        if request.data.get("callback", None):
            req = self.callback_task(request, local_file)
            try:
                result['callback'] = {
                    "status": req.status_code, "response": req.json()}
            except:
                result['callback'] = {
                    "status": req.status_code, "response": req.text}
        results.append(result)
        # # print(request.data['file'])
        # print(dir(request.data['file']))
        # # print(request.data['filename'].name)
        # for key, value in request.data['file'][0].iteritems():
        #     result = {}
        #     filename = value.name
        #     local_file = "{0}/{1}".format(uploadDirectory, filename)
        #     self.handle_file_upload(request.FILES[key], local_file)
        #     result[key] = local_file

        return Response(results)

    def handle_file_upload(self, f, filename):
        if f.multiple_chunks():
            with open(filename, 'wb+') as temp_file:
                for chunk in f.chunks():
                    temp_file.write(chunk)
        else:
            with open(filename, 'wb+') as temp_file:
                temp_file.write(f.read())

    def callback_task(self, request, local_file):
        # Get Token for task submission
        tok = Token.objects.get_or_create(user=request.user)
        headers = {'Authorization': 'Token {0}'.format(
            str(tok[0])), 'Content-Type': 'application/json'}
        queue = request.data.get("queue", "celery")
        # tags is a comma separated string; Converted to list
        tags = request.data.get("tags", '')
        tags = tags.split(',')
        taskname = request.data.get("callback")
        data = request.data
        del data['file']
        payload = {"function": taskname, "queue": queue, "args": [
            local_file, data], "kwargs": {}, "tags": tags}
        components = request.build_absolute_uri('/api/')  # .split('/')
        #hostname = os.environ.get("api_hostname", components[2])
        url = "{0}queue/run/{1}.json".format(components, taskname)
        return requests.post(url, data=json.dumps(payload), headers=headers)
