__author__ = 'mstacy'
from rest_framework.renderers import BrowsableAPIRenderer, JSONRenderer  # , #JSONPRenderer
from api.encoder import JSONEncoder


class DataBrowsableAPIRenderer(BrowsableAPIRenderer):
    # template = 'rest_framework/queue_run_api.html'
    def get_context(self, data, accepted_media_type, renderer_context):
        context = super(DataBrowsableAPIRenderer, self).get_context(
            data, accepted_media_type, renderer_context)
        # if context['request'].method.upper() == 'GET':
        #    context['content']=data
        temp = []
        i = 0
        crumbs = ['Api Root', 'Database', 'Collection', 'Data', 'Data Detail']
        for k, v in context['breadcrumblist']:
            temp.append((crumbs[i], v))
            i = i + 1
        context['breadcrumblist'] = temp

        return context


class mongoJSONRenderer(JSONRenderer):
    #media_type = 'application/json; indent=4'
    encoder_class = JSONEncoder


class mongoJSONPRenderer(mongoJSONRenderer):
    """
    Renderer which serializes to json,
    wrapping the json output in a callback function.
    """

    media_type = 'application/javascript'
    format = 'jsonp'
    callback_parameter = 'callback'
    default_callback = 'callback'
    charset = 'utf-8'

    def get_callback(self, renderer_context):
        """
        Determine the name of the callback to wrap around the json output.
        """
        request = renderer_context.get('request', None)
        params = request and request.query_params or {}
        return params.get(self.callback_parameter, self.default_callback)

    def render(self, data, accepted_media_type=None, renderer_context=None):
        """
        Renders into jsonp, wrapping the json output in a callback function.

        Clients may set the callback function name using a query parameter
        on the URL, for example: ?callback=exampleCallbackName
        """
        renderer_context = renderer_context or {}
        callback = self.get_callback(renderer_context)
        json = super(mongoJSONPRenderer, self).render(data, accepted_media_type,
                                                      renderer_context)
        return callback.encode(self.charset) + b'(' + json + b');'


# class mongoJSONPRenderer(JSONPRenderer):

 #   encoder_class = JSONPRenderer
