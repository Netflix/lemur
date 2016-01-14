import requests
from suds.transport.http import HttpAuthenticated
from suds.transport import Reply
import io


class SslAuthenticatedTransport(HttpAuthenticated):
    def __init__(self, **kwargs):
        self.cert = kwargs.pop('cert', None)
        # super won't work because not using new style class
        HttpAuthenticated.__init__(self, **kwargs)

    def open(self, request):
        """
        Fetches the WSDL using cert.
        """
        self.addcredentials(request)
        resp = requests.get(request.url, data=request.message,
             headers=request.headers, cert=self.cert, verify=False)
        result = io.StringIO(resp.content.decode('utf-8'))
        return result

    def send(self, request):
        """
        Posts to service using cert.
        """
        self.addcredentials(request)
        resp = requests.post(request.url, data=request.message,
                             headers=request.headers, cert=self.cert, verify=False)
        result = Reply(resp.status_code, resp.headers, resp.content)
        return result
