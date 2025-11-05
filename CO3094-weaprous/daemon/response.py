#
# Copyright (C) 2025 pdnguyen of HCMC University of Technology VNU-HCM.
# All rights reserved.
# This file is part of the CO3093/CO3094 course.
#
# WeApRous release
#
# The authors hereby grant to Licensee personal permission to use
# and modify the Licensed Source Code for the sole purpose of studying
# while attending the course
#

"""
daemon.response
~~~~~~~~~~~~~~~~~

This module provides a :class: `Response <Response>` object to manage and persist 
response settings (cookies, auth, proxies), and to construct HTTP responses
based on incoming requests. 

The current version supports MIME type detection, content loading and header formatting
"""
from daemon.request import * 
import datetime
import os
import mimetypes
from .dictionary import CaseInsensitiveDict
import urllib.parse
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) + "/../"
HTTP_REASON = {
    200: "OK",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error",
}
VALID_USERNAME = "admin"
VALID_PASSWORD = "password"
AUTH_COOKIE_NAME = "auth"
AUTH_COOKIE_VALUE = "true"
class Response():   
    """The :class:`Response <Response>` object, which contains a
    server's response to an HTTP request.

    Instances are generated from a :class:`Request <Request>` object, and
    should not be instantiated manually; doing so may produce undesirable
    effects.

    :class:`Response <Response>` object encapsulates headers, content, 
    status code, cookies, and metadata related to the request-response cycle.
    It is used to construct and serve HTTP responses in a custom web server.

    :attrs status_code (int): HTTP status code (e.g., 200, 404).
    :attrs headers (dict): dictionary of response headers.
    :attrs url (str): url of the response.
    :attrsencoding (str): encoding used for decoding response content.
    :attrs history (list): list of previous Response objects (for redirects).
    :attrs reason (str): textual reason for the status code (e.g., "OK", "Not Found").
    :attrs cookies (CaseInsensitiveDict): response cookies.
    :attrs elapsed (datetime.timedelta): time taken to complete the request.
    :attrs request (PreparedRequest): the original request object.

    Usage::

      >>> import Response
      >>> resp = Response()
      >>> resp.build_response(req)
      >>> resp
      <Response>
    """

    __attrs__ = [
        "_content",
        "_header",
        "status_code",
        "method",
        "headers",
        "url",
        "history",
        "encoding",
        "reason",
        "cookies",
        "elapsed",
        "request",
        "body",
        "reason",
    ]


    def __init__(self, request=None):
        """
        Initializes a new :class:`Response <Response>` object.

        : params request : The originating request object.
        """

        self._content = False
        self._content_consumed = False
        self._next = None

        #: Integer Code of responded HTTP Status, e.g. 404 or 200.
        self.status_code = None

        #: Case-insensitive Dictionary of Response Headers.
        #: For example, ``headers['content-type']`` will return the
        #: value of a ``'Content-Type'`` response header.
        self.headers = {}

        #: URL location of Response.
        self.url = None

        #: Encoding to decode with when accessing response text.
        self.encoding = None

        #: A list of :class:`Response <Response>` objects from
        #: the history of the Request.
        self.history = []

        #: Textual reason of responded HTTP Status, e.g. "Not Found" or "OK".
        self.reason = None

        #: A of Cookies the response headers.
        self.cookies = CaseInsensitiveDict()

        #: The amount of time elapsed between sending the request
        self.elapsed = datetime.timedelta(0)

        #: The :class:`PreparedRequest <PreparedRequest>` object to which this
        #: is a response.
        self.request = None

    def parse_post_body(self, body): 
        """
        Parse URL-encoded POST body into dictionary.
        
        :param body: Raw POST body string
        :return: Dictionary of parsed key-value pairs
        
        Example:
            body = "username=admin&password=12345"
            returns {'username': 'admin', 'password': '12345'}
        """
        data = {}
        if not body or body == "":
            return data

        for param in body.split('&'):
            if '=' in param: 
                key, value = param.split('=',1)
                key = urllib.parse.unquote_plus(key) # use for decode URL-encode string which derived from POST body HTML
                value = urllib.parse.unquote_plus(value)
                data[key] = value
                
        print(f"[Response] Parsed POST data: {data}")
        return data
    
    def is_authenticated(self,request): # check if request has valid authentication cookie
        """
        Check if request has valid authentication cookie.
        
        :param request: Request object
        :return: Boolean indicating authentication status
        """
        if not hasattr(request,'cookies') or request.cookies is None: 
            print("[Response] Authentication check: No cookies found")
            return False
        
        auth_value = request.cookies.get(AUTH_COOKIE_NAME.lower(), '')
        is_valid_cookies = auth_value == AUTH_COOKIE_VALUE
        print(f"[Response] Authentication check: auth={auth_value} - valid state={is_valid_cookies}")
        return is_valid_cookies
    
    def validate_credentials(self, username, password): 
        """
        Validate login credentials against stored values.
        
        :param username: Username string
        :param password: Password string
        :return: Boolean indicating if credentials are valid
        """
        is_valid_credent = (username == VALID_USERNAME and password == VALID_PASSWORD)
        print(f"[Response] Credential validation: username={username}, valid={is_valid_credent}")
        return is_valid_credent
    
    def build_login_response(self,request): 
        """
        Build response for POST /login request with authentication.
        
        :param request: Request object containing login credentials
        :return: Complete HTTP response bytes
        """
        print(f"[Response] Please wait, logging in...")
        
        # Parse credentials from POST body
        info = self.parse_post_body(request.body)
        username = info.get('username','')
        password = info.get('password','')

        if self.validate_credentials(username,password): 
            # Successful login
            print(f"[Response] Login successfully - setting auth cookie")
            filepath = os.path.join(BASE_DIR+ "www/", "index.html")
            
            try:
                with open(filepath,'rb') as f: 
                    content =f.read()

                self.status_code = 200
                self._content = content
                self.headers['Content-Type'] = 'text/html'
                self.headers['Content-Length'] = str(len(self._content))
                self.headers['Set-Cookie'] = f"{AUTH_COOKIE_NAME}={AUTH_COOKIE_VALUE}; Path=/; HttpOnly"
                self.headers['Cache-Control'] = 'no-cache'

            except FileNotFoundError:
                print("[Response] Error: index.html not found")
                self.status_code = 500
                self._content = b"Internal Server Error"
                self.headers['Content-Type'] = 'text/plain'
                self.headers['Content-Length'] = str(len(self._content))
        else:
            # login fail
            print(f"[Response] Login failed: Invalid credentials")
            self.status_code = 401
            filepath = os.path.join(BASE_DIR+ "www/errors/" , "401.html")

            try:
                with open(filepath,'rb') as f: 
                    content =f.read()
                self._content = content
            except FileNotFoundError:
                self._content = b"401 Unauthorized"

            self.headers['Content-Type'] = 'text/html'
            self.headers['Content-Length'] = str(len(self._content))
            self.headers['Cache-Control'] = 'no-cache'

        self.reason = HTTP_REASON.get(self.status_code, "Unknown")
        self._header = self.build_response_header(request)
        return self._header + self._content

    def build_unauthorized_response(self): 
        """
        Build 401 Unauthorized response.
        
        :return: Complete HTTP response bytes
        """
        print("[Response] Building 401 Unauthorized response")
        self.status_code = 401 
        filepath = os.path.join(BASE_DIR+ "www/errors/" , "401.html")

        try:
            with open(filepath,'rb') as f: 
                content =f.read()
            self._content = content
        except FileNotFoundError:
            # Fallback content if 401.html doesn't exist
            self._content = b"""<!DOCTYPE html>
<html>
<head><title>401 Unauthorized</title></head>
<body>
<h1>401 Unauthorized</h1>
<p>Please login to access this page.</p>
<a href="/login">Go to login</a>
</body>
</html>"""

        self.headers['Content-Type'] = 'text/html'
        self.headers['Content-Length'] = str(len(self._content))
        self.headers['Cache-Control'] = 'no-cache'
        self.reason = HTTP_REASON.get(self.status_code, "Unauthorized")

        # Build header
        status_line = f"HTTP/1.1 {self.status_code} {self.reason}"
        fmt_header = status_line + "\r\n"
        for key, value in self.headers.items():
            fmt_header += f"{key}: {value}\r\n"
        fmt_header += "\r\n"

        return str(fmt_header).encode('utf-8') + self._content

    def get_mime_type(self, path):
        """
        Determines the MIME type of a file based on its path.

        "params path (str): Path to the file.

        :rtype str: MIME type string (e.g., 'text/html', 'image/png').
        """

        try:
            mime_type, _ = mimetypes.guess_type(path)
        except Exception:
            return 'application/octet-stream'
        return mime_type or 'application/octet-stream'

    def prepare_content_type(self, mime_type='text/html'):
        """
        Prepares the Content-Type header and determines the base directory
        for serving the file based on its MIME type.

        :params mime_type (str): MIME type of the requested resource.

        :rtype str: Base directory path for locating the resource.

        :raises ValueError: If the MIME type is unsupported.
        """
        
        base_dir = ""

        # Processing mime_type based on main_type and sub_type
        main_type, sub_type = mime_type.split('/', 1)
        print(f"[Response] processing MIME main_type={main_type} sub_type={sub_type}")
        if main_type == 'text':
            self.headers['Content-Type']=f"text/{sub_type}"
            if sub_type in ['plain','css','csv','xml']:
                base_dir = BASE_DIR+"static/"
            elif sub_type == 'html':
                base_dir = BASE_DIR+"www/"
        elif main_type == 'image':
            if sub_type == 'png':
                base_dir = BASE_DIR+"static/"
            elif sub_type == 'x-icon':
                base_dir = BASE_DIR+"static/images"
            self.headers['Content-Type']=f"image/{sub_type}"
        elif main_type == 'application':
            base_dir = BASE_DIR+"apps/"
            self.headers['Content-Type']=f"application/{sub_type}"
        #
        #  TODO: process other mime_type
        #        application/xml       
        #        application/zip
        #        ...
        #        text/csv
        #        text/xml
        #        ...
        #        video/mp4 
        #        video/mpeg
        #        ...
        #
        else:
            raise ValueError(f"Invalid MIME type: main_type={main_type} sub_type={sub_type}")
        return base_dir


    def build_content(self, path, base_dir):
        """
        Loads the objects file from storage space.

        :params path (str): relative path to the file.
        :params base_dir (str): base directory where the file is located.

        :rtype tuple: (int, bytes) representing content length and content data.
        """

        filepath = os.path.join(base_dir, path.lstrip('/'))

        print(f"[Response] serving the object at location {filepath}")
            #
            #  TODO: implement the step of fetch the object file
            #        store in the return value of content
            #
        try: 
            with open(filepath,'rb') as f: 
                content = f.read()
                self.status_code = 200
        except FileNotFoundError:
            self.status_code = 404
            filepath_ = os.path.join(BASE_DIR+ "www/errors/" , "404.html")
            with open(filepath_,'rb') as f: 
                content =f.read()
            self.headers["Content-Type"] = "text/html"
        except Exception as e: # 500
            self.status_code = 500
            filepath_ = os.path.join(BASE_DIR+ "www/errors/" , "500.html")
            with open(filepath_,'rb') as f: 
                content =f.read()
            self.headers["Content-Type"] = "text/html"
        return len(content), content


    def build_response_header(self, request):
        """
        Constructs the HTTP response headers based on the class:`Request <Request>
        and internal attributes.

        :params request (class:`Request <Request>`): incoming request object.

        :rtypes bytes: encoded HTTP response header.
        """
        reqhdr = request.headers
        rsphdr = self.headers
    
        #Build dynamic headers
        headers = {
                "Accept": str(reqhdr.get("Accept", "application/json")),
                "Accept-Language": str(reqhdr.get("Accept-Language", "en-US,en;q=0.9")),
                "Authorization": str(reqhdr.get("Authorization", "Basic <credentials>")),
                "Cache-Control": "no-cache",
                "Content-Type": str(self.headers['Content-Type']),
                "Content-Length": str(len(self._content) if isinstance(self._content, (bytearray,bytes)) else 0 ),
#                "Cookie": "{}".format(reqhdr.get("Cookie", "sessionid=xyz789")), #dummy cooki
                "Date": str(datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")),
                "Max-Forward": "10",
                "Pragma": "no-cache",
                "Proxy-Authorization": "Basic dXNlcjpwYXNz",  # example base64
                "Warning": "199 Miscellaneous warning",
                "User-Agent": str(reqhdr.get("User-Agent", "Chrome/123.0.0.0")),
            }
        if 'Set-Cookie' in rsphdr: 
            headers['Set-Cookie'] = rsphdr['Set-Cookie']
            print(f"[Response] Adding Set-Cookie header: {rsphdr['Set-Cookie']}" )
        if 'Authorization' in reqhdr: # request having logging in
            headers['Authorization'] = str(reqhdr.get("Authorization")) 
        # Header text alignment
            #
            #  TODO: implement the header building to create formated
            #        header from the provied headers
            #
        #
        # TODO prepare the request authentication
        #
	# self.auth = ...
        self.reason = HTTP_REASON.get(self.status_code, "Unknown")
        status_line = f"HTTP/1.1 {self.status_code} {self.reason}"
        fmt_header = status_line + "\r\n"
        for key, value in  headers.items():
            fmt_header += f"{key}: {value}\r\n"
        fmt_header += "\r\n"
        return str(fmt_header).encode('utf-8')


    def build_notfound(self):
        """
        Constructs a standard 404 Not Found HTTP response.

        :rtype bytes: Encoded 404 response.
        """

        return (
                "HTTP/1.1 404 Not Found\r\n"
                "Accept-Ranges: bytes\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: 13\r\n"
                "Cache-Control: max-age=86000\r\n"
                "Connection: close\r\n"
                "\r\n"
                "404 Not Found" #body
            ).encode('utf-8')


    def build_response(self, request):
        """
        Builds a full HTTP response including headers and content based on the request.

        :params request (class:`Request <Request>`): incoming request object.

        :rtype bytes: complete HTTP response using prepared headers and content.
        """
        path = request.path
        method = request.method        
        print(f"[Response] {request.method} path {request.path}")
        
        # Handle POST /login
        if method == 'POST' and path == '/login': 
            print("[Response] Handling login POST request")
            return self.build_login_response(request)

        # Handle GET / or /index.html - require authentication
        if method == 'GET' and path in ['/', '/index.html']: 
            if not self.is_authenticated(request): 
                print("[Response] Access denied: No valid authentication cookie")
                return self.build_unauthorized_response()
            else: 
                print("[Response] Access permitted: Valid authentication cookie found")
                        
        # Continue with normal file serving
        mime_type = self.get_mime_type(path)
        print(f"[Response] MIME type: {mime_type}")
                
        base_dir = ""

        #If HTML, parse and serve embedded objects
        if path.endswith('.html') or mime_type == 'text/html':
            base_dir = self.prepare_content_type(mime_type = 'text/html')
        elif mime_type == 'text/css':
            base_dir = self.prepare_content_type(mime_type = 'text/css')
        elif mime_type and mime_type.startswith('image/'):
            base_dir = self.prepare_content_type(mime_type=mime_type)
        else:
            print(f"[Response] Unsupported MIME type: {mime_type}")
            return self.build_notfound()

        # Load content
        _, self._content = self.build_content(path, base_dir)
        self._header = self.build_response_header(request)
        self.reason = HTTP_REASON.get(self.status_code, "Unknown")

        return self._header + self._content
"""
request.path = "/index.html"
request.headers = {"User-Agent": "Mozilla/5.0"}
resp = Response(request)
data = resp.build_response(request)
print(data.decode('utf-8', errors='ignore'))
"""