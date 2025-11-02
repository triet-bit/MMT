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
daemon.request
~~~~~~~~~~~~~~~~~

This module provides a Request object to manage and persist 
request settings (cookies, auth, proxies).
"""
from .dictionary import CaseInsensitiveDict
from json import dumps
import urllib.parse
import base64
class Request(): # parse and prepare
    """The fully mutable "class" `Request <Request>` object,
    containing the exact bytes that will be sent to the server.

    Instances are generated from a "class" `Request <Request>` object, and
    should not be instantiated manually; doing so may produce undesirable
    effects.

    Usage::

      >>> import deamon.request
      >>> req = request.Request()
      ## Incoming message obtain aka. incoming_msg
      >>> r = req.prepare(incoming_msg)
      >>> r
      <Request>
    """
    __attrs__ = [
        "method",
        "url",
        "headers",
        "body",
        "reason",
        "cookies",
        "body",
        "routes",
        "hook",
    ]

    def __init__(self):
        #: HTTP verb to send to the server.
        self.method = None
        #: HTTP URL to send the request to.
        self.url = None
        #: dictionary of HTTP headers.
        self.headers = None
        #: HTTP path
        self.path = None        
        # The cookies set used to create Cookie header
        self.cookies = None
        #: request body to send to the server.
        self.body = None
        #: Routes
        self.routes = {}
        #: Hook point for routed mapped-path
        self.hook = None
    def extract_request_line(self, request):
        try:
            lines = request.splitlines()
            first_line = lines[0]
            method, path, version = first_line.split()

            if path == '/':
                path = '/index.html'
            if path == '/': 
                path = '/test.html'
        except Exception:
            return None, None, None

        return method, path, version
             
    def prepare_headers(self, request):
        """Prepares the given HTTP headers."""
        lines = request.split('\r\n')
        headers = {}
        for line in lines[1:]:
            if line == '': 
                break
            if ': ' in line:
                key, val = line.split(': ', 1) # only split once
                headers[key.lower()] = val
        return headers

    def prepare(self, request, routes=None):
        """Prepares the entire request with the given parameters."""

        # Prepare the request line from the request header
        self.method, self.path, self.version = self.extract_request_line(request)
        print(f"[Request] {self.method} path {self.path} version {self.version}")

        #
        # @bksysnet Preapring the webapp hook with WeApRous instance
        # The default behaviour with HTTP server is empty routed
        #
        # TODO manage the webapp hook in this mounting point
        #
        
        if not routes == {}: #{('POST', '/login'): login_function, ('GET', '/hello'): hello_function}
            self.routes = routes
            self.hook = routes.get((self.method, self.path))
        if self.hook is not None: 
            print(f"[Request] Handler founded for {self.method} - {self.path}")
        else: 
            print(f"[Request] No handler founded for {self.method} - {self.path}")

        self.headers = self.prepare_headers(request)
        cookies = self.headers.get('cookie', '') # "session_id=abc123; auth=true"
        items = cookies.split('; ')
        cookies_mp = {}
        for i in items: 
            key, value = i.split('=')
            cookies_mp[key.lower()] = value
        self.cookies = cookies_mp # {'session_id': 'abc123', 'auth': 'true'}
        return

    def prepare_body(self, data, files, json=None): # for POST/PUT, para are json>files>data
        """
        prepare_body(data={'user': 'admin', 'pass': '123'}, files=None, json=None)
        Kết quả: "user=admin&pass=123"

        prepare_body(data=None, files=None, json={'status': 'ok'})
        Kết quả: '{"status": "ok"}'

        prepare_body(data=None, files=None, json=None)
        Kết quả: 
        """
        # chuaw thuc hien phan files
        body = ""
        if json is not None:
            body = dumps(json)
            self.headers["Content-Type"] = 'application/json'

        elif data is not None and data != "" and data != {}: 
            self.headers["Content-Type"] = 'application/x-www-form-urlencoded'
            if type(data) == dict: 
                string = ""
                for key,value in data.items(): 
                    enq_key = urllib.parse.quote(str(key))
                    enq_value = urllib.parse.quote(str(value))
                    string = string + enq_key + "=" + enq_value + "&"
                body = string[:-1]
                
            elif type(data) == str: 
                body = data 

        else:
            body = ""

        self.body = body
        self.prepare_content_length(self.body)
        return


    def prepare_content_length(self, body):
        self.headers["Content-Length"] = "0"
        if (body is not None) and (body != ""): 
            body_len = len(body.encode('utf-8'))
            self.headers["Content-Length"] = str(body_len)
        return 


    def prepare_auth(self, auth, url=""): #(username, password)
        if not auth: 
            return
        if isinstance(auth,tuple) and len(auth) == 2:
            usr, pw = auth
            usr_pw = f"{usr}:{pw}"
            encoded = base64.b64encode(usr_pw.encode()).decode()
            self.headers["Authorization"] = f"Basic {encoded}"
        elif isinstance(auth,str): 
            self.headers["Authorization"] = f"Bearer {encoded}" 
    def prepare_cookies(self, cookies):
        if cookies is not None:  
            self.headers["Cookie"] = cookies
