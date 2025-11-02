from daemon.request import * 


req = Request()
raw = """"POST /api/data HTTP/1.1\r\n"
    "Host: localhost:8080\r\n"
    "Content-Type: application/json\r\n"
    "\r\n"
    '{"x":1, "y":2}'"""
line = req.extract_request_line()
print(line)