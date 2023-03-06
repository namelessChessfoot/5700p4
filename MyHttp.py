#! /usr/bin/env python3
from urllib.parse import urlparse
from MyTCP import tcp_process
import socket


class MyHttp():
    # Responsible for send, recv,
    # and request, which is a combination of send and recv
    # manage the cookie as well
    NEWLINE = "\r\n"

    @classmethod
    def build_initial(cls, method: str, path: str = "/") -> str:
        return f"{method} {path} HTTP/1.1{cls.NEWLINE}"

    def build_header(self, header_dict: dict):
        header_dict["connection"] = "keep-alive"
        ret = ""
        for h, v in header_dict.items():
            ret += f"{h}: {v}{self.NEWLINE}"
        return ret

    @classmethod
    def build_body(cls, body_dict: dict):
        ret = ""
        for k, v in body_dict.items():
            if len(ret) > 0:
                ret += "&"
            ret += f"{k}={v}"
        return ret

    def build_message(self, method: str, url: str, header_dict: dict = {}, body_dict: dict = {}) -> str:
        pr = urlparse(url)
        header_dict["Host"] = pr.netloc

        body = self.build_body(body_dict)
        header_dict["content-length"] = str(len(body))

        return f"{self.build_initial(method,pr.path)}{self.build_header(header_dict)}{self.NEWLINE}{body}"

    def get(self, url):
        pr = urlparse(url)
        ip = socket.gethostbyname(pr.netloc)
        print(ip)
        path = pr.path
        message = self.build_message("GET", url)
        res = tcp_process(message.encode(), ip, 80)
        data = b"".join(res)
        name = path.split("/")[-1]
        if len(name) == 0:
            name = "index.html"
        with open(f"{name}", "wb") as f:
            f.write(data.split(b"\r\n\r\n")[-1])


two = "http://david.choffnes.com/classes/cs5700f22/2MB.log"
ten = "http://david.choffnes.com/classes/cs5700f22/10MB.log"
webpage = "http://www.khoury.northeastern.edu"
http = MyHttp()
http.get(two)
