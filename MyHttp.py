#! /usr/bin/env python3
from urllib.parse import urlparse
from MyTCP import TCP
import socket


class MyHttp():
    '''
        Send a GET message, format the response, and save it.
    '''
    NEWLINE = "\r\n"

    def build_get_message(self) -> str:
        '''
            Build a GET message.
            Parameters:
                none
            Returns:
                The message with str type
        '''
        header_dict = {}
        header_dict["Host"] = self.pr.netloc
        header_dict["connection"] = "keep-alive"
        header_dict["content-length"] = "0"
        header = self.NEWLINE.join(
            map(lambda item: f"{item[0]}: {item[1]}", header_dict.items()))
        return f"GET {self.pr.path} HTTP/1.1{self.NEWLINE}{header}{self.NEWLINE*2}"

    def get(self, url: str) -> int:
        '''
            Download a resource with a URL.
            Parameters:
                url: the URL of the resource
            Returns:
                The number of bytes written to the output file.
                If an invalid message is received, returns -1 and does not create any file
        '''
        self.pr = urlparse(url)
        ip = socket.gethostbyname(self.pr.netloc)
        path = self.pr.path
        message = self.build_get_message()
        tcp = TCP(ip, 80)
        res = tcp.tcp_process(message.encode())

        CRLF = self.NEWLINE.encode()
        data = b"".join(res)
        seperator = CRLF*2
        p = data.find(seperator)
        header = data[:p].decode()
        payload = data[p+len(seperator):]

        if "200" not in header:
            print('Got a non-200 response')
            print(header)
            return
        if "Transfer-Encoding: chunked" in header:
            lst = payload.split(CRLF)
            tmp = b""
            for i in range(0, len(lst), 2):
                length = int(lst[i].decode(), 16)
                if length == 0:
                    break
                if length != len(lst[i+1]):
                    print("Bad chunked encoding format")
                    return -1
                tmp += lst[i+1]
            payload = tmp

        name = path.split("/")[-1]
        if len(name) == 0:
            with open(f"index.html", "w") as f:
                f.write(payload.decode())
        else:
            with open(f"{name}", "wb") as f:
                f.write(payload)

        return len(payload)
