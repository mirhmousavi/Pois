import socket

import pytest
from pois import *


class TestSocketPipeline:
    def test_execute_whois(self):
        result = SocketPipeline().execute(
            query="github.com\r\n", server="com.whois-servers.net", port=43
        )
        assert result

    def test_execute_whois_with_bad_whois_server(self):
        with pytest.raises(SocketError):
            SocketPipeline().execute(
                query="github.com\r\n", server="7465.whois-servers.net", port=43
            )

    def test_execute_whois_with_bad_domain(self):
        with pytest.raises(SocketError):
            SocketPipeline().execute(
                query="github\r\n", server="7465.whois-servers.net", port=43
            )

    def test_get_webpage(self):
        s = SocketPipeline()
        result = s.execute(
            "GET / HTTP/1.1\r\nHost: bestical.ir\r\n\r\n",
            socket.gethostbyname("bestical.ir"),
            80,
        )
        assert result

    def test_get_webpage_with_proxy(self):
        s1 = SocketPipeline(
            proxy_info={"proxy_type": "http", "addr": "localhost", "port": 8118}
        )
        result_with_proxy = s1.execute(
            "GET / HTTP/1.1\r\nHost: bestical.ir\r\n\r\n",
            socket.gethostbyname("bestical.ir"),
            80,
        )

        s2 = SocketPipeline()
        result_without_proxy = s2.execute(
            "GET / HTTP/1.1\r\nHost: bestical.ir\r\n\r\n",
            socket.gethostbyname("bestical.ir"),
            80,
        )

        assert (
            result_with_proxy.split("\r\n")[-1]
            != result_without_proxy.split("\r\n")[-1]
        )
        assert result_with_proxy
        assert result_without_proxy

    def test_whois_with_low_timeout(self):
        with self.assertRaises(SocketTimeoutError) as e:
            SocketPipeline(timeout=1).execute(
                query="GET / HTTP/1.1\r\nHost: bestical.ir\r\n",
                server=socket.gethostbyname("bestical.ir"),
                port=80,
            )

    def test_bad_proxy_format(self):
        with self.assertRaises(SocketBadProxyError) as e:
            SocketPipeline(proxy_info={"proxy_type": "xxx", "addr": "12"})
