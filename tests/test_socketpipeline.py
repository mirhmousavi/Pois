import socket

import mock
import pytest

from pois import *


class TestSocketPipeline:
    def test_execute_whois_with_valid_whois_server(self):
        result = SocketPipeline().execute(
            query="github.com\r\n", server="whois.verisign-grs.com", port=43
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

    def test_whois_with_low_timeout_that_raises_timeout_error(self):
        with pytest.raises(SocketTimeoutError):
            SocketPipeline(timeout=1).execute(
                query="github.com", server="whois.verisign-grs.com", port=43
            )
