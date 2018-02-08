import unittest
from pois import *


class SocketPipelineTests(unittest.TestCase):

    def test_execute_whois(self):
        result = SocketPipeline.execute_whois(domain='google.com', timeout=10, whois_server='com.whois-servers.net')
        # print(result)
        assert result
        
    def test_execute_whois_with_bad_whois_server(self):
        try:
            result = SocketPipeline.execute_whois(domain='google.com', timeout=10, whois_server='7465.whois-servers.net')
            assert True == False
        except WhoisError:
            assert True == True
       
    def test_execute_whois_with_bad_domain(self):
        try:
            result = SocketPipeline.execute_whois(domain='google', timeout=10, whois_server='7465.whois-servers.net')
            assert True == False
        except WhoisError:
            assert True == True
       
