import unittest
from pois import *


class PoisTests(unittest.TestCase):

    def test_fetch_whois_of_valid_domain(self):
        result = Pois().fetch(domain='github.com')
        assert result

    def test_fetch_whois_of_valid_domain_with_defined_whois_server(self):
        result = Pois().fetch(domain='github.com', whois_server='whois.verisign-grs.com')
        assert result

    def test_fetch_whois_of_not_exist_domain(self):
        result = Pois().fetch(domain='notexist1234567888888888999999999.com')
        assert result

    def test_fetch_whois_of_not_exists_tld(self):
        with self.assertRaises(NoWhoisServerFoundError) as e:
            Pois().fetch(domain='github.notexis8888888')