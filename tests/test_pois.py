import unittest
from pois import *
import time

class PoisTests(unittest.TestCase):

    def test_fetch_whois_of_valid_domain(self):
        result = Pois().fetch(domain='github.com')
        assert result

    def test_fetch_whois_of_valid_domain_with_not_utf8_result(self):
        result = Pois().fetch(domain='cloudpbx.com.tr')
        expected_result='** Registrant:\n   Empatiq Ýletiþim Teknolojileri A.Þ.\n   Anadolu Hisarý Göksu Villalarý Kaktüs Sk. B181 - A\n   Beykoz\n   Ýstanbul,\n     Türkiye\n   atasoy.sacide@gmail.com\n   + 90-216-2222500-\n   + \n\n\n** Administrative Contact:\nNIC Handle\t\t: mih81-metu\nOrganization Name\t: Medyatel Ýletiþim Hizmetleri A.Þ.\nAddress\t\t\t: kucukbakkalkoy mh atilla ilhan cd\n\t\t\t  no:10 atasehir\n\t\t\t  Ýstanbul,34750\n\t\t\t  Türkiye\nPhone\t\t\t: + 216-216-2220707-\nFax\t\t\t: + 90-216-2220708-\n\n\n** Technical Contact:\nNIC Handle\t\t: mih81-metu\nOrganization Name\t: Medyatel Ýletiþim Hizmetleri A.Þ.\nAddress\t\t\t: kucukbakkalkoy mh atilla ilhan cd\n\t\t\t  no:10 atasehir\n\t\t\t  Ýstanbul,34750\n\t\t\t  Türkiye\nPhone\t\t\t: + 216-216-2220707-\nFax\t\t\t: + 90-216-2220708-\n\n\n** Billing Contact:\nNIC Handle\t\t: mih81-metu\nOrganization Name\t: Medyatel Ýletiþim Hizmetleri A.Þ.\nAddress\t\t\t: kucukbakkalkoy mh atilla ilhan cd\n\t\t\t  no:10 atasehir\n\t\t\t  Ýstanbul,34750\n\t\t\t  Türkiye\nPhone\t\t\t: + 216-216-2220707-\nFax\t\t\t: + 90-216-2220708-\n\n\n** Domain Servers:\nns1.dortdort.com\nns2.dortdort.com\n\n** Additional Info:\nCreated on..............: 2016-Jul-28.\nExpires on..............: 2019-Jul-27.\n'
        assert result == expected_result

    def test_fetch_whois_of_valid_domain_with_proxy(self):
        result = Pois(proxy_info={'type':'http','addr':'localhost', 'port': 8118}).fetch(domain='github.com',)
        assert result

    def test_fetch_whois_of_valid_domain_with_defined_whois_server(self):
        result = Pois().fetch(domain='github.com', whois_server='whois.verisign-grs.com')
        assert result

    def test_fetch_whois_of_not_exist_domain(self):
        result = Pois().fetch(domain='notexistdomain123.com')
        assert result

    def test_fetch_whois_of_not_exists_tld(self):
        with self.assertRaises(NoWhoisServerFoundError) as e:
            Pois().fetch(domain='github.az')

    def test_update_tld_file(self):
        random = int(time.time())
        p = Pois()
        p.update_tlds_file({'random': random})
        with open(Pois.tlds_file_path,'r') as f:
            content = json.load(f)
            assert content['random'] == random