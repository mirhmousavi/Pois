import unittest
from pois import *
import time

class PoisTests(unittest.TestCase):

    def test_fetch_whois_of_valid_domain(self):
        result = Pois().fetch(domain='github.com')
        assert result

    def test_fetch_whois_of_valid_domain_with_not_utf8_result(self):
        result = Pois().fetch(domain='cloudpbx.com.tr')['registry_result']
        expected_result='** Registrant:\n   Empatiq Ýletiþim Teknolojileri A.Þ.\n   Anadolu Hisarý Göksu Villalarý Kaktüs Sk. B181 - A\n   Beykoz\n   Ýstanbul,\n     Türkiye\n   atasoy.sacide@gmail.com\n   + 90-216-2222500-\n   + \n\n\n** Administrative Contact:\nNIC Handle\t\t: mih81-metu\nOrganization Name\t: Medyatel Ýletiþim Hizmetleri A.Þ.\nAddress\t\t\t: kucukbakkalkoy mh atilla ilhan cd\n\t\t\t  no:10 atasehir\n\t\t\t  Ýstanbul,34750\n\t\t\t  Türkiye\nPhone\t\t\t: + 216-216-2220707-\nFax\t\t\t: + 90-216-2220708-\n\n\n** Technical Contact:\nNIC Handle\t\t: mih81-metu\nOrganization Name\t: Medyatel Ýletiþim Hizmetleri A.Þ.\nAddress\t\t\t: kucukbakkalkoy mh atilla ilhan cd\n\t\t\t  no:10 atasehir\n\t\t\t  Ýstanbul,34750\n\t\t\t  Türkiye\nPhone\t\t\t: + 216-216-2220707-\nFax\t\t\t: + 90-216-2220708-\n\n\n** Billing Contact:\nNIC Handle\t\t: mih81-metu\nOrganization Name\t: Medyatel Ýletiþim Hizmetleri A.Þ.\nAddress\t\t\t: kucukbakkalkoy mh atilla ilhan cd\n\t\t\t  no:10 atasehir\n\t\t\t  Ýstanbul,34750\n\t\t\t  Türkiye\nPhone\t\t\t: + 216-216-2220707-\nFax\t\t\t: + 90-216-2220708-\n\n\n** Domain Servers:\nns1.dortdort.com\nns2.dortdort.com\n\n** Additional Info:\nCreated on..............: 2016-Jul-28.\nExpires on..............: 2019-Jul-27.\n'
        assert result == expected_result

    def test_fetch_whois_of_idn(self):
        result = Pois().fetch(domain='购物.购物')['registry_result']
        expected_result='Reserved Domain Name\r\nURL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\r\n>>> Last update of WHOIS database: 2018-08-11T05:30:22Z <<<\r\nThe above WHOIS results have been redacted to remove potential personal data. The full WHOIS output may be available to individuals and organisations with a legitimate interest in accessing this data not outweighed by the fundamental privacy rights of the data subject. To find out more, or to make a request for access, please visit: RDDSrequest.nic.xn--g2xx48c.\r\n\r\nFor more information on Whois status codes, please visit https://icann.org/epp\r\n\r\nThe whois information provided on this site is intended to provide you with the relevant contact information for a domain name registrant and the identity of certain administrative and technical contacts associated with that domain name. The data in this record is provided by Neustar, Inc. on behalf of Minds + Machines Group Limited ("the Company"), for informational purposes only. Accuracy is not guaranteed. The Company is the authoritative source for whois information in top-level domains it operates under contract with the Internet Corporation for Assigned Names and Numbers. This service is intended only for query-based access. Note that the lack of a whois record for a particular domain does not indicate that the name is available for registration. By using this service, you agree that you will use any data presented for lawful purposes only and that under no circumstances will you use (a) data acquired for the purpose of allowing, enabling, or otherwise supporting the transmission by email, telephone, facsimile, or other communications mechanisms mass unsolicited, commercial, advertising, or solicitations to entities other than your existing customers; or (b) this service to enable high volume, automated, electronic processes that send queries or data to the systems of any registrar or any registry except as reasonably necessary to register domain names or to modify existing domain name registrations. The Company reserves the right to modify these terms at any time. By submitting this query, you agree to abide by this policy. All rights reserved. For more information on Whois status codes, please visit https://icann.org/epp\r\n\r\n'
        # because result contains whois result time in seconds we can't compare them
        assert result.startswith('Reserved Domain Name')

    def test_fetch_whois_of_valid_domain_with_proxy(self):
        result = Pois(proxy_info={'type':'http','addr':'localhost', 'port': 8118}).fetch(domain='github.com',)['registry_result']
        assert result

    def test_fetch_whois_of_valid_domain_with_defined_whois_server(self):
        result = Pois().fetch(domain='github.com', whois_server='whois.verisign-grs.com')['registry_result']
        assert result

    def test_fetch_whois_of_not_exist_domain(self):
        result = Pois().fetch(domain='notexistdomain123.com')['registry_result']
        assert result

    def test_fetch_whois_of_not_exists_tld(self):
        with self.assertRaises(NoWhoisServerFoundError) as e:
            Pois().fetch(domain='github.az')['registry_result']

    def test_update_tld_file(self):
        random = int(time.time())
        p = Pois()
        p.update_tlds_file({'random': random})
        with open(Pois.tlds_file_path,'r') as f:
            content = json.load(f)
            assert content['random'] == random

    def test_find_whois_server_for_tld(self):
        result = Pois().find_whois_server_for_tld('guru')
        assert result == 'whois.nic.guru'

    def test_find_whois_server_for_not_exists_tld(self):
        with self.assertRaises(NoWhoisServerFoundError) as e:
            Pois().find_whois_server_for_tld('xxxxxxxxxxxxx123')

    # def test_get_idna_repr_non_ascii_input(self):
    #     p = Pois()
    #     result = p.get_idna_repr('سلام')
    #     expected_result = 'xn--mgbx5cf'
    #     assert result == expected_result
    #
    # def test_get_idna_repr_ascii_input(self):
    #     p = Pois()
    #     result = p.get_idna_repr('hello')
    #     expected_result = 'hello'
    #     assert result == expected_result