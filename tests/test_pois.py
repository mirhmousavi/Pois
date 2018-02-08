import unittest
from pois import *
import traceback


class PoisTests(unittest.TestCase):
    
    def test_fetch_whois_with_bad_formatted_domain(self):
        try:
            Pois().fetch_whois(domain='sdfgs@fg(*&com')
            assert True == False
        except BadDomainError:
            assert True == True

    def test_fetch_whois_of_valid_domain(self):
        try:
            Pois().fetch_whois(domain='github.com')
            assert True == True 
        except :
            assert True == False
            
#     def test_not_found(self):
#         
#         handle = open('result', 'w')
#         tlds = open('tld.txt').read().split()
#         output = []
#         tld=['com','net']
#         for tld in tlds:
#             try:
#                 print('jhvsdf7dfsdf7asdfhdf.{}'.format(tld))
#                 print("{}.whois-servers.net".format(tld))
#                 Pois.load_tld()
#                 result = SocketPipeline.execute_whois(domain='jhvsdf7dfsdf7asdfhdf.{}'.format(tld), whois_server=Pois.tld[tld]['host'], timeout=10)
#                 output.append(result)
#                 output.append('---------------')
#                 print(result)
#             except Exception as err:
#                 print(err.args)
#                 #assert True == False
#             
#         handle.writelines(output)
#         assert True == True

