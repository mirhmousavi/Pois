import tldextract, subprocess, re, sys, json, traceback, socket, os
from unittest import result
ROOT_DIR = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))

                
class Pois():
    tld = []
    
    @classmethod
    def load_tld(cls):
        if not cls.tld: cls.tld = json.loads(open(ROOT_DIR + '/tld.json', 'r').read())

    @classmethod
    def check_tld_whois_server_is_available(cls, domain):
        if not cls.tld: cls.load_tld()
        
        suffix = URI.get_domain_suffix(domain)
        if suffix not in cls.tld: raise NoWhoisServerFoundError(domain, suffix)
        return True

    @classmethod
    def fetch_whois(cls, domain, whois_server=None, timeout=10):
        # domain nomalization        
        domain = URI.normalize_domain(domain)
        
        domain_suffix = URI.get_domain_suffix(domain)
        whois_server = whois_server or (cls.check_tld_whois_server_is_available(domain) and cls.tld[domain_suffix]['host']) 
        result = SocketPipeline.execute_whois(domain=domain, whois_server=whois_server, timeout=timeout)

        try:
            registrar_whois_server = (re.findall("^.*whois server.*$", result, re.MULTILINE | re.IGNORECASE) or re.findall("^.*registrar whois.*$", result, re.MULTILINE | re.IGNORECASE))[0].strip().split(':')[1].strip()
        except Exception as e:
            registrar_whois_server = None 
                
            # sometimes Registrar WHOIS Server is present but empty like 1001mp3.biz
            # so we use the previous result
            if registrar_whois_server:
                result = SocketPipeline.execute_whois(domain=domain, whois_server=registrar_whois_server, timeout=timeout)
        
        output = {}
        output['normalized'] = cls.normalize_result(result)
        output['raw'] = result
        cls.validate_result(domain, output['normalized'])
        return output

    @classmethod
    def validate_result(cls, domain, normalized_result):
#         result_in_small_caps = result.lower()
#         domain_not_found_statements = [
#             'No match', 'NOT FOUND', 'No matching record.', 'This domain name has not been registered',
#             'No Data Found', 'No Object Found', 'Domain Status: free', 'The queried object does not exist',
#             'El dominio no se encuentra registrado en NIC Argentina',
#             'This query returned 0 objects', 'no entries found', 'Domain Status: free',
#             "{} is free".format(domain), 'Status:            available',
#             'Status:    AVAILABLE', 'Status: Not Registered', 'Status: free',
#             'Status: AVAILABLE', 'Available: Yes', 'Domain name {} does not exist in database'.format(domain),
#             'Object does not exist', 'Domain status:         available', "{} is available.".format(domain),
#             "{}: no existe".format(domain), 'This query returned 0 objects',
#             'Not Registered', 'No data was found to match the request criteria', 'The requested domain was not found in the Registry or Registrar’s WHOIS Server.',
#             'Nothing found for this query', 'No such domain',
#             'No_Se_Encontro_El_Objeto/Object_Not_Found', 'query_status: 220 Available',
#             'Domain unknown', 'No information available about domain name',
#             'Status.: NOT FOUND', 'Not find MatchingRecord', 'Nothing found for this query',
#             'registration status: invalid', '網域名稱不合規定',
#         ]
#        if result_in_small_caps.startswith('Available') or result_in_small_caps in domain_not_found_statements_in_small_caps:
        
        if len(normalized_result) < 10:
            raise DomainNotExistsError(domain, result)
        return None
    
    @classmethod
    def normalize_result(cls, result):
        lines = result.split('\n')
        output = {}
        # last_key = None
        for line in lines:
            if not line.strip(): continue
            splitted_by_colon = line.split(': ', maxsplit=1)
    
            if len(splitted_by_colon) < 2: continue
            
            key, value = splitted_by_colon
            key = key.strip()
            value = value.strip()
            
            if output.get(key):
                if type(output.get(key)) == list: 
                    output[key].append(value)
                else:
                    temp = output[key]
                    output[key] = []
                    output[key].append(temp)
                    output[key].append(value)
            else:
                output[key] = value
                
        return output


class SocketPipeline():

    @classmethod
    def execute_whois(cls, domain, whois_server, timeout):
        output = []
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.settimeout(timeout)
                sock.connect((whois_server, 43))
                sock.send("{}\r\n".format(domain).encode('utf-8'))
                result = b''
                while True:
                    chunk = sock.recv(4096)
                    result += chunk
                    if not chunk: break
                return result.decode('utf-8').strip()
            except socket.timeout:
                raise TimeoutError(domain)
            except Exception as err:
                raise WhoisError(domain, str(err))

            
class URI():

    @staticmethod
    def normalize_domain(domain):
        parsed_url = tldextract.extract(domain)
        domain = parsed_url.domain and parsed_url.domain + '.' + parsed_url.suffix;
        if not domain: raise BadDomainError(input)
        return domain

    @staticmethod
    def get_domain_suffix(domain):
        parsed_url = tldextract.extract(domain)
        return parsed_url.suffix

                
class DomainNotExistsError(Exception):

    def __str__(self):
        return 'domain not found on specified whois server'


class BadDomainError(Exception):

    def __str__(self):
        return 'domain in bad format'


class TimeoutError(Exception):

    def __str__(self):
        return 'whois return timeout'


class WhoisError(Exception):

    def __str__(self):
        return 'problem on fetching whois'

    
class NoWhoisServerFoundError(Exception):

    def __str__(self):
        return 'no whois server found for this tld'
