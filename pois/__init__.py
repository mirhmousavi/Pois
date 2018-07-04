import json
import os
import re
import socket
import socks
import tldextract

###################################################
###################################################
###################################################

ROOT_DIR = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))


class Pois():
    tlds = []

    def __init__(self, timeout=10):
        self.tlds_file_path = ROOT_DIR + '/tlds.json'
        self.timeout = timeout
        self.tlds = self.load_tlds_file(self.tlds_file_path)
        self.proxy_info={}

    ##################################
    ##################################

    def load_tlds_file(self, path):
        try:
            return json.loads(open(path, 'r').read())
        except Exception as err:
            raise TldsFileError('tld data file can not be load, %s, err: %s' % (self.tlds_file_path, str(err)))

    ##################################
    ##################################

    def update_tlds_file(self, new_tld):
        try:
            with open(self.tlds_file_path, 'w') as f:
                self.tlds.update(new_tld)
                f.write(json.dumps(self.tlds, indent=4))
        except Exception as err:
            raise TldsFileError('can not write to file, %s,err: %s' % (self.tlds_file_path, str(err)))

    ##################################
    ##################################

    def set_proxy(self, *args, **kwargs):
        self.proxy_info = kwargs

    ##################################
    ##################################

    def find_whois_server_for_tld(self, tld):
        whois_server = ''
        try:
            s = SocketPipeline()
            result = s.execute('%s\r\n' % tld, 'whois.iana.org', 43)
            whois_server = (re.findall("^.*whois:.*$", result, re.MULTILINE | re.IGNORECASE))[0].strip().split(':')[1].strip()
        except:
            pass

        if whois_server:
            self.update_tlds_file({tld: whois_server})
            return whois_server

        raise NoWhoisServerFoundError('no whois server found for %s' % tld)

    ##################################
    ##################################

    def fetch(self, domain, whois_server=None):
        # domain nomalization        
        domain = Domain.normalize(domain)
        domain_suffix = Domain.get_suffix(domain)
        whois_server = whois_server or self.tlds.get(domain_suffix) or self.find_whois_server_for_tld(domain_suffix)

        s = SocketPipeline(timeout=self.timeout)
        if self.proxy_info: s.set_proxy(**self.proxy_info)
        result = s.execute(query="%s\r\n" % domain, server=whois_server,port=43)

        try:
            registrar_whois_server = (re.findall("^.*whois server.*$", result, re.MULTILINE | re.IGNORECASE)or
                    re.findall("^.*registrar whois.*$", result, re.MULTILINE | re.IGNORECASE))[0].strip().split(':')[1].strip()

        except Exception:
            registrar_whois_server = None
        # sometimes Registrar WHOIS Server is present but empty like 1001mp3.biz
        # so we use the previous result
        if registrar_whois_server:
            result = s.execute(query="%s\r\n" % domain, server=registrar_whois_server, port=43)

        return result

        ###################################################
        ###################################################
        ###################################################


class SocketPipeline():

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.proxy_info = {}

    def set_proxy(self, **kwargs):
        if kwargs.get('proxy_type') == 'http':
            kwargs['proxy_type'] = socks.HTTP
        elif kwargs.get('proxy_type') == 'socks4':
            kwargs['proxy_type'] = socks.SOCKS4
        elif kwargs.get('proxy_type') == 'sock5':
            kwargs['proxy_type'] = socks.SOCKS5

        self.proxy_info = kwargs

    def execute(self, query, server, port):
        try:
            s = socks.socksocket()
            if self.proxy_info: s.set_proxy(**self.proxy_info)
            s.settimeout(self.timeout)
            s.connect((server, port))
            s.send(query.encode('utf-8'))
            result = b''
            while True:
                chunk = s.recv(4096)
                result += chunk
                if not chunk: break
            return result.decode('utf-8').strip()
        except (socks.ProxyConnectionError, socket.timeout):
            raise SocketTimeoutError('time out on quering %s' % query)
        except Exception as err:
            raise SocketError('error on quering %s, err: %s' % (query, str(err)))
        finally:
            s.close()

            ###################################################
            ###################################################
            ###################################################


class Domain():

    @staticmethod
    def normalize(domain):
        parsed_url = tldextract.extract(domain)
        domain = parsed_url.domain and parsed_url.domain + '.' + parsed_url.suffix
        if not domain: raise BadDomainError(input)
        return domain.lower()

    @staticmethod
    def get_suffix(domain):
        parsed_url = tldextract.extract(domain)
        return parsed_url.suffix

        ###################################################
        ###################################################
        ###################################################

class PoisError(Exception):
    pass


class TldsFileError(PoisError):
    pass


class BadDomainError(PoisError):
    pass


class NoWhoisServerFoundError(PoisError):
    pass

class SocketError(PoisError):
    pass


class SocketTimeoutError(SocketError):
    pass

