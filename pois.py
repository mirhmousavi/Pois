import tldextract, subprocess, re, sys, json, traceback

                
class Pois():
    tld = {}

    @classmethod
    def load_whois_servers(cls):
        if not cls.tld:
            cls.tld = json.loads(open('tld.json', 'r').read())

    @classmethod
    def check_whois_is_installed(cls):
        p = subprocess.Popen('whois', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result , err = p.communicate(timeout=1)
        if 'not found' in err.decode('utf-8'): raise WhoisNotInstalledError()
        
    @classmethod
    def fetch_whois(cls, input, timeout=10, whois_server=None):
        cls.load_whois_servers()
        # domain nomalization        
        domain = URI.normalize_domain(input)
        if not domain:
            raise BadDomainError(input)

        command = []
        command.append('whois')
        
        domain_suffix = URI.get_domain_suffix(domain)

        if whois_server or cls.tld.get(domain_suffix):
            command.append('-h')
            if whois_server: command.append(whois_server)
            elif cls.tld.get(domain_suffix): command.append(cls.tld[domain_suffix]['host'])
        
        command.append(domain)

        result, err = Bash.run_bash_command_in_list_format(command, timeout=timeout)

        if not whois_server and 'registrar whois server' in result.lower():
            try:      
                registrar_whois_server = re.findall("^.*Registrar WHOIS Server.*$", result,
                                                    re.MULTILINE | re.IGNORECASE)[0].strip().split(':')[1].strip()
                # sometimes Registrar WHOIS Server is present but empty like 1001mp3.biz
                # so we use the previous result
                if registrar_whois_server:
                    command = ['whois', '-h', registrar_whois_server, domain]
                    result, err = Bash.run_bash_command_in_list_format(command, timeout=timeout)
            except Exception as e:
                pass
        
        if err: raise WhoisError(err, domain)
        if not result: raise TimeouFtError(domain)
        
        cls.validate_result(domain, result)
        return {'raw':result, 'normalized':cls.normalize_result(result)}

    @classmethod
    def validate_result(cls, domain, result):
        if result.lower().startswith('no match') or ('no entries found' in result.lower()): raise DomainNotFoundError(domain, result)
        if result.lower().startswith('no whois server'): raise NoWhoisServerFoundError(domain, result)
        return None
    
    @classmethod
    def normalize_result(cls, result):
        lines = result.split('\n')
        output = {}
        last_key = None
        for line in lines:
            if not line.strip(): continue
            splitted_by_colon = line.split(': ', maxsplit=1)

            if len(splitted_by_colon) < 2:
                if not last_key: last_key = '0'
                output[last_key] += splitted_by_colon[0].strip()
                continue
            
            key, value = splitted_by_colon
            output[key.strip()] = value.strip()
            last_key = key.strip()
            
        return output


class URI():

    @staticmethod
    def normalize_domain(domain):
        parsed_url = tldextract.extract(domain)
        return parsed_url.domain + '.' + parsed_url.suffix;

    @staticmethod
    def get_domain_suffix(domain):
        parsed_url = tldextract.extract(domain)
        return parsed_url.suffix

    
class Bash():
    
    @staticmethod
    def run_bash_command_in_list_format(command, timeout=5):
        try:
            p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            result, err = b'', b''
        return result.decode('utf-8').strip(), err.decode('utf-8').strip()

                
class DomainNotFoundError(Exception):

    def __str__(self):
        return 'domain not found'


class BadDomainError(Exception):

    def __str__(self):
        return 'domain in bad format'


class NoWhoisServerFoundError(Exception):

    def __str__(self):
        return 'no whois server found'


class TimeoutError(Exception):

    def __str__(self):
        return 'whois return timeout'


class WhoisError(Exception):

    def __str__(self):
        return 'problem on fetching whois'


class WhoisNotInstalledError(Exception):
        
    def __str__(self):
        return 'whois is not installed'

