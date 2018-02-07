import tldextract, subprocess, re, sys

                
class Pois():
    
    def __init__(self, timeout='20', tunnel_tor='0'):
        self.timeout = int(timeout)
        self.tunnel_tor = int(tunnel_tor)
        
    @staticmethod
    def check_whois_is_installed():
        p = subprocess.Popen('whois', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result , err = p.communicate(timeout=1)
        if 'not found' in err.decode('utf-8'): raise WhoisNotInstalledError()
        
    def fetch_whois(self, domain):
        # whois -h $(whois reddit.com | grep 'Registrar WHOIS Server:' | cut -f2- -d:) reddit.com
        # registrar_whois_server, err = self._run_bash_command_in_list_format(["whois {} | grep 'Registrar WHOIS Server:' | cut -f2- -d:".format(domain)])       
        # domain nomalization        
        domain = URI.normalize_domain(domain)
        if not domain:
            raise Exception('bad formatted domain ', domain)

        command = []
        if self.tunnel_tor:
            command.append('torsocks')
            command.append('-i')

        command.append('whois')
        command.append(domain)

        result, err = Bash.run_bash_command_in_list_format(command, timeout=self.timeout)

        if 'registrar whois server' in result.lower():
            try:      
                registrar_whois_server = re.findall("^.*Registrar WHOIS Server.*$", result,
                                        re.MULTILINE | re.IGNORECASE)[0].strip().split(':')[1].strip()
                # sometimes Registrar WHOIS Server is present but empty like 1001mp3.biz
                # so we use the last result
                if registrar_whois_server:
                    command.pop()
                    command.pop()
                    command.append("whois -h {} {}".format(registrar_whois_server, domain))
                    
                    result, err = Bash.run_bash_command_in_list_format(command, timeout=self.timeout)
            except Exeption as e:
                pass
        
        if err: raise WhoisError(err, domain)
        if not result: raise TimeoutError(domain)
        
        self.validate_result(result)
        return {'raw':result, 'normalized':self.normalize_result(result)}

    def validate_result(self, result):
        if result.lower().startswith('no match') or ('no entries found' in result.lower()): raise DomainNotFoundError()
        if result.lower().startswith('no whois server'): raise NoWhoisServerFoundError()
        return True
    
    def normalize_result(self, result):
        lines = result.split('\n')
        output = {}
        for line in lines:
            splitted_by_colon = line.split(':') 
            if len(splitted_by_colon) != 2: continue
            key, value = splitted_by_colon
            output[key.strip()] = value.strip()
            
        return output


class URI():

    @staticmethod
    def normalize_domain(domain):
        parsed_url = tldextract.extract(domain)
        return parsed_url.domain + '.' + parsed_url.suffix;


class Bash():
    
    @staticmethod
    def run_bash_command_in_list_format(command, timeout=5):
        try:
            p = subprocess.Popen(' '.join([token for token in command]), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
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

