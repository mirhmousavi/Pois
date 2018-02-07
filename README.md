# Pois
a Python wrapper for linux whois with authentic information (not abuse)

## Why use it?
---


try:    
    Pois.check_whois_is_installed()
    result = Pois(timeout=10).fetch_whois('knowclub.com')
    print(result['normalized'])
except Exception as err:
    print(str(err))
    print(err.args)
