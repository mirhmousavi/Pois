import traceback

from pois import Pois
try:

    Pois.check_whois_is_installed()
    result = Pois.fetch_whois('github.com',timeout=5)
    print(result['normalized'])
    
except Exception as err:
    print(str(err))
    print(err.args)
    print(traceback.format_exc())
