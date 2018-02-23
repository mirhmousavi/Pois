# Pois
a better whois client for python




## Why use Pois over other libraries?


so why use Pois over robust libraries like [pythonwhois](https://github.com/joepie91/python-whois), [pywhois](https://bitbucket.org/richardpenman/pywhois)...


1. Pois use all whois servers of all available tld so it whois domain with tld specific whois server (worth mention that linux whois utility is lack of get whois of new tld like .rocks)


3. You can pass a whois server to query that server for whois


2. Pois return BadWhoisResultError if domain not found or your whois quota exceeded.


3. You can specify a timeout for whois operation, some whois servers after user quota exceeded for get whois just don't return
anything and won't close the connection.



4. Pois parse result and if find a Registrar whois server, re-whois that server to get complete whois (thick whois)



5. Pois use sockets so it's portable.



6. Pois return result in raw and nomalized format, in the latter you a get a clean dict of whois result.



*** tld whois severs provided from [weppos/whois](https://github.com/weppos/whois/)





## How use it



copy 'pois' folder anywhere you want then use it in you program like this:


```python

from pois import Pois

try:

    result = Pois.fetch_whois(domain='github.com', whois_server=None, timeout=5)
    print(result['raw'], result['normalized'])
    
except Exception as err:
    print(str(err))
    print(err.args)
    
```


## Exceptions


Pois return these exceptions that is self-described


```

TimeoutError, WhoisError, BadDomainError, BadWhoisResultError, NoWhoisServerFoundError


```






