# Pois
a better whois client for python




## Why use Pois over other libraries?


so why use Pois over robust libraris like [pythonwhois](https://github.com/joepie91/python-whois), [pywhois](https://bitbucket.org/richardpenman/pywhois)...


1. Pois use all whois servers of all available tld so it whois domain with tld specific whois server (worth mention that linux whois utility is lack of get whois of new tld like .rocks)



2. Pois knows when a domain is available or not so if you whois an unregistered domain
 you get DomainNotFoundError (this come from parsing major whois servers response for an unvalid domain and make a pattern for it)



3. You can specify a timeout for whois operation, some whois servers after user quota exceeded for get whois just don't return
anything and won't close the connection.



4. Pois parse result and if find a Registrar whois server, re-whois that server to get complete whois (thick whois)



5. Pois use sockets so it's portable.



6. Pois return result in raw and nomalized format, in the latter you a get a clean dict of whois result.



*** tld whois severs provided from [weppos/whois](https://github.com/weppos/whois/)





## How use it



Download project and rename it to Pois then use it in you program like this:


```python

from Pois import Pois

try:

    result = Pois.fetch_whois(domain='github.com', timeout=5)
    print(result['raw'], result['normalized'])
    
except Exception as err:
    print(str(err))
    print(err.args)
    
```


## Exceptions


Pois return these exceptions that is self-described


```

TimeoutError, WhoisError, BadDomainError, DomainNotFoundError


```






