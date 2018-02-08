# Pois
a Python wrapper for linux whois that return authentic domain information (not abuse)

## Why use it?
---
so why use Pois over other libraries? <br>

1. when you whois a gtold like .com you get a thin whois means no contact information will be returned, for get that information and get a thick whois you should whois domain with 
Registrar whois server, some whois clients in linux do it automatically but some win't<br>
Pois parse whois result and if found a Registrar whois server entry it will re-whois domain with that server
so you always get authentic result not abuse ones.

2. Pois has all whois servers of all available tld so it whois domain with tld specific whois server (worth mention that linux whois utility is lack of get whois of new tld like .rocks)

3. Pois return result in raw and nomalized format, in the latter you a get a clean dict of whois result.


4. not enogh!



## How use it
---


```python

from pois import Pois
Pois.check_whois_is_installed()
result = Pois.fetch_whois('knowclub.com')

```


you can pass timeout (in second) and whois_server, if whois_server is pass whois is perform on that server (no parsing take place for finding registrar whois server)



```python

Pois.check_whois_is_installed()
result = Pois.fetch_whois('knowclub.com', whois_server='whois.onlinenic.com', timeout=5)

```


and a complete example



```python
try:

    Pois.check_whois_is_installed()
    result = Pois.fetch_whois('knowclub.com', whois_server='whois.onlinenic.com', timeout=5)
    
except Exception as err:
    print(str(err))
    print(err.args)
```





