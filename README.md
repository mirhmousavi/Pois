# Pois
a Python wrapper for linux whois that return authentic domain information (not abuse)




## Why use Pois over other libraries?



1. when you whois a gtld like com you get a thin whois means no contact information will be returned, for get that information and get a thick whois you should whois domain with 
Registrar whois server, some whois clients in linux do it automatically but some won't<br>
Pois parse whois result and if found a Registrar whois server entry it will re-whois domain with that server
so you always get authentic result not abuse ones.

2. Pois use all whois servers of all available tld so it whois domain with tld specific whois server (worth mention that linux whois utility is lack of get whois of new tld like .rocks)

3. Pois return result in raw and nomalized format, in the latter you a get a clean dict of whois result.


4. not enogh!


* tld whois severs provided from [weppos/whois](https://github.com/weppos/whois/)




## How use it




```python

from pois import Pois
Pois.check_whois_is_installed()
result = Pois.fetch_whois('github.com')
print(result['raw'], ['normalized'])

```



you can pass timeout (in second) and whois_server, if whois_server is pass whois is perform on that server (no parsing take place for finding Registrar whois server)



```python

Pois.check_whois_is_installed()
result = Pois.fetch_whois('github.com', whois_server='whois.onlinenic.com', timeout=5)

```


and a complete example



```python

from pois import Pois

try:

    Pois.check_whois_is_installed()
    result = Pois.fetch_whois('github.com', whois_server='whois.onlinenic.com', timeout=5)
    print(result['raw'], ['normalized'])
    
except Exception as err:
    print(str(err))
    print(err.args)
    
```





