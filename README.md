Data Science Toolbox Assignment 1
===
Data Science Toolbox Assignment 1
## Install Geoip
> pip install maxinddb-geolilte2


If it shows that the module doesn't exist, please try things below:<br> 

>import sys<br> 
>sys.path.append('/usr/lib/python3.6/site-packages') #Your package path<br> 
>from geolite2 import geolite2 <br> 
>reader = geolite2.reader()<br> 
>reader.get('162.10.35.25')<br> 

## Usage
Basic form:

> from geolite2 import geolite2 <br>
> reader.get('162.10.35.25')

It will return a data like this:
>

## 2. 
