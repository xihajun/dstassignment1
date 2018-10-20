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

>import sys<br> 
>sys.path.append('Your package path') <br> 
>from geolite2 import geolite2 <br> 
>reader = geolite2.reader()<br> 
>reader.get('162.10.35.25')<br> 

It will return a data with this form:

>{'city': {'geoname_id': 5074472,
  'names': {'de': 'Omaha',
   'en': 'Omaha',
   'es': 'Omaha',
   'fr': 'Omaha',
   'ja': 'オマハ',
   'pt-BR': 'Omaha',
   'ru': 'Омаха',
   'zh-CN': '奥马哈'}},
 'continent': {'code': 'NA',
  'geoname_id': 6255149,
  'names': {'de': 'Nordamerika',
   'en': 'North America',
   'es': 'Norteamérica',
   'fr': 'Amérique du Nord',
   'ja': '北アメリカ',
   'pt-BR': 'América do Norte',
   'ru': 'Северная Америка',
   'zh-CN': '北美洲'}},
 'country': {'geoname_id': 6252001,
  'iso_code': 'US',
  'names': {'de': 'USA',
   'en': 'United States',
   'es': 'Estados Unidos',
   'fr': 'États-Unis',
   'ja': 'アメリカ合衆国',
   'pt-BR': 'Estados Unidos',
   'ru': 'США',
   'zh-CN': '美国'}},
 'location': {'accuracy_radius': 1000,
  'latitude': 41.3674,
  'longitude': -96.0454,
  'metro_code': 652,
  'time_zone': 'America/Chicago'},
 'postal': {'code': '68122'},
 'registered_country': {'geoname_id': 6252001,
  'iso_code': 'US',
  'names': {'de': 'USA',
   'en': 'United States',
   'es': 'Estados Unidos',
   'fr': 'États-Unis',
   'ja': 'アメリカ合衆国',
   'pt-BR': 'Estados Unidos',
   'ru': 'США',
   'zh-CN': '美国'}},
 'subdivisions': [{'geoname_id': 5073708,
   'iso_code': 'NE',
   'names': {'en': 'Nebraska',
    'es': 'Nebraska',
    'fr': 'Nebraska',
    'ja': 'ネブラスカ州',
    'pt-BR': 'Nebrasca',
    'ru': 'Небраска'}}]}

## 2. 
