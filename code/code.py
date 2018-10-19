#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Oct 11 14:41:26 2018

@author: SydMacBook
"""

import pandas as pd
import json
import pylab
pylab.rcParams['figure.figsize'] = (16.0, 5.0)

"""
Importing and Data Cleaning
"""

f = open('honeypot.json', 'r')
count = 0
glastopf = []
amun = []
for line in f:
    j = json.loads(line)
    temp = []
    temp.append(j["_id"]["$oid"])
    temp.append(j["ident"])
    temp.append(j["normalized"])
    temp.append(j["timestamp"]["$date"])
    temp.append(j["channel"])
    payload = json.loads(j["payload"])
    if j["channel"] == "glastopf.events":
        temp.append(payload["pattern"])
        temp.append(payload["filename"])
        temp.append(payload["request_raw"])
        temp.append(payload["request_url"])
        temp.append(payload["source"][0])
        temp.append(payload["source"][1])
        glastopf.append(temp)
    elif j["channel"] == "amun.events":
        temp.append(payload["attackerIP"])
        temp.append(payload["attackerPort"])
        temp.append(payload["victimIP"])
        temp.append(payload["victimPort"])
        temp.append(payload["connectionType"])
        amun.append(temp)
    else:
        print(j)
f.close()

amun_df = pd.DataFrame(amun, columns=['id','ident','normalized','timestamp','channel','attackerIP','attackerPort','victimIP','victimPort','connectionType'])
glastopf_df = pd.DataFrame(glastopf, columns=['id','ident','normalized','timestamp','channel','pattern','filename','request_raw','request_url','attackerIP','attackerPort'])

amun_df['timestamp'] = amun_df['timestamp'].apply(lambda x: str(x).replace('T', 'T '))
glastopf_df['timestamp'] = glastopf_df['timestamp'].apply(lambda x: str(x).replace('T', 'T '))

amun_df['timestamp'] = pd.to_datetime(amun_df['timestamp'])
glastopf_df['timestamp'] = pd.to_datetime(glastopf_df['timestamp'])

"""
Augementing Data
"""

# Write function so that when key exists it returns country (google checking how key exists) or use a try accept

from geolite2 import geolite2

reader = geolite2.reader()

amun_df['attackerCountry'] = amun_df['attackerIP'].apply(lambda x: reader.get(x)['country'][u'names'][u'en'] if (reader.get(x) and ('country' in reader.get(x))) else "NaN")
glastopf_df['attackerCountry'] = glastopf_df['attackerIP'].apply(lambda x: reader.get(x)['country'][u'names'][u'en'] if reader.get(x) else "NaN")

#Victim Port 80 (http port so less secure)
# Add some other values provided by other honeypots to the glastopf dataframe
glastopf_df['victimPort'] = 80
glastopf_df['victimIP'] = 0
glastopf_df['victimIP'] = glastopf_df.ident.apply(lambda x: 'www.www.www.www' if x == 'a16f5f36-3c41-11e4-9ee4-0a0b6e7c3e9e' else 'yyy.yyy.yyy.yyy')

"""
Create a new dataframe with things that are common
Add back in 'attackerCountry'
"""

cols = ['channel','timestamp','attackerIP','victimPort','attackerCountry','ident','victimIP']
attacker_df = pd.DataFrame()
attacker_df = attacker_df.append(amun_df[cols], ignore_index=True)
attacker_df = attacker_df.append(glastopf_df[cols], ignore_index=True)

attacker_df = attacker_df.set_index('timestamp')

"""
What are the top 10 most active IPs in the attacker_df? 
What honeypot type picked up this attacker, and what port(s) was this attacker especially fond of.
"""

attacker_df['attackerIP'].value_counts().head(10)

"""
61.153.106.24      50212
71.190.176.162      9518
74.91.25.122        6386
194.63.142.218      5125
1.34.22.39          5111
165.225.157.188     4700
221.192.199.54      4593
204.188.195.74      4129
104.171.112.125     3713
37.203.214.134      3412
Name: attackerIP, dtype: int64
"""

print(attacker_df[attacker_df['attackerIP'] == '61.153.106.24']['channel'].unique())
amun_df[amun_df['attackerIP'] == '61.153.106.24']['victimPort'].unique()

"""
array([135])?
WHAT DOES THIS MEAN
"""

"""
Extract the User-Agent value from the honeypot data and create a column with the value. Then find most popular.
"""

import re

regex = re.compile('.*[Uu][Ss][Ee][Rr]-[Aa][Gg][Ee][Nn][Tt]:(.*?)(?:\\r|$)')
glastopf_df['user-agent'] = glastopf_df['request_raw'].apply(lambda x: re.search(regex, x).group(1) if re.search(regex, x) else None)

glastopf_df['user-agent'].value_counts()

"""
Find shell-shock attempts
"""

glastopf_df[glastopf_df['request_raw'].str.contains('{ :;}')]['request_raw'].value_counts()

"""
Try to pull out the urls that might host the most potential malware
"""

glastopf_df[glastopf_df['request_raw'].str.contains('};')]['request_raw'].apply(lambda x: x[x.find('http://'):x[x.find('http://'):].find(' ') + x.find('http://')] if x.find('http://') > 0 else 'a').unique()
    
"""
Looking for encoded requests and then attempts containing directory traversal
"""

glastopf_df[glastopf_df['request_raw'].str.contains('%')]['request_raw'].value_counts()

glastopf_df[glastopf_df['request_raw'].str.contains('\.\.')]['request_raw'].value_counts()
    
"""
Time Series Graphs
(MINE DOES DIFFERENT SCALE)
"""

"""
Total events over time
"""

import matplotlib.pyplot as plt

plt.plot(attacker_df['attackerIP'].resample("D", how='count'), label="Total Events")
plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)    
plt.show()

"""
Port activity over time
Cleaned up depriciated comment resample
"""

attacker_df['victimPort'] = attacker_df['victimPort'].astype(int)
for port in attacker_df['victimPort'].value_counts().index:
    if port < 10000:
        plt.plot(attacker_df[attacker_df == port]['victimPort'].resample("D").count(), label=str(port))
plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)    
plt.show()

"""
Non-Amun honeypot traffic and their associated ports.
"""

tempdf = attacker_df[attacker_df['channel'] != 'amun.events']
for port in tempdf['victimPort'].value_counts().index:
    plt.plot(tempdf[tempdf == port]['victimPort'].resample("D").count(), label=str(port))
plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)    
plt.show()

"""
Honeypot activity over time by honeypot type
"""

for channel in attacker_df['channel'].value_counts().index:
    plt.plot(attacker_df[attacker_df['channel'] == channel]['channel'].resample("D").count(), label=channel)
plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)    
plt.show()

"""
Individual honeypot activity over time
"""

for ident in attacker_df['ident'].value_counts().index:
    channel = attacker_df[attacker_df['ident'] == ident]['channel'].tolist()[0]
    a =  channel.split('.')[0]
    plt.plot(attacker_df[attacker_df['ident'] == ident]['ident'].resample("D").count(), label=a)
plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)    
plt.show()

"""
Just the glastopf honeypot activity over time.
"""

for ident in attacker_df['ident'].value_counts().index:
    channel = attacker_df[attacker_df['ident'] == ident]['channel'].tolist()[0]
    a =  channel.split('.')[0]
    if a != 'amun':
        plt.plot(attacker_df[attacker_df['ident'] == ident]['ident'].resample("D").count(), label=a)
plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)    
plt.show()

"""
Removed the most active attacker IP to look at how the rest of the top 10 behaved.
"""

for ip in attacker_df['attackerIP'].value_counts().index[1:10]:
    plt.plot(attacker_df[attacker_df['attackerIP'] == ip]['attackerIP'].resample("D").count(), label=ip)
plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)    
plt.show()

"""
Further eploration into attacker country
CAN"T DO ATM
"""

attacker_df['attackerCountry'].value_counts()[:20]

glastopf_df[glastopf_df['request_raw'].str.contains('};')]['attackerCountry'].value_counts()

"""
Learning vunerabilities people are scanning for from the URL
WAY LARGER NUMBERS THAN HIM (SOMETHING HAS NOT BEEN REMOVED?)
"""

glastopf_df['request_url'].value_counts()

glastopf_df[glastopf_df['request_raw'].str.contains('phpMyAdmin')]['request_url'].value_counts().head(20)

len(glastopf_df[glastopf_df['request_raw'].str.contains('phpMyAdmin')]['attackerIP'].unique())
# should be 10 and I get 33

for ip in glastopf_df[glastopf_df['request_raw'].str.contains('phpMyAdmin')]['attackerIP'].unique().tolist():
    print("%s - %s" %(ip, glastopf_df[glastopf_df['attackerIP'] == ip]['attackerCountry'].unique()))
# won't work as has attackerCountry in it

"""
See if any attackers were seen across multiple honeypots
"""

honeymap = {}
for ident in set(attacker_df.ident.tolist()):
    honeymap[ident] = {}
    honeymap[ident]['channel'] = list(set(attacker_df[attacker_df['ident'] == ident]['channel'].tolist()))[0]
    honeymap[ident]['ip'] = list(set(attacker_df[attacker_df['ident'] == ident]['victimIP'].tolist()))[0]

for ip in set(attacker_df['attackerIP'].tolist()):
    ids = set(attacker_df[attacker_df['attackerIP'] == ip]['ident'].tolist())
    if len(ids) > 1:
        temp = []
        for i in ids:
            temp.append(honeymap[i]['ip'] + ':' + honeymap[i]['channel'])
        temp = set(temp)
        if len(temp) > 3:
            print("%s seen across %d honeypots (%s) with %d connections" %(ip, len(temp), ", ".join(temp), attacker_df[attacker_df['attackerIP'] == ip].shape[0]))
    
#178.218.210.59
for ident in attacker_df[attacker_df.attackerIP == '178.218.210.59']['ident'].value_counts().index:
    channel = attacker_df[attacker_df['ident'] == ident]['channel'].tolist()[0]
    a =  channel.split('.')[0]
    plt.plot(attacker_df[attacker_df['ident'] == ident]['ident'].resample("D").count(), label=a)
plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)    
plt.show()

glastopf_df[glastopf_df.attackerIP == '178.218.210.59'].request_url.value_counts()

"""
Time Series Correlation
"""

"""
Are there countries that are active at the same time across the various honypots? The more red a square is the more the countries are correlated.
WON'T WORK BECAUSE OF COUNTRY
"""

cols = ['channel','timestamp','attackerIP','victimPort','attackerCountry','ident','victimIP']
adf = pd.DataFrame()
adf = adf.append(amun_df[cols], ignore_index=True)
adf = adf.append(glastopf_df[cols], ignore_index=True)
subset = adf[['timestamp','attackerCountry']]
subset['count'] = 1
subset = subset.set_index('timestamp')
pivot = pd.pivot_table(subset, values='count', index=subset.index, columns=['attackerCountry'], fill_value=0)

grouped = pivot.groupby([(lambda x: x.month), (lambda x: x.day)]).sum()

topN = subset['attackerCountry'].value_counts()[:20].index
corr_df = grouped[topN].corr()

import statsmodels.api as sm
corr_df.sort(axis=0, inplace=True) # Just sorting so exploits names are easy to find
corr_df.sort(axis=1, inplace=True)
corr_matrix = corr_df.as_matrix()
pylab.rcParams['figure.figsize'] = (10.0, 10.0)
sm.graphics.plot_corr(corr_matrix, ynames=corr_df.index.tolist(), xnames=corr_df.columns.tolist())
plt.show()

pylab.rcParams['figure.figsize'] = (14.0, 6.0)
print(grouped[['France','Germany','Russian Federation']].corr())
grouped[['France','Germany','Russian Federation']].plot()
pylab.ylabel('Probes')
pylab.xlabel('Date Scanned')

"""
IP Level not Country Level
ADD BACK IN attackerCountry TO cols
THIS PART MAKES KERNEL DIE
"""

cols = ['channel','timestamp','attackerIP','victimPort','ident','victimIP']
adf = pd.DataFrame()
adf = adf.append(amun_df[cols], ignore_index=True)
adf = adf.append(glastopf_df[cols], ignore_index=True)
subset = adf[['timestamp','attackerIP']]
subset['count'] = 1
subset = subset.set_index('timestamp')
pivot = pd.pivot_table(subset, values='count', index=subset.index, columns=['attackerIP'], fill_value=0)

grouped = pivot.groupby([(lambda x: x.month), (lambda x: x.day)]).sum()

topN = subset['attackerIP'].value_counts()[:20].index
corr_df = grouped[topN].corr()

import statsmodels.api as sm
corr_df.sort(axis=0, inplace=True) # Just sorting so exploits names are easy to find
corr_df.sort(axis=1, inplace=True)
corr_matrix = corr_df.as_matrix()
pylab.rcParams['figure.figsize'] = (10.0, 10.0)
sm.graphics.plot_corr(corr_matrix, ynames=corr_df.index.tolist(), xnames=corr_df.columns.tolist())
plt.show()

pylab.rcParams['figure.figsize'] = (14.0, 6.0)
print(grouped[['202.102.48.186','61.153.106.24','61.163.217.30','85.105.85.72','71.190.176.162','71.179.27.162']].corr())
grouped[['202.102.48.186','61.163.217.30','85.105.85.72','71.190.176.162','71.179.27.162']].plot()
pylab.ylabel('Probes')
pylab.xlabel('Date Scanned')
