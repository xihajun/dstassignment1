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
    try:
        payload = json.loads(j["payload"])
    except:
        payload = j["payload"]
        print(payload)  
    #payload = json.loads(j["payload"]) is not work for H's laptop
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

#Avoiding reusing ip addresses
amun_df['country']=0
glastopf_df['country']=0

#temp variables
temp = set(amun_df['attackerIP'])
x = list(temp)
temp2 = pd.DataFrame(x, columns = ['ip'])

count = 0
try:
    amun_df.country[A]='test'
except:
    print 'error'

#
count = 0
for i in temp2['ip']:
    # 批量赋值
    #查找第一个ip在大数据表中对应的行
    T = amun_df.attackerIP==i # and amun_df.iloc[count,10]):
    A = [j for j in range(len(T)) if T[j]==True]
    if reader.get(i) and reader.get(i)['registered_country']:
        amun_df.country[A]=reader.get(i)['registered_country']['names']['en']
    else:
        amun_df.country[A]='Unknow'
