time_start=time.time()
reuseip=amun_df['attackerIP']
allip=temp['ip']
t=[1]
j=0
for i in range(1,len(reuseip)-1):
    if reuseip[i]==reuseip[i-1]:
        #temp['count']=j
        t.append(j)
    else:
        j=j+1
        t.append(j)
        #temp['count']=j
a=[]
j=0
f = lambda x: reader.get(x)['country'][u'names'][u'en'] if (reader.get(x) and ('country' in reader.get(x))) else "NaN"
#定义一个函数
#对应的序号的ip
for i in range(1,t[len(t)-1]):
    m = f(reuseip[t.index(i)])
    for j in range(1,t.index(i+1)-t.index(i)):
        a.append(m)
    if t.index(i+1)-t.index(i)==1:
        a.append(m)
    
time_end=time.time()
print('totally cost',time_end-time_start)
time_start=time.time()

amun_df['attackerCountry'] = amun_df['attackerIP'].apply(lambda x: reader.get(x)['country'][u'names'][u'en'] if (reader.get(x) and ('country' in reader.get(x))) else "NaN")

time_end=time.time()
print('totally cost',time_end-time_start)
