#!/usr/bin/env python
# coding: utf-8

# In[148]:


import pandas as pd
import numpy as np
import dataframe_image as dfi


# In[149]:


# generating df for summary data 
try: 
    f = open('./425outs/425-test-s.out', "r")
    lines = f.readlines()
finally:  
    f.close()

# remove /n at the end of each line
data = []
for index, line in enumerate(lines):
    lines[index] = line.strip()
    row = lines[index].split(':')
    data.append(row)

summary_df = pd.DataFrame(data, columns=["Summary", "Data"])
summary_df


# In[150]:


try: 
    f = open('./425outs/425-test-m.out', "r")
    lines = f.readlines()
finally:  
    f.close()
data = []
for index, line in enumerate(lines):
    lines[index] = line.strip()
    row = lines[index].split(' ')
    data.append(row)

traffic_df = pd.DataFrame(data, columns=['Source_IP', 'Dest_IP', 'Total_Payload'])
traffic_df["Total_Payload"] = pd.to_numeric(traffic_df["Total_Payload"])
traffic_df.nlargest(5, 'Total_Payload')


# In[151]:


dfi.export(traffic_df.nlargest(5, 'Total_Payload'),"largest.png")


# In[152]:


try: 
    f = open('./425outs/425-test-l.out', "r")
    lines = f.readlines()
finally:  
    f.close()
data = []
for index, line in enumerate(lines):
    lines[index] = line.strip()
    row = lines[index].split(' ')
    data.append(row)

length_df = pd.DataFrame(data, columns=['Timestamp', 'Caplen', 'IP_len', 'IP_hl', 'Transport', 'Transport_hl', 'Payload_len'])


# In[153]:


num_of_tcp_pkts = length_df['Transport'].value_counts()['T']
num_of_udp_pkts = length_df['Transport'].value_counts()['U']
num_of_other_protocol_pkts = length_df['Transport'].value_counts()['?']
num_of_without_ip_header_pkts = len(length_df[length_df.Transport== '-'])
rows = ['TCP PACKETS', 'UDP PACKETS', 'OTHER PROTOCOL PACKETS', 'PACKETS WITHOUT IP HEADER', 'TOTAL PACKETS']
values = [num_of_tcp_pkts, num_of_udp_pkts, num_of_other_protocol_pkts, num_of_without_ip_header_pkts]
values.append(sum(values))
d = {'Key Findings': rows, 'Count': values}
pckt_analysis_df = pd.DataFrame(d)
pckt_analysis_df


# In[154]:


dfi.export(pckt_analysis_df,"packet_analysis.png")
dfi.export(summary_df, "summary.png")


# In[155]:


try: 
    f = open('./425outs/425-test-p.out', "r")
    lines = f.readlines()
finally:  
    f.close()
data = []
for index, line in enumerate(lines):
    lines[index] = line.strip()
    row = lines[index].split(' ')
    data.append(row)

tcp_packets_df = pd.DataFrame(data, columns=['Timestamp', 'Src_ip', 'Dest_ip', 'IP_ttl', 'SRC_PORT', 'DST_PORT', 'Window', 'SEQNO', 'ACKNO'])
tcp_packets_df["SRC_PORT"] = pd.to_numeric(tcp_packets_df["SRC_PORT"])
tcp_packets_df["DST_PORT"] = pd.to_numeric(tcp_packets_df["DST_PORT"])
tcp_packets_df["IP_ttl"] = pd.to_numeric(tcp_packets_df["IP_ttl"])
tcp_packets_df["Window"] = pd.to_numeric(tcp_packets_df["Window"])


# In[156]:


num_of_src_80 = len(tcp_packets_df[tcp_packets_df.SRC_PORT== 80])
num_of_dest_80 = len(tcp_packets_df[tcp_packets_df.DST_PORT== 80])
num_of_src_80


# In[157]:


num_of_dest_80

