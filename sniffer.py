import pyfiglet
from geolocation import get_ip_country_info
from log import save_data
from scapy.all import IP, TCP, UDP, ICMP, sniff
from pathlib import Path

def check_access_attempt(packet):
    pattern = r'\((.*?)\)'
    data = {}
    datai={}
    datai1={}
    if IP in packet:
        data['src_ip'] = packet[IP].src
        data['dst_ip'] = packet[IP].dst
        a=packet[IP].src
        b=packet[IP].dst
        datai=get_ip_country_info(a)
        datai1=get_ip_country_info(b)
        data["src_CountryName"]=datai['countryName']
        data["des_CountryName"]=datai1['countryName']
        data['src_city']=datai['city']
        data['des_city']=datai1['city']
        data["src_latitude"]=datai['latitude']
        data["src_longitude"]=datai['longitude']
        data["des_latitude"]=datai1['latitude']
        data["des_longitude"]=datai1['longitude']
        if TCP in packet:
            data['flag'] = packet[TCP].flags      
            data['src_port'] = packet[TCP].sport
            data['dst_port'] = packet[TCP].dport
            data['service'] = packet[TCP].dport
        elif UDP in packet:
            data['flag'] = "UDP"
            data['src_port'] = packet[UDP].sport
            data['dst_port'] = packet[UDP].dport
            data['service'] = packet[TCP].dport 
        elif ICMP in packet:
            data['flag'] = "ICMP"
            
    #save_data(data)
    return data


packets = sniff(iface='Wi-Fi', prn=check_access_attempt, filter="tcp")



extracted_data = []


for packet in packets:    
    extracted_data.append(check_access_attempt(packet))

# Print the extracted data
for data in extracted_data:
    
    print(data)