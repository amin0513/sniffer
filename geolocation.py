import requests
#mylog=0
#my_li=0
#g = geocoder.ip('me')
#mylog, my_li = g.latlng
def get_ip_country_info(ip):
    dataip={}
    a="Private_ip"
    ip_address=ip
    dataC="-"
    dataLo=0
    dataLi=0
    dataci='-'
    url = f"https://freeipapi.com/api/json/{ip_address}"
    response = requests.get(url).json()
    dataC = response['countryName']
    dataLo = response['latitude']
    dataLi = response['longitude']
    dataci=response['cityName']
    dataip['countryName']=dataC
    dataip['city']=dataci
    dataip['latitude']=dataLo
    dataip['longitude']=dataLi
    if dataC=='-':
        dataip['countryName']=a
        dataip['city']=a
        dataip['latitude']=0
        dataip['longitude']=0
    else:
        dataip['countryName']=dataC
        dataip['city']=dataci
        dataip['latitude']=dataLo
        dataip['longitude']=dataLi
    return dataip


if __name__=='__main__':
    print(get_ip_country_info('192.168.99.1'))