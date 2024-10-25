from flask import Flask, jsonify
from pymongo import MongoClient
from flask import Flask
import geocoder
from flask_cors import CORS
from bson.objectid import ObjectId
import requests
app = Flask(__name__)
CORS(app)  # Allow CORS for all routes

# MongoDB connection
client = MongoClient('mongodb+srv://amin:BBrXLIN1VzqF1H38@atlascluster.syhusk7.mongodb.net/')
db = client['Adtapter_visualization']
collection = db['WiFi2']
collection2 = db['newdataset']
collection3 = db['CVE_predictor']
g = geocoder.ip('me')
mylog, my_li = g.latlng


def get_cvss_score(cve_id):
    try:
        # API endpoint to get CVE details
        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        
        # Make the API request
        response = requests.get(url)
        
        # Check if the request was successful
        if response.status_code == 200:
            data = response.json()
            
            # Extract the CVSS score
            cvss_score = data.get('cvss')
            
            if cvss_score is not None:
                return cvss_score
            else:
                return "No CVSS score available"
        else:
            return f"Error: Unable to fetch data (Status code: {response.status_code})"
    except Exception as e:
        return f"Exception occurred: {str(e)}"


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
    if dataC=='-':
        dataip['countryName']=a
        dataip['city']=a
        dataip['latitude']=mylog
        dataip['longitude']=my_li
    else:
        dataip['countryName']=dataC
        dataip['city']=dataci
        dataip['latitude']=dataLo
        dataip['longitude']=dataLi
    return dataip


@app.route('/api/data', methods=['GET'])
def get_data():
    # Query MongoDB for data
    data = list(collection.find({}))  # You can add a query here if needed

    # Convert MongoDB documents to JSON
    json_data = []
    for item in data:
        json_data.append({
            'id': str(item['_id']),
            'src_ip': str(item['src_ip']),
            'dst_ip': str(item['dst_ip']),
            'src_country_name': str(item['src_country_name']),
            'des_country_name': str(item['des_country_name']),
            'src_latitude': item['src_latitude'],
            'src_longitude': item['src_longitude'],
            'des_latitude': item['des_latitude'],
            'des_longitude': item['des_longitude'],
            'src_port': item['src_port'],
            'dst_port': item['dst_port'],
            'service': item['service'],
            'date': item['date'],
            
            'src_city': item['src_city'],
            'des_city': item['des_city'],
            # Add more fields as needed src_city
        })

    return jsonify(json_data)

@app.route('/api/data2', methods=['GET'])
def get_data8():
    # Query MongoDB for data
    data = list(collection3.find({}))  # You can add a query here if needed

    # Convert MongoDB documents to JSON
    json_data = []
    for item in data:
        json_data.append({
            'id': str(item['_id']),
        'protocol_type': item['protocol_type'],
        'src_ip': str(item['src_ip']),
        'dst_ip': str(item['dst_ip']),
        'src_port': item['src_port'],
        'dst_port': item['dst_port'],
        'service': item['service'],
        'src_bytes': item['src_bytes'],
        'dst_bytes': item['dst_bytes'],
        'dst_host_diff_srv_rate': item['dst_host_diff_srv_rate'],
        'flag': item['flag'],
        'dst_host_srv_diff_host_rate': item['dst_host_srv_diff_host_rate'],
        'dst_host_srv_count': item['dst_host_srv_count'],
        'dst_host_same_src_port_rate': item['dst_host_same_src_port_rate'],
        'dst_host_same_srv_rate': item['dst_host_same_srv_rate'],
        'dst_host_count': item['dst_host_count'],
        'prediction': item['prediction'],
        
        'date': item['date']

            # Add more fields as needed src_city
        })

    return jsonify(json_data)


@app.route('/api/data/<id>', methods=['GET'])
def get_data_by_id(id):
    a=[]
    try:
        # Convert the string ID to an ObjectId
        object_id = ObjectId(id)
    except:
        return jsonify({"error": "Invalid ID format"}), 400

    # Query MongoDB for the document with the given ID
    data = collection3.find_one({'_id': object_id})
    s=data.get('src_ip')
    s2=data.get('dst_ip')
    don={'countryName': 'Singapore', 'city': 'Singapore', 'latitude': 1.289987, 'longitude': 103.850281}
    don2={'countryName': 'Private_ip', 'city': 'Private_ip', 'latitude': 33.5973, 'longitude': 73.0479}
    s=data.get('cve_id')
    for cve in s:
        q=get_cvss_score(cve)
        a.append(q)
    print(a)
        


    if not data:
        return jsonify({"error": "Record not found"}), 404

    # Convert the MongoDB document to JSON
    json_data = {
        'id': str(data['_id']),
        'protocol_type': data.get('protocol_type'),
        'src_ip': str(data.get('src_ip')),
        'dst_ip': str(data.get('dst_ip')),
        'src_port': data.get('src_port'),
        'dst_port': data.get('dst_port'),
        'service': data.get('service'),
        'src_bytes': data.get('src_bytes'),
        'dst_bytes': data.get('dst_bytes'),
        'dst_host_diff_srv_rate': data.get('dst_host_diff_srv_rate'),
        'flag': data.get('flag'),
        'dst_host_srv_diff_host_rate': data.get('dst_host_srv_diff_host_rate'),
        'dst_host_srv_count': data.get('dst_host_srv_count'),
        'dst_host_same_src_port_rate': data.get('dst_host_same_src_port_rate'),
        'dst_host_same_srv_rate': data.get('dst_host_same_srv_rate'),
        'dst_host_count': data.get('dst_host_count'),
        'prediction': data.get('prediction'),
        'cve_id':data.get('cve_id'),
        'src_long':don['longitude'],
        'src_lati':don['latitude'],
        'dst_long':don2['longitude'],
        'dst_lati':don2['latitude'],
        'src_country':don['countryName'],
        'src_city':don['city'],
        'dst_country':don2['countryName'],
        'dst_city':don2['city'],
        'cve_score':a,
        'date': data.get('date')

    }

    return jsonify(json_data)


@app.route('/api/distant_cities', methods=['GET'])
def get_distant_cities():
    # Query MongoDB collection for distant cities
    distant_cities = db.WiFi.distinct("src_country_name")
     # Count occurrences of each city
    city_counts = {}
    for city in distant_cities:
        count = collection.count_documents({"src_country_name": city})
        city_counts[city] = count

    return jsonify(city_counts)

@app.route('/api/distant_country', methods=['GET'])
def get_distant_country():
    # Query MongoDB collection for distant cities
    distant_cities = db.WiFi.distinct("des_country_name")
     # Count occurrences of each city
    city_counts = {}
    for city in distant_cities:
        count = collection.count_documents({"des_country_name": city})
        city_counts[city] = count

    return jsonify(city_counts)

@app.route('/api/predictions/count_normal', methods=['GET'])
def count_normal_predictions():
    # Count number of documents where prediction is 'normal'
    query = {'prediction': 'Normal'}
    count = collection2.count_documents(query)
    response = {'count': count}
    return jsonify(response), 200

@app.route('/api/predictions/count_ddos', methods=['GET'])
def count_ddos_predictions():
    # Count number of documents where prediction is 'normal'
    query = {'prediction': 'DDos'}
    count = collection2.count_documents(query)
    response = {'count': count}
    return jsonify(response), 200


@app.route('/api/predictions/count_u2l', methods=['GET'])
def count_u2l_predictions():
    # Count number of documents where prediction is 'normal'
    query = {'prediction': 'U2L'}
    count = collection2.count_documents(query)
    response = {'count': count}
    return jsonify(response), 200


@app.route('/api/predictions/count_r2l', methods=['GET'])
def count_r2l_predictions():
    # Count number of documents where prediction is 'normal'
    query = {'prediction': 'R2L'}
    count = collection2.count_documents(query)
    response = {'count': count}
    return jsonify(response), 200

@app.route('/api/predictions/count_probe', methods=['GET'])
def count_probe_predictions():
    # Count number of documents where prediction is 'normal'
    query = {'prediction': 'Probe'}
    count = collection2.count_documents(query)
    response = {'count': count}
    return jsonify(response), 200

if __name__ == '__main__':
    app.run(debug=True)
