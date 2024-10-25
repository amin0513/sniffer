from pathlib import Path
from pymongo import MongoClient
import datetime

client=MongoClient("mongodb+srv://amin:BBrXLIN1VzqF1H38@atlascluster.syhusk7.mongodb.net/")
db=client.Adtapter_visualization


def save_data(data):
    collection=db['WiFi2']
    doc={
        "src_ip": data['src_ip'],
        "dst_ip" : data['dst_ip'],
        "src_country_name" : data['src_CountryName'],
        "des_country_name" : data['des_CountryName'],
        "src_latitude" : data['src_latitude'],
        "src_longitude" : data['src_longitude'],
        "des_latitude" : data['des_latitude'],
        "des_longitude" : data['des_longitude'],
        "src_city" : data['src_city'],
        "des_city" : data['des_city'],
        #"flag" : data['flag'],
        "src_port" : data['src_port'],
        "dst_port" : data['dst_port'],
        "service" :data['service'],
        "date":datetime.datetime.utcnow()
    }
    inserted=collection.insert_one(doc)
    return inserted.inserted_id
