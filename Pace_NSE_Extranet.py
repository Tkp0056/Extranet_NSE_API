import csv
import os
from datetime import datetime, timezone
import json
import time
import django
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from django.utils.encoding import force_bytes, force_str
import requests

SECRET_KEY = "3MVtwzMgweao/nmQYnacZUqz5c80OxUKRO23BXP9m2A="
value = force_bytes("Pacefin@8181")
backend = default_backend()
key= force_bytes(base64.urlsafe_b64decode(SECRET_KEY))


class Crypto:
    def __init__(self):
        self.encryptor = Cipher(algorithms.AES(key), modes.ECB(), backend).encryptor()
        self.decryptor = Cipher(algorithms.AES(key), modes.ECB(), backend).decryptor()


    def encrypt(self):
        padder = padding.PKCS7(algorithms.AES(key).block_size).padder()
        padded_data = padder.update(value) + padder.finalize()
        encrypted_text = self.encryptor.update(padded_data) + self.encryptor.finalize()
        return encrypted_text
    

    def decrypt(self, value):
        padder = padding.PKCS7(algorithms.AES(key).block_size).unpadder()
        decrypted_data = self.decryptor.update(value)
        unpadded = padder.update(decrypted_data) + padder.finalize()
        return unpadded


# Function to generate a new token
def generate_token():
    crypto = Crypto()
    crypto_text = force_str(base64.urlsafe_b64encode(crypto.encrypt()))

    payload = {
    "memberCode":"90326",
    "loginId":"PULKIT",
    "password":"AiTsdxeCVtQIY9-0krrZXg=="
    }
    headers = {"Content-Type": "application/json"}

    url="https://www.connect2nse.com/extranet-api/login/2.0/"
    r = requests.post(url, json=payload, headers=headers)
    if r.status_code == 200:
        r_json = r.json()
        token = r_json['token']
        print("Token generated:", token)
        return token
    else:
        print(f"Failed to generate token: {r.status_code}")
        return None


# Function to download files using the generated token
def download_files(token):
    filtered_data=[]
    today_date = datetime.now(timezone.utc).date()
    current_date = datetime.now().strftime('%d-%m-%Y')
    members = ["FO", "CM"]
    paths = ['/Reports']
    dir_path ="D:\\Pocketful"
    
    def file_records(filtered_data,member,folder_name):
        file_name = 'file_records_{}.csv'.format(current_date)
        new_path = os.path.join(dir_path, member)
        os.makedirs(new_path, exist_ok=True)
        if (folder_name!="Reports"):
            new_path=os.path.join(new_path,folder_name) 
            os.makedirs(new_path, exist_ok=True)
        file_path = os.path.join(new_path,file_name)
        with open(file_path, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Name', 'Last Updated'])
            for item in filtered_data:
                writer.writerow([item.get('name'), item.get('lastUpdated')])                
        print("Record file {} of  successfully".format(folder_name,new_path))
  
    def content_folder(updated_url,member,folder_name,folder_path):
        global filtered_data
        headers = {'Authorization': 'Bearer ' + token}
        response = requests.get(updated_url, headers=headers)
        if response.status_code == 200:
            #print(response)
            data=response.content
            #print(data)
            json_data=json.loads(data.decode('utf-8'))
            for item in json_data['data']:          
                item['lastUpdated'] = datetime.fromisoformat(item['lastUpdated'])
            filtered_data = [item for item in json_data['data'] if item['lastUpdated'].date() == today_date]
            if filtered_data!=[]:
                file_records(filtered_data,member,folder_name)
                for item in filtered_data:
                    if item.get("type")=="File":
                        file_name=item.get('name')
                        download_folder(file_name,member,folder_path,folder_name)

        else:
            # If the request is unsuccessful, print the status code and the error message
            print(f'Request failed with status code {response.status_code}: {response.text}')
            print("Problem in getting content",folder_path,folder_name)
        print("All Files of folder {0} of member {1} has been downloaded".format(folder_name,member))


    def download_folder(file_name,member,folder_path,folder_name):
        global count
        new_path = os.path.join(dir_path, member)
        os.makedirs(new_path, exist_ok=True)
        download_url="https://www.connect2nse.com/extranet-api/member/file/download/2.0?segment={0}&folderPath={1}&filename={2}".format(member,folder_path,file_name)
        headers = {'Authorization': 'Bearer ' + token}
        response = requests.get(download_url, headers=headers)
        if response.status_code == 200:
            data=response.content
            #print(response)
            try:
                folder_name=folder_path.split("/")[2]
                new_path = os.path.join(new_path, folder_name)
                os.makedirs(new_path, exist_ok=True)
                file_path = os.path.join(new_path,file_name)
                with open(file_path, "wb") as f:
                    f.write(data)
            except (ValueError,IndexError):
                count+=1
                file_path = os.path.join(new_path,file_name)
                with open(file_path, "wb") as f:
                    f.write(data)

        else:
            # If the request is unsuccessful, print the status code and the error message
            print(f'Request failed with status code {response.status_code}: {response.text}')
            print("Problem in downloading",folder_path,folder_name)

    for path in paths:
        for member in members:
            global count
            count=0
            dummy_url="https://www.connect2nse.com/extranet-api/member/content/2.0?segment=exchange&folderPath=path&date=current_date"
            content_url=dummy_url.replace("exchange",member).replace("path",path).replace("current_date",current_date)
            headers = {'Authorization': 'Bearer ' + token}
            response = requests.get(content_url, headers=headers)
            if response.status_code == 200:
                #print(response)
                data=response.content
                #print(data)
                json_data=json.loads(data.decode('utf-8'))
                for item in json_data['data']:
                    if item.get("type")=="Folder":
                        folder_name=item.get("name")
                        folder_path="/"+item.get("folderPath")+folder_name
                        updated_url=dummy_url.replace("path",folder_path).replace("exchange",member).replace("current_date",current_date)
                        content_folder(updated_url,member,folder_name,folder_path)
                    elif item.get("type")=="File":
                        file_path=path
                        folder_name=path.split("/")[1]
                        content_folder(content_url,member,folder_name,file_path)
                        break

            else:
                # If the request is unsuccessful, print the status code and the error message
                print(f'Request failed with status code {response.status_code}: {response.text}')  

            print("All files downloaded of member {} number {}".format(member,count))           


while True:
    token = generate_token()

    if token:
        # Download files using the generated token
        download_files(token)

    # Wait for 2 hours before generating the token again
    time.sleep(3600)  
