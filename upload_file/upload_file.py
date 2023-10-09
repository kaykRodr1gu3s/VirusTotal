import requests
import os

api_key = 'api_key'
path = os.getcwd()+'\\python-3.11.5-amd64.exe'  # here you need to put the file.exe that you want to upload for get the data from them. in the example i put the python installer 

def getting_link(endpoint, path):
    global api_key


    files = { "file": ("the executable name(for example : python-3.11.5-amd64.exe) ", open(path, "rb"), "application/x-msdownload") }
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }



    # doing the request

    response = requests.post(endpoint, files=files, headers=headers)


    datas = response.json()


    # getting the id
    
    id = datas['data']['link']

    id = id['self']

    return id
    
path = ''   # the path where is your file
endpoint = 'https://www.virustotal.com/api/v3/files'
file = getting_link(endpoint, path)