import requests
import os

api_key = 'type your API here'
file_name = 'example(python-3.11.5-amd64.exe)'

def get_sha256(api, file_name):


    endpoint = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api}
    files = { "file": (file_name, open(file_name, "rb"), "application/x-msdownload") }
    

    response = requests.post(endpoint, files=files, params=params)
    json = response.json()
    json = json['sha256']


    return json


id = get_sha256(api_key, file_name)


def file_behavior(api_key, id):
 
    url = f"https://www.virustotal.com/api/v3/files/{id}/behaviour_summary"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)

    datas_for_saved = response.json()

    return datas_for_saved


datas_for_saved = file_behavior(api_key, id) 
path = os.getcwd() + '\\files_behavior\\behavior'

names = ['files_attribute_changed' ,'files_deleted' ,'processes_created' ,
         'files_opened' ,'registry_keys_set' ,'text_highlighted' ,
         'modules_loaded' ,'registry_keys_opened' ,'ip_traffic' ,
         'processes_tree' ,'memory_dumps' ,'calls_highlighted' ,
         'files_written' ,'files_dropped' ,'command_executions']

with open(f'{path}\\behavior.txt', 'w') as f:
     for name in names:
          f.write('-='* 10 + name.replace('_', ' ') + '-='*20 + '\n')
          f.write(' \n')
          for c in datas_for_saved['data'][name]:
               f.write(f'{c}\n')

          f.write(' \n')