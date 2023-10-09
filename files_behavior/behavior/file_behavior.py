import requests
import os

api_key = 'type your API here'
file_name = 'python-3.11.5-amd64.exe'

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
 
    url = f"https://www.virustotal.com/api/v3/files/{id }/behaviour_summary"
 
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
 
    response = requests.get(url, headers=headers)
 
    datas_for_saved = response.json()
 
    return datas_for_saved


datas_for_saved = file_behavior(api_key, id) 
path = os.getcwd() + '\\files_behavior\\behavior'


with open(f'{path}\\behavior.txt', 'w') as f:
    
    f.write('-='* 10 + 'files attribute changed' + '-='*20 + '\n')
    f.write(' \n')
    for c in datas_for_saved['data']['files_attribute_changed']:
        f.write(c + '\n')

    f.write(' \n')
    f.write('-='* 10 + 'files deleted' + '-='*20 + '\n')
    f.write(' \n')
    for c in datas_for_saved['data']['files_deleted']:
        f.write(c + '\n')
 
    f.write(' \n')
    f.write('-='* 10 + 'processes created' + '-='*20 + '\n')
    f.write(' \n')
    for c in datas_for_saved['data']['processes_created']:
        f.write(c + '\n')
 
    f.write(' \n')
    f.write('-='* 10 + 'files opened' + '-='*20 + '\n')
    f.write(' \n')
    for c in datas_for_saved['data']['files_opened']:
        f.write(c + '\n')

    f.write(' \n')
    f.write('-='* 10 + 'registry keys set' + '-='*20 + '\n')
    f.write(' \n')
    for c in datas_for_saved['data']['registry_keys_set']:
        f.write(f'{c}\n')
   
    f.write(' \n')
    f.write('-='* 10 + 'text highlighted' + '-='*20 + '\n')
    f.write(' \n')
    for c in datas_for_saved['data']['text_highlighted']:
         f.write(f'{c}\n')

    f.write(' \n')
    f.write('-='* 10 + 'modules loaded' + '-='*20 + '\n')
    f.write(' \n')
    for c in datas_for_saved['data']['modules_loaded']:
         f.write(f'{c}\n')

    f.write(' \n')
    f.write('-='* 10 + 'registry keys opened' + '-='*20 + '\n')
    f.write(' \n')
    for c in datas_for_saved['data']['registry_keys_opened']:
         f.write(f'{c}\n')

    f.write(' \n')
    f.write('-='* 10 + 'ip traffic' + '-='*20 + '\n')
    f.write(' \n')
    for c in datas_for_saved['data']['ip_traffic']:
         f.write(f'{c}\n')

    f.write(' \n') 
    f.write('-='* 10 + 'ip traffic' + '-='*20 + '\n')
    for c in datas_for_saved['data']['ip_traffic']:
         f.write(f'{c}\n')
     
    f.write(' \n')     
    f.write('-='* 10 + 'processes tree' + '-='*20 + '\n')
    f.write(' \n')
    for c in datas_for_saved['data']['processes_tree']:
         f.write(f'{c}\n')
    
    f.write(' \n')
    f.write('-='* 10 + 'memory dumps' + '-='*20 + '\n')
    for c in datas_for_saved['data']['memory_dumps']:
         f.write(f'{c}\n')

    f.write(' \n')
    f.write('-='* 10 + 'calls highlighted' + '-='*20 + '\n')
    f.write(' \n')
    for c in datas_for_saved['data']['calls_highlighted']:
         f.write(f'{c}\n')  

    f.write(' \n')
    f.write('-='* 10 + 'files written' + '-='*20 + '\n')
    f.write(' \n')
    for c in datas_for_saved['data']['files_written']:
         f.write(f'{c}\n')  
    
    f.write(' \n')
    f.write('-='* 10 + 'files dropped' + '-='*20 + '\n')
    f.write(' \n')
    for c in datas_for_saved['data']['files_dropped']:
         f.write(f'{c}\n')

    f.write(' \n')
    f.write('-='* 10 + 'command executions' + '-='*20 + '\n')
    f.write(' \n')
    for c in datas_for_saved['data']['command_executions']:
         f.write(f'{c}\n')