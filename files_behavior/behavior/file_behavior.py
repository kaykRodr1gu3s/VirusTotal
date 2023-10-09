import requests
import os


path = os.getcwd() + '\\files_behavior\\behavior'
url = "https://www.virustotal.com/api/v3/files/1bb46f65bb6f71b295801c8ff596bb5b69fa4c0645541db5f3d3bac33aa6eade/behaviour_summary"

api_key = 'type here your api'

headers = {
    "accept": "application/json",
    "x-apikey": "api_key"
}

response = requests.get(url, headers=headers)

datas_for_saved = response.json()



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