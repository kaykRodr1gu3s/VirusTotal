import requests
import csv
import os


class MITRE_ATTACK:
    

    def __init__(self, API_KEY, file_name):
        """
        
        Api key must be your virustotal api, pass as argument       
        as second argument, put the file.exe name(example python-3.11.5-amd64.exe)

        """

        print('In init')
        print('-=' * 20)

        self.API_KEY = API_KEY
        self.base_endpoint = 'https://www.virustotal.com/'
        self.file_name = file_name


    def path(self):

        print('File created')
        print('-=' * 20)

        dir_name = os.getcwd() + '\\Main\\MITRE_ATT&CK'

        
        return dir_name
        


    def getting_sha256(self):
        params = {
            'apikey': self.API_KEY,
        }

        path = os.getcwd()+'\\' + self.file_name
        files = {'file': (f'{self.file_name}', open(path, 'rb'))}
        response = requests.post(self.base_endpoint + 'vtapi/v2/file/scan', files=files, params=params)

        data = response.json()
        
        
        identifier = data['sha256']
        
        return identifier   
    
    
    def Mitre(self):

        identifier = self.getting_sha256()
    
        headers = {
        "accept": "application/json",
        "x-apikey": self.API_KEY
                    }
    
        response = requests.get(self.base_endpoint + f'api/v3/files/{identifier}/behaviour_mitre_trees', headers=headers)
    
        json = response.json()
    
        json_response = json['data']
        
        return json_response
        

    def parsing(self):         

        sandboxes = []
        tat_tech = []
        instance = self.Mitre()    

        for key in instance:
            sandboxes.append(key)
    
        for sandbox in sandboxes:
    
            data_json = instance[sandbox]
            data_json = data_json['tactics']
           
            for value in data_json:    
    
                both_tat_tech = []
                tactics = []
                Techniques = []
        
                tactics.append(value['name'])
                tactics.append(value['id'])
                tactics.append(value['link'])
        
                both_tat_tech.append(tactics)        
    
                value = value['techniques']
                        
                for tec in value:
    
                    value = tec
                    Techniques.append(value['name'])
                    Techniques.append(value['id'])
                    Techniques.append(value['link'])
    
                    both_tat_tech.append(Techniques[:])
    
                    Techniques.clear()
    
                tat_tech.append(both_tat_tech)
        

        return tat_tech


    def file_behavior(self):

        id = self.getting_sha256()
        url = f"https://www.virustotal.com/api/v3/files/{id}/behaviour_summary"

        headers = {
            "accept": "application/json",
            "x-apikey": self.API_KEY
        }

        response = requests.get(url, headers=headers)

        datas_for_saved = response.json()

        return datas_for_saved




header = ['Name', 'Techniques/Tactics', 'Link(See on Mitre)']

api_key = str(input('type your api here: '))
print()
print('example (python-3.12.0-amd64.exe)')
file_name = str(input('put your file name: '))
mitre = MITRE_ATTACK(api_key,file_name)


create_file = ' '

while create_file not in 'YN':


    create_file = str(input("Do you wanna create a csv file with all data ?\ny = yes\nn = no\ntype here: ")).upper()

    if create_file in 'Y' or 'YES':
        
        print('-=' * 20)
        print('creating file...')
        print('saving the datas')

        path = os.getcwd() + '\\main\\csv_files'
        with open(f'{path}\\{mitre.file_name}_MITRE_ATT&CK.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(header)

            for list in mitre.parsing():
                for value in list:
                    writer.writerow(value)
        

    else:

        for list in mitre.parsing():
            
            for value in list:
                print(value)
cont = ' '

print('-=' * 20)
while  cont not in 'YN':
    cont = str(input("do you wanna save the file behavior ? \nit can take a litle bit time\ny = yes\nn=not"))
    path = os.getcwd() + '\\Main\\behavior'
    if cont in 'Y':
        print('creating file...')
        print('saving the datas')
        names = ['files_attribute_changed' ,'files_deleted' ,'processes_created' ,
                'files_opened' ,'registry_keys_set' ,'text_highlighted' ,
                'modules_loaded' ,'registry_keys_opened' ,'ip_traffic' ,
                'processes_tree' ,'memory_dumps' ,'calls_highlighted' ,
                'files_written' ,'files_dropped' ,'command_executions']



        with open(f'{path}\\{mitre.file_name}.txt', 'w') as f:
            for name in names:
                f.write('-='* 10 + name.replace('_', ' ') + '-='*20 + '\n')
                f.write(' \n')
                for c in mitre.file_behavior()['data'][name]:
                    f.write(f'{c}\n')

                f.write(' \n')
    else:
        print('You do not want to save the behavior in a text file!')
        break
print('All the data has been colected')