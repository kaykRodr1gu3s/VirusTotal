import requests
import csv
import os





endpoint = "https://www.virustotal.com/api/v3/files/1bb46f65bb6f71b295801c8ff596bb5b69fa4c0645541db5f3d3bac33aa6eade/behaviour_mitre_trees"


def mkdir():
    dir_name = os.getcwd() + '\\upload_file'
    folder_name = 'files_Results'
    folder_path = os.path.join(dir_name, folder_name)



    if not os.path.exists(folder_path):
        os.mkdir(folder_path)
        print('Folder created')



    else:
        print('Folder already exist')


    path = os.getcwd() +'\\upload_file\\files_Results'

    return path



def request(endpoint):




    headers = {
        "accept": "application/json",
        "x-apikey": "api_key"
    }




    response = requests.get(endpoint, headers=headers)
    json = response.json()


    return json



req = request(endpoint)


json_response = req['data']


def parsing(json_response): 
    sandboxes = []


    tat_tech = []


    for key in json_response.keys():
        sandboxes.append(key)


    for sandbox in sandboxes:


        data_json = json_response[sandbox]
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
  
parser = parsing(json_response)
 


header = ['Name', 'Techniques/Tactics', 'Link(See on Mitre)']


with open(f'{mkdir()}\\MITRE_ATT&CK.csv', 'w', newline='') as f:
 
 
    writer = csv.writer(f)
    writer.writerow(header)
 
 
    for list in parser:


        for value in list:
            
            writer.writerow(value)