import requests

url = 'https://www.virustotal.com/vtapi/v2/file/scan'

params = {'apikey': '<apikey>'}

files = { "file": ("python-3.11.5-amd64.exe", open("python-3.11.5-amd64.exe", "rb"), "application/x-msdownload") }

response = requests.post(url, files=files, params=params)

response = response.json()

print(response['sha256'])