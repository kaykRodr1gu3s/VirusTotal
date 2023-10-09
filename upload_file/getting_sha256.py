import requests



url = "https://www.virustotal.com/api/v3/files"

files = { "file": ("python-3.11.5-amd64.exe", open("python-3.11.5-amd64.exe", "rb"), "application/x-msdownload") }
headers = {
    "accept": "application/json",
    "x-apikey": "type here your api"
}

response = requests.post(url, files=files, headers=headers)

resp = response.json()

print(resp)