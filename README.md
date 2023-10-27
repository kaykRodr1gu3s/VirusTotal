# Virustotal

O Script realiza o upload de um arquivo .exe para a plataforma do VirusTotal, realizando pesquisas sobre este arquivo e coletando todos os seus comportamentos observados pela sandbox do VirusTotal, e táticas e técnicas do MITRE ATT&CK.

---


## Como usar 

### Necessários

* virustotal API KEY
* arquivo executável

### Como conseguir uma API KEY do virustotal
  Logo após fazer o login na plataforma do VirusTotal, vá até a aba de API KEY.

  ![Imagem do WhatsApp de 2023-10-26 à(s) 22 55 47_973bb533](https://github.com/kaykRodr1gu3s/VirusTotal/assets/110197812/8f5a8a2b-e8db-48ae-8ccd-4e9c9d935283)

### Arquivo 

* Para conseguir utilizar um arquivo diferente, sem ser o python-3.12.0-amd64.exe, basta apenas escolher um arquivo executável, e colocá-lo no mesmo diretorio de seu código. eu deixei o python-3.12.0-amd64.exe como apenas um exemplo



### executação do código 
Logo após você ter sua API e o executável estiver no diretório, basta apenas executar. Você precisará inserir a sua API e o nome do arquivo como entrada. Isso será mostrado em sua tela, e será possível ver um exemplo de como inserir o nome do seu executável.

Haverá possibilidade de salvar todas as táticas e técnicas do MITRE ATT&CK e seus respectivos nomes em um .csv. Haverá outra opção para ser escolhida para salvar o comportamento de seu arquivo em um .txt. 


# Como contribuir

clone o repositório , após fazer as suas mudanças, efetue um pull request.
