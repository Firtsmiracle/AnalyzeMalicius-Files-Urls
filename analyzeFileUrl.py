import requests
import os
import json
import sys
import signal
from colorama import init, Fore, Style

#Colores
blue = Fore.BLUE
yellow = Fore.YELLOW
red = Fore.RED
white = Fore.WHITE
green = Fore.GREEN
purple = Fore.MAGENTA
cyan = Fore.CYAN
reset = Style.RESET_ALL

# Configurar la clave de API de VirusTotal
API_KEY = 'Ingresa tu API key de Virus Total'

def def_handler(sig, frame):
    print(red + "\n\n[+] Saliendo...!\n" + reset)
    sys.exit(1)

#ctrl_c
signal.signal(signal.SIGINT, def_handler)

def check_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            file_content = f.read()
    except FileNotFoundError:
        print(red + "Error: archivo no encontrado" + reset)
        return
    
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files={'file': file_content}, params={'apikey': API_KEY})
    
    if response.status_code == 200:
        resource = response.json()['resource']
        while True:
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params={'apikey': API_KEY, 'resource': resource})
            json_response = response.json()
            if json_response['response_code'] == 1:
                break
        
        print(blue + "\nArchivo: " + green + f"{file_path}\n\n" +
              blue + "Detecciones positivas: " + green + f"{json_response['positives']}/{json_response['total']}\n\n" +
              blue + "Etiquetas de detección: " + green + f"{', '.join(json_response['scans'].keys())}\n\n" +
              blue + "Enlace al informe detallado: " + green + f"{json_response['permalink']}\n" + reset)
    else:
        print(red + "Error: no se pudo conectar a la API de VirusTotal" + reset)

os.system("clear")

print("""
 █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗██╗███████╗    ███╗   ███╗ █████╗ ██╗     ██╗ ██████╗██╗██╗   ██╗███████╗    
██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝██╔════╝██║██╔════╝    ████╗ ████║██╔══██╗██║     ██║██╔════╝██║██║   ██║██╔════╝    
███████║██╔██╗ ██║███████║██║   ╚████╔╝ ███████╗██║███████╗    ██╔████╔██║███████║██║     ██║██║     ██║██║   ██║███████╗    
██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝  ╚════██║██║╚════██║    ██║╚██╔╝██║██╔══██║██║     ██║██║     ██║██║   ██║╚════██║    
██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████║██║███████║    ██║ ╚═╝ ██║██║  ██║███████╗██║╚██████╗██║╚██████╔╝███████║    
╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚═╝╚══════╝    ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝╚═╝ ╚═════╝ ╚══════╝    
                                                                                                                             
                         ██╗███████╗██╗██╗     ███████╗    ██╗██╗   ██╗██████╗ ██╗     ██╗                                   
                        ██╔╝██╔════╝██║██║     ██╔════╝   ██╔╝██║   ██║██╔══██╗██║     ╚██╗                                  
                        ██║ █████╗  ██║██║     █████╗    ██╔╝ ██║   ██║██████╔╝██║      ██║                                  
                        ██║ ██╔══╝  ██║██║     ██╔══╝   ██╔╝  ██║   ██║██╔══██╗██║      ██║                                  
                        ╚██╗██║     ██║███████╗███████╗██╔╝   ╚██████╔╝██║  ██║███████╗██╔╝                                  
                         ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝     ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝                                   

        """)
option = input(yellow + "¿Qué desea analizar: una URL o un archivo?" + blue + " (u/a): " + reset)
while option not in ('u', 'a'):
    print(cyan + "Opción inválida. Intente nuevamente." + reset)
    option = input(yellow + "¿Qué desea comprobar: una URL o un archivo? (u/a): " + reset).lower()

if option == 'u':
    url = input(yellow + "Ingrese la URL que desea comprobar: " + reset)
    
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
    
    try:
        response = requests.get(url)
        response.raise_for_status()
    except:
        print(red + "\nError: URL no válida" + reset)
        exit()
    
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params={'apikey': API_KEY, 'resource': url})
    
    if response.status_code == 200:
        json_response = response.json()
        if json_response['response_code'] == 1:
            while json_response['response_code'] == -2:
                print("Análisis en curso. Espere unos segundos...")
                response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params={'apikey': API_KEY, 'resource': url})
                json_response = response.json()
            
            print(blue + "\nURL: " + green +  f"{url}\n\n" +
              blue + "Detecciones positivas: " + green + f"{json_response['positives']}/{json_response['total']}\n\n" +
              blue + "Etiquetas de detección: " + green + f"{', '.join(json_response['scans'].keys())}\n\n" +
              blue + "Enlace al informe detallado: " + green + f"{json_response['permalink']}\n" + reset)
        else:
            print(red + "Error: la URL no se ha analizado todavía" + reset)
    else:
        print(red + "Error: no se pudo conectar a la API de VirusTotal" + reset)

elif option == 'a':


    archivo_valido = False

    while not archivo_valido:
        file_path = input(yellow + "Ingrese el archivo que desea comprobar: " + reset)

        if os.path.isfile(file_path):
            archivo_valido = True
            check_file(file_path)
        else:
            print(cyan + "El archivo no existe o no se encuentra en la ruta ingresada. Intente nuevamente" + reset)
else:
    print(red + "Error: opción no válida" + reset)

