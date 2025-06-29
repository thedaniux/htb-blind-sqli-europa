# Blind SQL Injection Script for OSWE

## Descripción
Este proyecto contiene un script en Python diseñado para realizar **inyección SQL ciega basada en tiempo** (Time-Based Blind SQL Injection) contra aplicaciones web vulnerables. El script automatiza la extracción de bases de datos, tablas, columnas y datos de una base de datos MySQL, explotando una vulnerabilidad en un formulario de login. Fue desarrollado como parte de mi preparación para el examen **Offensive Security Web Expert (OSWE)**, demostrando habilidades en explotación de vulnerabilidades web, automatización de ataques y análisis de bases de datos.

El script envía payloads SQL inyectados en el campo `email` de una solicitud POST, detectando respuestas basadas en retrasos de tiempo (usando `SLEEP`). Extrae:
- Nombres de bases de datos.
- Tablas de una base de datos seleccionada.
- Columnas de cada tabla.
- Valores de todas las columnas de cada tabla.

## Características
- **Automatización completa**: Extrae toda la estructura y datos de la base de datos sin intervención manual.
- **Inyección basada en tiempo**: Usa `SLEEP` para detectar respuestas, ideal para escenarios ciegos donde no hay salida visible.
- **Soporte para caracteres personalizados**: Configurable para diferentes conjuntos de caracteres.
- **Manejo de errores robusto**: Gestiona casos vacíos o errores en la conexión.
- **Progreso visual**: Usa la librería `pwn` para mostrar el progreso de la extracción.

## Requisitos
- **Python 3.6+**
- Librerías necesarias:
  ```bash
  pip install requests urllib3 pwntools
  ```
- Acceso a un servidor web vulnerable con un formulario de login que sea susceptible a inyección SQL.
- Conexión a internet estable (el script realiza múltiples solicitudes HTTP).

## Instalación
1. Clona el repositorio:
   ```bash
   git clone https://github.com/thedaniux/htb-blind-sqli-europa
   cd htb-blind-sqli-europa
   ```
2. Instala las dependencias:
   ```bash
   pip install -r requirements.txt
   ```
3. Configura la URL del objetivo en el archivo `blind_sqli.py`:
   ```python
   CONFIG = {
       'url': "http://admin.cronos.htb/",  # Cambia por tu URL vulnerable
       ...
   }
   ```

## Uso
1. Asegúrate de que el servidor vulnerable esté activo.
2. Ejecuta el script:
   ```bash
   python3 blind_sqli.py
   ```
3. El script:
   - Extraerá las bases de datos disponibles.
   - Seleccionará automáticamente una base de datos (excluyendo `information_schema`).
   - Listará las tablas y columnas.
   - Extraerá todos los valores de cada columna de cada tabla.
4. Ejemplo de salida:
   ```
   [*] Iniciando ataque de inyección SQL...
   [+] Bases de datos: ['information_schema', 'app']
   [*] Usando base de datos: app
   [+] Tablas: ['users', 'products']
   [*] Analizando tabla: users
   [+] Columnas: ['id', 'email', 'pass']
   [*] Extrayendo datos de la columna: id
   [+] Datos: [1, 2]
   [*] Extrayendo datos de la columna: email
   [+] Datos: ['admin@europacorp.htb', 'user@europacorp.htb']
   [*] Extrayendo datos de la columna: pass
   [+] Datos: ['hash123', 'hash456']
   [+] Resultados finales para tabla users:
   id: [1, 2]
   email: ['admin@europacorp.htb', 'user@europacorp.htb']
   pass: ['hash123', 'hash456']
   ```

## Detalles Técnicos
### Inyección SQL Ciega Basada en Tiempo
El script explota una vulnerabilidad en un formulario de login, inyectando payloads SQL en el campo `email`. Usa consultas como:
```sql
' AND IF(CONDITION,SLEEP(1),0)-- -
```
Si la condición es verdadera, el servidor espera 1 segundo (configurable en `CONFIG['sleep_time']`), lo que permite inferir información sin ver la salida directa.

### Flujo del Script
1. **Extracción de bases de datos**: Consulta `information_schema.schemata` para listar nombres de bases de datos.
2. **Selección de base de datos**: Elige la primera base de datos no-sistema (excluye `information_schema`).
3. **Extracción de tablas**: Usa `information_schema.tables` para listar tablas en la base de datos seleccionada.
4. **Extracción de columnas**: Obtiene nombres de columnas con `information_schema.columns`.
5. **Extracción de datos**: Itera sobre cada columna de cada tabla, extrayendo valores carácter por carácter.
   - **Conteo**: Determina cuántas filas hay.
   - **Longitudes**: Calcula la longitud de cada valor.
   - **Extracción**: Reconstruye los valores probando caracteres del conjunto definido en `CONFIG['charset']`.

### Estructura del Código
- **Configuración**: `CONFIG` define parámetros como la URL, tiempo de espera, y conjunto de caracteres.
- **Plantillas SQL**: `PAYLOADS` contiene las consultas SQL para cada etapa (`db`, `table`, `column`, `data`).
- **Funciones principales**:
  - `send_request`: Envía solicitudes HTTP con el payload.
  - `count_items`: Cuenta elementos (bases de datos, tablas, etc.).
  - `get_name_lengths`: Calcula longitudes de nombres.
  - `extract_names`: Extrae valores carácter por carácter.
  - `extract_data`: Orquesta el proceso de extracción.
  - `main`: Ejecuta el flujo completo.

## Notas para el Examen OSWE
Este script refleja habilidades clave para la OSWE:
- **Análisis de vulnerabilidades**: Identificación y explotación de inyección SQL ciega.
- **Automatización**: Escritura de scripts para automatizar ataques complejos.
- **Comprensión de bases de datos**: Uso de `information_schema` para mapear la estructura de la base de datos.
- **Manejo de payloads**: Construcción de consultas SQL seguras y efectivas.
- **Robustez**: Gestión de errores y casos extremos.

El script fue probado en un entorno controlado, simulando escenarios del examen OSWE, como los labs de Offensive Security.

## Aviso Legal
Este script es para **fines educativos y de investigación** únicamente. El uso no autorizado contra sistemas sin permiso expreso es ilegal y va en contra de la ética de ciberseguridad. Asegúrate de tener autorización antes de probarlo en cualquier sistema. El autor no se responsabiliza por el mal uso de esta herramienta.

## Contribuciones
Este es un proyecto personal para la OSWE, pero si tienes sugerencias o mejoras, ¡abre un issue o un pull request!
