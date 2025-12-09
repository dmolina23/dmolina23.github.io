---
title: Ingeniería Inversa a la Mi Band 4. Descifrando su Protocolo BLE para Tomar el Control de los Sensores.
date: 2025-12-09
categories:
    - Reverse Engineering
    - IoT
    - DIY
tags:
    - IoT
    - Bluetooth
    - BLE
    - Middleware
img_path: /assets/img/commons/miband/
image: miband.jpg
---

Los dispositivos IoT, como las pulseras de actividad, son cajas negras para la mayoría de los usuarios. Funcionan, pero ¿cómo? ¿Qué secretos guardan sus protocolos de comunicación? A veces, para construir, primero hay que deconstruir.

Este post es un caso práctico de ingeniería inversa. Vamos a darle una segunda vida a una _Mi Band 4_, no solo para usarla, sino para entenderla.

Nuestro objetivo final: interceptar y utilizar los datos de sus sensores directamente desde un PC con Linux, sentando las bases para crear una herramienta de control por gestos.

Para ello, nos sumergiremos en el protocolo Bluetooth Low Energy (BLE), descifraremos su mecanismo de autenticación y escribiremos un script en Python que nos dará el control.


## Entendiendo BLE y el Protocolo GATT
---
Antes de escribir una sola línea de código, debemos entender el lenguaje en el que hablan los dispositivos IoT. La _Mi Band 4_ utiliza Bluetooth Low Energy (BLE), un protocolo diseñado para la comunicación de bajo ancho de banda y consumo energético mínimo.

En una conexión BLE, tenemos dos roles:
* **Central** (Nuestro PC): El dispositivo que inicia la conexión y solicita los datos.
* **Periférico** (La _Mi Band 4_): El dispositivo que ofrece los datos y espera conexiones.

La comunicación de datos sobre BLE no es un flujo caótico, está estructurada por un reglamento llamado **GATT** (Generic Attribute Profile). La mejor forma de entender **GATT** es imaginarlo como un sistema de archivos simple:
* **Servicios** (Carpetas): Un Servicio agrupa funcionalidades relacionadas. Por ejemplo, la Mi Band tiene un "Servicio de Batería", un "Servicio de Ritmo Cardíaco", etc. Cada servicio se identifica por un UUID (Universally Unique Identifier), que es su dirección única.
* **Características** (Archivos): Dentro de cada Servicio, hay una o más Características. Estas contienen los datos reales. El "Servicio de Batería" (`UUID 0x180F`) contiene una "Característica de Nivel de Batería" (`UUID 0x2A19`), cuyo valor es un byte que representa el porcentaje de 0 a 100.

Nuestro objetivo es, por tanto, navegar por este "sistema de archivos" GATT para leer el "archivo" que contiene el dato que nos interesa. Pero antes, necesitamos permiso para acceder.

## La Auth Key y el Proceso de Autenticación
---

Aquí es donde entra en juego la ingeniería inversa. Los fabricantes no quieren que cualquiera pueda conectarse y leer datos sensibles (como tu ritmo cardíaco). Para evitarlo, la _Mi Band 4_ implementa un mecanismo de autenticación que depende de una Clave de Autenticación (**Auth Key**)

### ¿Qué es y cómo funciona la Auth Key?
La **Auth Key** es un secreto compartido de 16 bytes (32 caracteres hexadecimales) que se genera durante el primer emparejamiento entre la pulsera y la aplicación oficial (ej. Zepp Life). Una vez generada, se almacena tanto en el teléfono como en la pulsera.

> **💡 Tip**: A pesar de almacenarse en el teléfono, no podemos acceder a ella si no tenemos un teléfono _rooteado_.

El proceso de autenticación en cada nueva conexión funciona así:
1. **Conexión Inicial**: Nuestro script (el Central) establece una conexión BLE básica con la pulsera (el Periférico).
2. **El Desafío**: La pulsera bloquea el acceso a la mayoría de sus servicios GATT y nos envía un "desafío": un número aleatorio.
3. **La Respuesta**: Nuestro script debe tomar ese número aleatorio y cifrarlo utilizando un algoritmo (normalmente AES/ECB) con la **Auth Key** como clave secreta. El resultado cifrado se envía de vuelta a la pulsera a través de una característica específica de autenticación.
4. **Verificación**: La pulsera realiza exactamente la misma operación de cifrado en su lado con su copia de la Auth Key.
5. **Acceso Concedido**: Si su resultado coincide con el que le hemos enviado, la pulsera considera que somos un dispositivo de confianza y "desbloquea" el acceso a los servicios protegidos.

Sin esta clave, cualquier intento de leer datos sensibles será rechazado. Nuestro script, por tanto, debe "suplantar" a la aplicación oficial presentando la clave correcta.

### ¿Cómo Obtenemos la Clave? (El "Hackeo")
Aquí es donde aplicamos técnicas de ingeniería inversa para extraer la clave del ecosistema cerrado de la app:
* **Análisis de la Base de Datos** (Requiere Root): En un dispositivo Android rooteado, la app oficial almacena la **Auth Key** en una base de datos SQLite local, sin cifrar. Es posible acceder al sistema de archivos del teléfono y extraerla directamente.
* **Aplicaciones Modificadas**: La comunidad ha descompilado la app oficial, inyectado código para que escriba la **Auth Key** en un archivo de texto en un directorio accesible, y la ha vuelto a compilar. Usar estas apps es el método más común, pero conlleva un riesgo de seguridad, ya que confías en código de terceros.
* **Sniffing de Tráfico BLE (Avanzado)**: Sería posible capturar el intercambio de la clave durante el emparejamiento inicial. Sin embargo, los protocolos de emparejamiento modernos como LE Secure Connections utilizan criptografía de clave pública para proteger este intercambio, haciendo este método muy complejo.

## Conexión y Script
---
Ahora que entendemos el funcionamiento de nuestra pulsera, vamos a la práctica.

### Preparando el Entorno en Ubuntu
Instalamos las dependencias para la comunicación BLE en Python:

```bash
sudo apt-get update
sudo apt-get install libglib2.0-dev
pip install bleak cryptography
```

### Reconocimiento: Encontrando la Dirección MAC
Necesitamos la dirección del objetivo. Con el Bluetooth de tu móvil desactivado para que la pulsera sea visible, ejecutamos un escaneo:

```bash
sudo hcitool lescan
```

Busca la línea de _Mi Smart Band 4_ y anota su dirección MAC (XX:XX:XX:XX:XX:XX).


### PoC: El Script para Leer la Batería
Este script será nuestra prueba de concepto (Proof of Concept). Demostrará que hemos logrado la autenticación y podemos leer datos:

```python
import asyncio
import logging
import struct
from bleak import BleakClient, BleakScanner
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- CONFIGURACIÓN ---
# REEMPLAZA ESTO CON TUS DATOS REALES
MAC_ADDRESS = "XX:XX:XX:XX:XX:XX" 
AUTH_KEY_HEX = "8f3a2b..." # Tu clave de 32 caracteres hex (ej. '8f3a2b4c...')

# --- UUIDs DE LA MI BAND 4 ---
# UUIDs Base de Huami
UUID_SERVICE_MIBAND2 = "0000fee1-0000-1000-8000-00805f9b34fb"
UUID_CHAR_AUTH = "00000009-0000-3512-2118-0009af100700"

UUID_SERVICE_MIBAND1 = "0000fee0-0000-1000-8000-00805f9b34fb"
# Característica específica de Xiaomi para info detallada de batería (no la estándar 0x2a19)
UUID_CHAR_BATTERY = "00000006-0000-3512-2118-0009af100700"

# --- CONSTANTES DEL PROTOCOLO ---
AUTH_SEND_KEY = b'\x01\x00'
AUTH_REQUEST_RANDOM_AUTH_NUMBER = b'\x02\x00'
AUTH_SEND_ENCRYPTED_AUTH_NUMBER = b'\x03\x00'
AUTH_RESPONSE = b'\x10'
AUTH_SUCCESS = b'\x01'
AUTH_FAIL = b'\x04'

# Configuración de Logs
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MiBandMiddleware:
    def __init__(self, mac, auth_key):
        self.mac = mac
        self.auth_key = bytes.fromhex(auth_key)
        self.client = None
        self.auth_event = asyncio.Event() # Para esperar respuesta de la pulsera
        self.auth_success = False

    def encrypt_aes(self, data):
        """Cifra los datos usando AES ECB con la Auth Key."""
        cipher = Cipher(algorithms.AES(self.auth_key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    async def notification_handler(self, sender, data):
        """Maneja las notificaciones de la pulsera (Callback)."""
        # La pulsera responde con prefijo \x10
        if data.startswith(AUTH_RESPONSE):
            # UUID_CHAR_AUTH response
            cmd_id = data[1]
            status = data[2]
            
            if cmd_id == 2 and status == 1: 
                # Respuesta a Solicitud de Aleatorio (0x02) -> Nos da el número random
                logger.info("Recibido número aleatorio de la pulsera.")
                random_number = data[3:]
                
                # Ciframos el número y lo enviamos de vuelta
                encrypted_number = self.encrypt_aes(random_number)
                payload = AUTH_SEND_ENCRYPTED_AUTH_NUMBER + encrypted_number
                logger.info("Enviando desafío cifrado...")
                await self.client.write_gatt_char(UUID_CHAR_AUTH, payload)
                
            elif cmd_id == 3 and status == 1:
                # Respuesta a Envío Cifrado (0x03) -> Éxito
                logger.info("¡Autenticación Exitosa!")
                self.auth_success = True
                self.auth_event.set()
                
            elif status == 4:
                logger.error("Error de autenticación: Clave incorrecta o error en el handshake.")
                self.auth_success = False
                self.auth_event.set()

    async def authenticate(self):
        """Realiza el flujo de autenticación."""
        logger.info("Iniciando autenticación...")
        
        # 1. Suscribirse a notificaciones de autenticación
        await self.client.start_notify(UUID_CHAR_AUTH, self.notification_handler)
        
        # 2. Solicitar número aleatorio
        # Nota: Si es la primera vez absoluta, se enviaría AUTH_SEND_KEY, 
        # pero asumimos que ya tienes la KEY y la pulsera está 'pairada' lógicamente.
        logger.info("Solicitando número aleatorio...")
        await self.client.write_gatt_char(UUID_CHAR_AUTH, AUTH_REQUEST_RANDOM_AUTH_NUMBER)
        
        # 3. Esperar a que el handler procese la lógica
        try:
            await asyncio.wait_for(self.auth_event.wait(), timeout=10.0)
        except asyncio.TimeoutError:
            logger.error("Tiempo de espera de autenticación agotado.")
            return False
            
        return self.auth_success

    async def read_battery(self):
        """Lee el estado de la batería una vez autenticado."""
        if not self.auth_success:
            logger.error("No se puede leer batería sin autenticación.")
            return

        logger.info("Leyendo datos de batería...")
        # Leemos la característica propietaria 0x0006
        battery_data = await self.client.read_gatt_char(UUID_CHAR_BATTERY)
        
        # Parseo de datos para Mi Band 4 (Firmware v1.0.9.x)
        # Estructura usual: [Nivel, Estado, UltimaCarga?, ...]
        level = battery_data[1]
        status_byte = battery_data[2]
        
        status_str = "Desconocido"
        if status_byte == 0: status_str = "Normal"
        elif status_byte == 1: status_str = "Cargando"
        
        logger.info(f"--- ESTADO BATERÍA ---")
        logger.info(f"Nivel: {level}%")
        logger.info(f"Estado: {status_str}")
        logger.info(f"Raw Data: {battery_data.hex()}")

    async def run(self):
        logger.info(f"Conectando a {self.mac}...")
        
        async with BleakClient(self.mac) as client:
            self.client = client
            if client.is_connected:
                logger.info("Conectado. Verificando servicios...")
                
                # Paso 1: Autenticar
                if await self.authenticate():
                    # Paso 2: Leer Sensores/Batería
                    await self.read_battery()
                    
                    # Aquí podrías añadir bucles para leer acelerómetro, ritmo cardíaco, etc.
                    # await asyncio.sleep(5) 
                else:
                    logger.error("Falló la autenticación. Desconectando.")

if __name__ == "__main__":
    # Asegúrate de poner tu clave REAL aquí
    if "XX" in MAC_ADDRESS:
        print("ERROR: Edita el script y pon tu MAC Address y Auth Key.")
    else:
        middleware = MiBandMiddleware(MAC_ADDRESS, AUTH_KEY_HEX)
        asyncio.run(middleware.run())
```

### Ejecución
Ejecutamos el script: `python3 script.py`

Si ves el nivel de la batería en tu terminal, ¡lo has conseguido! Has realizado con éxito una conexión autenticada a un dispositivo BLE, has superado su seguridad y has extraído datos.

> **💡 Tip**: La salida debería ser similar a la siguiente:
> ```txt
> INFO - Conectando a XX:XX:XX:XX:XX:XX...
> INFO - Conectado. Verificando servicios...
> INFO - Iniciando autenticación...
> INFO - Solicitando número aleatorio...
> INFO - Recibido número aleatorio de la pulsera.
> INFO - Enviando desafío cifrado...
> INFO - ¡Autenticación Exitosa!
> INFO - Leyendo datos de batería...
> INFO - --- ESTADO BATERÍA ---
> INFO - Nivel: 77%
> INFO - Estado: Normal
> INFO - Raw Data: 0f4d00e9070c09001b2a04e9070c09002d390464
> ```


<br>

## Próximos Pasos
---
Este es solo el primer paso. Con la autenticación resuelta, el camino está libre para acceder a sensores más interesantes como el acelerómetro y el giroscopio, que son la base para nuestro futuro proyecto. Has convertido una caja negra en una herramienta de código abierto

> H4Ppy H4ck1ng!
