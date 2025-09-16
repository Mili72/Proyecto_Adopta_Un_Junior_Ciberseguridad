***
## Descripción del proyecto

En este caso he elegido una máquina vulnerable de la plataforma [Dockerlabs](https://dockerlabs.es), en la cuál existe un endpoint vulnerable de **Node.js**, que permite la explotación de este para conseguir acceso a la máquina. En este documento se mostrará la existencia de las vulnerabilidades, como explotarlas y como mitigarlas para mejorar la seguridad este endpoint.

***
### Descubrimiento del Endpoint Vulnerable

Se realiza un ecaneo de puertos general para ver posibles vectores de entrada.

```bash
sudo nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 172.17.0.2 -oG allports
[sudo] contraseña para elmili: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-15 12:49 CEST
Initiating ARP Ping Scan at 12:49
Scanning 172.17.0.2 [1 port]
Completed ARP Ping Scan at 12:49, 0.05s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 12:49
Scanning 172.17.0.2 [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Discovered open port 3000/tcp on 172.17.0.2
Discovered open port 5000/tcp on 172.17.0.2
Completed SYN Stealth Scan at 12:49, 0.31s elapsed (65535 total ports)
Nmap scan report for 172.17.0.2
Host is up, received arp-response (0.0000010s latency).
Scanned at 2025-09-15 12:49:42 CEST for 1s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE REASON
80/tcp   open  http    syn-ack ttl 64
3000/tcp open  ppp     syn-ack ttl 64
5000/tcp open  upnp    syn-ack ttl 64
MAC Address: 02:42:AC:11:00:02 (Unknown)
```

#### Parámetros de escaneo general

*-sS (Stealth Scan):* Escaneo "sigiloso" que permite encontrar puertos sin completar el *Three-way handshake*, es decir, no llega a terminar la conexión con la máquina.
*-p- (All ports):* Escanea todos los puertos existentes (65535).
*--open (Puertos abiertos):* Parámetro para especificar que solo presente los puertos abiertos, ya que puden aparecer puertos filtrados que no interesan.
*--min-rate 5000 (Velocidad de escaneo):* Establece la velocidad de paquetes enviados a la máquina, esto nos ayuda a acelerar el proceso de escaneo.
*-vvv (Verbose):* Para que muestre la mayor cantidad de información posible durante el escaneo.
*-n (Resolución DNS):* Evita la resolución DNS para acelerar levemente el escaneo, activado por defecto en Nmap.
*-Pn (Reconocimiento de Hosts):* Evita el reconocimiento de hosts mediante trazas ICMP, activado por defecto en Nmap.
*-oG allports (Exportar):* Exporta la información a un archivo en formate Grepeable o del que se puede extraer información, en este caso allports

En este primer escaneo se encuentran los siguientes puertos:

- Puerto 80/tcp (HTTP): Servicio Web
- Puerto 3000/tcp (PPP): Protocolo de escucha Point-to-Point Protocol, usado en desarrollo de aplicaciones web normalmente de Node.js.
- Puerto 5000/tcp (UPNP): Universal Plug and Play que permite establecer conexiones entre los dispositivos de una red y descubrirse entre ellos.

***

```bash
❯ nmap -sCV -p80,3000,5000 172.17.0.2 -oN target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-15 13:03 CEST
Nmap scan report for picadilly.lab (172.17.0.2)
Host is up (0.000078s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.61 ((Debian))
|_http-title: Mi Sitio
|_http-server-header: Apache/2.4.61 (Debian)
3000/tcp open  http    Node.js Express framework
|_http-title: Error
5000/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 f8:37:10:7e:16:a2:27:b8:3a:6e:2c:16:35:7d:14:fe (ECDSA)
|_  256 cd:11:10:64:60:e8:bf:d9:a4:f4:8e:ae:3b:d8:e1:8d (ED25519)
MAC Address: 02:42:AC:11:00:02 (Unknown)
```

#### Parámetros de escaneo específico

*-sCV (Scripts básicos y versión de servicios):* "-sC" Paramétro que usa una serie de scrips básicos de reconocimiento de Nmap. "-sV" Parámetro para conocer la versión de las aplicaciones y servicios que corren en un puerto dado.
*-p(puertos):* Detrás de esta flag especificas los puertos que se quieren escanear para acelerar el proceso y buscar simplemente en los puertos interesantes.
*-oN target (Exportar):* Exportar la salida del escaneo en formato Nmap para poder leerlo mejor a un archivo.

Después de este escaneo se ve más información en los puertos que han aparecido en el escaneo general:

- Puerto 80/tcp (HTTP): Servicio Web | Versión: httpd 2.4.61 | Apache/2.4.61
- Puerto 3000/tcp (HTTP): Endpoint Node.js Express framework
- Puerto 5000/tcp (SSH): OpenSSH 9.2p1 Debian 2+deb12u3

***
### Reconocimiento y recolección del Endpoint Node.js Vulnerable

Se intenta entrar en el puerto del servicio web del puerto 3000 pero no logra alcanzar el recurso.

![[Pasted image 20250915131227.png]]

En la web del puerto 80 aparece un botón que dice estar en fase beta. No parece que haga nada, pero al ver el origen de la página aparece un script *authenticate.js*. Y permite la lectura del contenido de dicho script.

![[Pasted image 20250915131331.png]]

En el script aparece información sensible, como un token de acceso y el recurso:

![[Pasted image 20250915131540.png]]

Al intentar acceder al directorio */recurso/* no permite la entrada debido a la falta del token de acceso, el cuál conocemos.

![[Pasted image 20250915131906.png]]

***
### Explotación de la Vulnerabilidad 1 (Sensitive Data Exposure)

Se hace uso de la herramienta *cURL*, para ver el contenido del servicio web y confirmando el funcionamiento del Token exfiltrado.

```bash
curl -X POST http://172.17.0.2:3000/recurso/ -H "Content-Type: application/json" -d '{"token":"tokentraviesito"}'
lapassworddebackupmaschingonadetodas
```

Al usar el token directamente expone una credencial, seguramente del servicio SSH. Cabe añadir que además de este vulnerabilidad, existe otra que expone la misma credencial sin hacer uso de este token de acceso.

### Mitigación de la Vulnerabilidad 1

- **Eliminar el token del código** → nunca debe estar escrito en claro en el script.
- **Encriptar, hashear y/o eliminar contraseñas y credenciales** → la contraseña aparece en texto claro.
- **Establecer una lista de IPs permitidas**
	- Evitar total acceso de una red al recurso.
- **Almacenar el token de forma segura**:
    - Usar variables de entorno o un gestor de claves.
- **Eliminar el token comprometido** y generar uno nuevo con permisos mínimos.
- **Restringir acceso al recurso oculto**:
    - Impedir que archivos internos (como scripts con lógica sensible) estén accesibles desde el navegador o expuestos a la red.
- **Principio de menor privilegio**: el nuevo token debe ser de corta duración y con permisos limitados.

***
### Explotación de la Vulnerabilidad 2 (Insecure File Exposure | Credentials in Source Code)

Realizando un escaneo de directorios sobre el servicio web aparecen dos directorios a los que no debería haber acceso externo.

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://172.17.0.2 -t 200 -x php,html,js,css,txt
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 275]
/index.html           (Status: 200) [Size: 234]
/backend              (Status: 301) [Size: 310] [--> http://172.17.0.2/backend/] <--
/javascript           (Status: 301) [Size: 313] [--> http://172.17.0.2/javascript/]
/authentication.js    (Status: 200) [Size: 117]
```

En el aparece información sensible, tanto de como está montado el servidor web como módulos de Node.js, los cuales podrían ser vulnerables.

![[Pasted image 20250915132522.png]]

En el archivo *server.js* aparece la siguiente información:

```Node.js
const express = require('express');
const app = express();

const port = 3000;

app.use(express.json());

app.post('/recurso/', (req, res) => {
    const token = req.body.token;
    if (token === 'tokentraviesito') {
        res.send('lapassworddebackupmaschingonadetodas');
    } else {
        res.status(401).send('Unauthorized');
    }
});

app.listen(port, '0.0.0.0', () => {
    console.log(`Backend listening at http://consolelog.lab:${port}`);
});
```

Aparece el puerto en el que está establecido el servicio (3000), la petición post al directorio */recurso/*, confirma la lectura del token exfiltrado anteriormente para aceptar la conexión al recurso, el mensaje en caso de aceptar la conexión (contraseña en texto claro del servicio SSH), y mensaje o código de estado en caso de que el token fuera incorrecto. Además, aparece el DNS de la página web *consolelog.lab*, que acepta conexiones desde cualquier IP, es decir cualquier equipo de la red puede ponerse en escucha en este equipo, lo que se expone completamente en un ataque.

### Mitigación Vulnerabilidad 2

Ejemplo de código seguro para Node.js. Crea variables de entorno almacenadas de forma segura para el Token de acceso y el secreto de backup. También establece un límite de tamaño para evitar inyección de payloads demasiado grandes contrarrestando posibles ataques DoS o desbordamientos. Y aplica validación del buffer convirtiendolo en bytes, mediante el uso de la comparación de tiempos para que el atacante no pueda conocer el tamaño del token por duración (*timing attack*) y además se requiren dos buffers del mismo tamaño 

```Node.js
//server.js
const express = require('express');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

//Limitar cuerpo de la petición para evitar payloads muy grandes
app.use(express.json({ limit: '10kb' }));

//Creación de variables de entorno
const API_TOKEN = process.env.API_TOKEN;
const BACKUP_SECRET = process.env.BACKUP_SECRET;

if (!API_TOKEN || !BACKUP_SECRET) {
  console.error('Faltan variables de entorno: API_TOKEN o BACKUP_SECRET');
  process.exit(1);
}

//Validación de Token
function validToken(t) {
  try {
    const a = Buffer.from(String(t));
    const b = Buffer.from(String(API_TOKEN));
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch (e) {
    return false;
  }
}

app.post('/recurso', (req, res) => {
  const auth = (req.get('authorization') || '');
  let token = '';

  if (auth.toLowerCase().startsWith('bearer ')) {
    token = auth.slice(7).trim();
  } else if (req.body && req.body.token) {
    token = String(req.body.token).trim();
  }

  if (!validToken(token)) return res.status(401).json({ error: 'Unauthorized' });

//Hash del secreto de Backup (se siguen recomendando credenciales robustas)
  res.json({ backup_secret_hash: hashSecret(BACKUP_SECRET) });
});

function hashSecret(secret) {
  return crypto.createHash('sha256').update(secret).digest('hex');
}

//Ocultación del directorio Backend, el cuál puede contener información sensible
app.use('/backend', (req, res) => {
  res.status(404).send('Not Found');
})

app.listen(port, '0.0.0.0', () => console.log(`Servidor en puerto ${port}`));
```

Este código aumenta considerablemente la seguridad del sitio, y por ello al implementarlo existe la oportunidad de suprimir la funcion *authentication.js*, hosteada en el sitio web y en la que aparecía por ejemplo el Token en texto claro. Y para evitar que se expongan carpetas que deberían estar ocultas, esto se puede realizar sin problema en ambos servicios web de los dos puertos, tanto el 80, como el 3000.

***
### Buenas prácticas

- No hardcodear credenciales ni tokens de acces en el código.
- No exponer directorios sensibles de cara a Internet.
- Tener una buena segmentación de la red para evitar accessos no autorizados o malintencionados.
- Prácticas Zero Trust.
- Renovación de credenciales de acceso al recurso cada poco tiempo y hashearla o encriptarla de forma segura y que sean robustas.
- Uso de Gestor de Contraseñas.
- Desarrollo seguro de aplicaciones web.