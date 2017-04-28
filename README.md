# Instrucciones
Este script realiza un análisis de nuestra red local, para comprobar problemas a partir de las direcciones MAC. Por una parte, comprueba que no haya direcciones MAC duplicadas para prevenir ataques de spoofing, y por otra a partir de una lista blanca, comprueba que todas las direcciones MAC de la red están permitidas. Todo el análisis es registrado en un archivo log. 

El archivo que contiene las direcciones MAC permitidas, es un archivo de texto en el que cada línea se corresponde con una dirección MAC. AL utilizar scapy la herramienta, cuando finalice el envió de los paquetes, hace falta darle a Ctrl+C.

Para ambos casos, es enviado un correo electrónico. En el caso de los duplicados, en el correo enviado aparecen las direcciones MAC que se encuentran duplicadas, y para el caso de la lista blancas, el correo contiene las direcciones MAC no permitidas. El correo solo es enviado cuando ha encontrado un problema, y en este viene adjunto el archivo log con los resultados del análisis. Los parámetros con los que trabaja el script son los siguientes:

--log: indicar el nombre del archivo que contendrá el registro de los log. Por defecto el valor es informe.log, con la variable log

--iface: la interfaz sobre la que se realiza el escaneo arp. Por defecto el valor es eth0, con la variable iface

--filename: el fichero que contiene la lista de direcciones MAC permitidas. Por defecto el valor es WhiteList.txt, con la variable filename

--iprange: el rango de la red. Por defecto es su valor es 192.168.1.0/24, con la variable iprange

--smtp: el servidor smtp del email desde el que se enviarán los correos. Por defecto su valor es smtp.gmail.com, con la variable smtp

--user: el usuario del email desde el que se enviarán los correos. Por defecto su valor esta vacío, con la variable user

--pass: la contraseña del email desde el que se enviarán los correos. Por defecto su valor esta vacío, con la variable passw

--src: dirección email de origen. Por defecto su valor esta vacío, con la variable src

--dst: dirección email de destino. Por defecto su valor esta vacío, con la variable dst

Script en python para detectar vulnerabilidades en la red a partir de las direcciones MAC.
