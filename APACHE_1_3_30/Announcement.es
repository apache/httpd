              Liberado el Servidor de HTTP Apache 1.3.30

La Fundación de Software Apache y el Proyecto de Servidor HTTP Apache se
complacen en anunciar el lanzamiento de la versión 1.3.30 del Servidor HTTP
Apache ("Apache"). Este comunicado recoge los cambios más significativos que
se han introducido en la versión 1.3.30 con respecto a la versión 1.3.29.
Este comunicado está también disponible en Inglés, Alemán y Japonés, en los
siguientes enlaces: 

   http://www.apache.org/dist/httpd/Announcement.html
   http://www.apache.org/dist/httpd/Announcement.html.de
   http://www.apache.org/dist/httpd/Announcement.html.ja

La nueva version soluciona principalmente problemas de seguridad y errores
de programación (bugs). Al final de este documento puede encontrar un
resumen parcial de los problemas corregidos. En el fichero CHANGES está la
lista completa de los cambios introducidos. De especial relevancia son los
tres problemas potenciales de seguridad que se han resuelto en la version
1.3.30:

	* CAN-2003.0020 (cve.mitre.org)	
	  Filtrado de datos arbitrarios antes de escribir en el registro de
	  errores (errorlog). 

	* CAN-2004-0174 (cve.mitre.org)	
	  Soluciona el problema de muerte por inanición en sockets de
	  escucha, en el que una conexión de vida corta a un socket de
	  escucha raramente accedido provocará que un hijo mantenga aceptado
	  el mutex y bloquee las nuevas conexiones hasta que otra conexión
	  llegue a ese socket de escucha raramente accedido.

	* CAN-2003-0993 (cve.mitre.org)	
	  Soluciona el problema que surge al analizar las reglas de las
	  directivas Allow/Deny usando direcciones IP sin una máscara de
	  red; este problema actualmente solo se conoce que afecte a la
	  plataformas de 64 bits big-endian

Consideramos que Apache 1.3.30 es la mejor versión disponible de Apache 1.3
y recomendamos firmemente a los usuarios de versiones anteriores,
especialmente los de las versiones 1.1.x y 1.2.x, que se actualicen lo antes
posible. No se harán nuevas versiones de la familia 1.2.x.

Apache 1.3.30 puede descargarse desde el siguiente enlace:

       http://httpd.apache.org/download.cgi

Este servicio usa una red de mirrors cuya lista puede consultarse en:

       http://www.apache.org/mirrors/

Por favor, consulte el fichero CHANGES_1.3 para ver la lista completa de
cambios introducidos en la nueva versión.

Como todas las distribuciones binarias de Apache posteriores a la 1.3.12, la
nueva versión contiene todos los módulos estándar de Apache como objetos
compartidos (si son soportados por la plataforma) e incluye todo el código
fuente. La instalación se hace fácilmente ejecutando el script de
instalación incluido. Si quiere informacion detallada, consulte los ficheros
README.bindist y INSTALL.bindist. Tenga en cuenta que las distribuciones
binarias se suministran para su propia conveniencia y que no siempre
incluyen las últimas actualizaciones en todas las plataformas. Las
distribuciones binarias para Win32 están basadas en la tecnología del
Instalador Microsoft (MSI). Mientras que continua el desarrollo para hacer
el método de instalación mas robusto, las preguntas sobre el tema deben
dirigirse al grupo de news news:comp.infosystems.www.servers.ms-windows

Para tener una visión general de las nuevas características introducidas con
posterioridad a la version 1.2 de Apache, consulte el siguiente enlace:

 http://httpd.apache.org/docs/new_features_1_3.html

En general, Apache 1.3 ofrece diversas mejoras sustanciales sobre la versión
1.2, incluido un mejor rendimiento, una mayor fiabilidad y un mayor rango de
plataformas soportadas, incluidas Windows NT y 2000 (que entran en la
categoria "Win32"), OS2, Netware, y plataformas TPF threaded.

Apache es el servidor web mas popular en el universo conocido; más de la
mitad de los servidores de Internet usan Apache o alguna de sus variantes.

AVISO IMPORTANTE PARA LOS USUARIOS DE APACHE: Apache 1.3 ha sido diseñado
para sistemas operativos Unix y sus variantes. Aunque las versiones para
plataformas no Unix (tales como Win32, Netware u OS2) son de una calidad
aceptable, Apache 1.3 no está optimizado para esas plataformas. Los
problemas de seguridad, estabilidad o rendimiento presentes en esas
versiones no Unix, no afectan generalmente a las versiones para Unix.

Apache 2.0 se ha estructurado para múltiples sistemas operativos desde el
principio, introduciendo la Librería de Portabilidad de Apache y los modulos
MPM. Se recomienda firmemente a los ususarios de plataformas no Unix que
pasen a usar Apache 2.0 para mejorar el rendimiento, la estabilidad y la
seguridad en sus plataformas.


               Principales cambios introducidos en Apache 1.3.30

Problemas de seguridad

	* CAN-2003.0020 (cve.mitre.org)	
	  Filtrado de datos arbitrarios antes de escribir en el registro de
	  errores (errorlog). 

	* CAN-2004-0174 (cve.mitre.org)	
	  Soluciona el problema de muerte por inanición en sockets de
	  escucha, en el que una conexión de vida corta a un socket de
	  escucha raramente accedido provocará que un hijo mantenga aceptado
	  el mutex y bloquee las nuevas conexiones hasta que otra conexión
	  llegue a ese socket de escucha raramente accedido.

	* CAN-2003-0993 (cve.mitre.org)	
	  Soluciona el problema que surge al analizar las reglas de las
	  directivas Allow/Deny usando direcciones IP sin una máscara de
	  red; este problema actualmente solo se conoce que afecte a la
	  plataformas de 64 bits big-endian

Nueva funcionalidad

 Nueva funcionalidad específica para una plataforma:

      * Linux 2.4+: Si se arranca Apache como usuario root y ejecuta el
        comando CoreDumpDirectory, los coredumps se activan via prctl()

 Nueva funcionalidad para todas las plataformas:

     * Se añaden los modulos mod_whatkilledus y mod_backtrace (de forma
       experimental) para reportar la información de diagnóstico
       despues de que una proceso hijo termine de forma inesperada.

     * Se añade un hook de excepción irrecuperable para ejecutar el
       código de diagnóstico después de un error irrecuperable.

     * Se ha añadido un módulo de registro forénsico (mod_log_forensic)

     * '%X' es aceptado a partir de ahora como alias para '%c' en la
       directiva LogFormat. Esto le permite configurar el logging para
       almacenar el estado de la conexión, incluso con mod_ssl

Errores de programación solucionados 

Estos son los errores de programación de relevancia que fueron
encontrados en la version de Apache 1.3.29 (o anteriores) y que han
sido corregidos en Apache 1.3.30:

     * Solucionado el problema de corrupción de memoria con la función
       ap_custom_response(). La configuración principal per-dir config
       referenciaba posteriormente a los datos comunes de la petición que
       serían reusados para diferentes propósitos en sucesivas peticiones.

     * El módulo mod_usertrack no inspecciona a partir de ahora la cabecera
       Cookie2 para encontrar el nombre de la cookie. A partir de ahora
       tampoco sobreescribe otras cookies.

     * Solucionado el problema causado por volcado de memoria (core dump)
       cuando se usa CookieTracking sin especificar un CookieName
       directamente.

     * UseCanonicalName off ignoraba la información sobre el puerto
       proporcionada por el cliente. 
