<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 105174:805049 (outdated) -->

<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
 contributor license agreements.  See the NOTICE file distributed with
 this work for additional information regarding copyright ownership.
 The ASF licenses this file to You under the Apache License, Version 2.0
 (the "License"); you may not use this file except in compliance with
 the License.  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

<manualpage metafile="glossary.xml.meta">

  <title>Glosario</title>

<summary>
<p>Este glosario define la terminolog&#237;a m&#225;s com&#250;n
relacionada con Apache en particular y con los servidores web en
general. En los enlaces que hay asociados a cada t&#233;rmino se puede
encontrar informaci&#243;n m&#225;s detallada.</p>
</summary>

<section id="definitions"><title>Definiciones</title>

<dl>
<dt><a name="authentication">Autentificaci&#243;n</a></dt> <dd>La
identificaci&#243;n positiva de una entidad de red tal como un
servidor, un cliente, o un usuario.<br /> Consulte: <a
href="howto/auth.html">Autentificaci&#243;n, Autorizaci&#243;n, y
Control de Acceso</a></dd>

<dt><a name="accesscontrol">Control de Acceso</a></dt> <dd>La
restricci&#243;n en el acceso al entorno de una red. En el contexto de
Apache significa normalmente la restricci&#243;n en el acceso a
ciertas <em>URLs</em>.<br /> Consulte: <a
href="howto/auth.html">Autentificaci&#243;n, Autorizaci&#243;n, y
Control de Acceso</a></dd>

<dt><a name="algorithm">Algoritmo</a></dt> <dd>Un proceso definido sin
ambiguedades o un conjunto de reglas para solucionar un problema en un
n&#250;mero finito de pasos. Los algoritmos para encriptar se llaman
normalmente <dfn>algoritmos de cifrado</dfn>.</dd>

<dt><a name="apacheextensiontool">Herramienta de extensi&#243;n de
Apache</a> <a name="apxs">(apxs)</a></dt> <dd>Es un script escrito en
Perl que ayuda a compilar el c&#243;digo fuente de algunos <a
href="#module">m&#243;dulos</a> para convertirlos en Objetos Dinamicos
Compartidos (<a href="#dso">DSO</a>s) y ayuda a instalarlos en el
servidor web Apache.<br /> Consulte: <a
href="programs/apxs.html">Paginas de Ayuda: apxs</a></dd>

<dt><a name="certificate">Certificado</a></dt>

<dd>Una informaci&#243;n que se almacena para autentificar entidades
    de red tales como un servidor o un cliente. Un certificado
    contiene piezas de informaci&#243;n X.509 sobre su poseedor
    (llamado sujeto) y sobre la <a
    href="#certificationauthority">Autoridad Certificadora</a>
    (llamada el expendedor) que lo firma, m&#225;s la <a
    href="#publickey">clave publica</a> del propietario y la firma de
    la AC. Las entidades de red verifican las firmas usando
    certificados de las AC.<br />

Consulte: <a href="ssl/">Encriptado SSL/TLS</a></dd>

<dt><a name="certificationauthority">Autoridad Certificadora</a> <a
name="ca">(CA)</a></dt> <dd>Una entidad externa de confianza cuyo fin
es firmar certificados para las entidades de red que ha autentificado
usando medios seguros. Otras entidades de red pueden verificar la
firma para comprobar que una Autoridad Certificadora ha autentificado
al poseedor del certificado.<br /> Consulte: <a href="ssl/">Encriptado
SSL/TLS</a></dd>

<dt><a name="certificatsigningrequest">Petici&#243;n de firma de
Certificado</a> <a name="csr">(CSR)</a></dt> <dd>Es la petici&#243;n a
una <a href="#certificationauthority">Autoridad Certificadora</a> para
que firme un <a href="#certificate">certificado</a> a&#250;n sin
firmar. La Autoridad Certificadora firma el <em>Certificado</em> con
la <a href="#privatekey">Clave Privada</a> de su <a
href="#certificate">certificado</a> de Autoridad Certificadora. Una
vez que el CSR est&#225; firmado, se convierte en un aut&#233;ntico
certificado.<br /> Consulte: <a href="ssl/">Encriptado
SSL/TLS</a></dd>


<dt><a name="cipher">Algoritmo de cifrado</a></dt> <dd>Es un algoritmo
o sistema de encriptado de informaci&#243;n. Ejemplos de estos
algoritmos son DES, IDEA, RC4, etc.<br /> Consulte: <a
href="ssl/">Encriptado SSL/TLS</a></dd>

<dt><a name="ciphertext">Texto cifrado</a></dt> <dd>El resultado de
haber aplicado a un <a href="#plaintext">texto sin cifrar</a> un <a
href="#cipher">algoritmo de cifrado</a>.<br /> Consultar: <a
href="ssl/">Encriptado SSL/TLS</a></dd>

<dt><a name="commongatewayinterface">Common Gateway Interface</a> <a
name="cgi">(CGI)</a></dt> <dd>Una definici&#243;n est&#225;ndar para
un interfaz entre un servidor web y un programa externo que permite
hacer peticiones de servicio a los programas externos.  Este interfaz
fue definido originalmente por la <a
href="http://hoohoo.ncsa.uiuc.edu/cgi/overview.html">NCSA</a> pero
tambien hay un proyecto <a
href="http://cgi-spec.golux.com/">RFC</a>.<br /> Consulte: <a
href="howto/cgi.html">Contenido Din&#225;mico con CGI</a></dd>


<dt><a name="configurationdirective">Directivas de
configuraci&#243;n</a></dt> <dd>Consulte: <a
href="#directive">Directivas</a></dd>

<dt><a name="configurationfile">Fichero de Configuraci&#243;n</a></dt>
<dd>Un fichero de texto que contiene <a
href="#directive">Directivas</a> que controlan la configuraci&#243;n
de Apache.<br /> Consulte: <a href="configuring.html">Ficheros de
Configuraci&#243;n</a></dd>

<dt><a name="connect">CONNECT</a></dt> <dd>Un <a
href="#method">m&#233;todo</a> de HTTP para hacer proxy a canales de
datos sin usar HTTP. Puede usarse para encapsular otros protocolos,
tales como el protocolo SSL.</dd>

<dt><a name="context">Contexto</a></dt> <dd>Un &#225;rea en los <a
href="#configurationfile">ficheros de configuraci&#243;n</a> donde
est&#225;n permitidos ciertos tipos de <a
href="#directive">directivas</a>.<br /> Consulte: <a
href="mod/directive-dict.html#Context">Terminos usados para describir
las directivas de Apache</a></dd>

<dt><a name="digitalsignature">Firma Digital</a></dt> <dd>Un bloque de
texto encriptado que verifica la validez de un certificado o de otro
fichero. Una <a href="#certificationauthority">Autoridad
Certificadora</a> crea una firma generando un hash a partir de la
<em>Clave P&#250;blica</em> que lleva incorporada en un
<em>Certificado</em>, despu&#233;s encriptando el hash con su propia
<em>Clave Privada</em>. Solo las claves p&#250;blicas de las CAs
pueden desencriptar la firma, verificando que la CA ha autentificado a
la entidad de red propietaria del <em>Certificado</em>.<br />
Consulte: <a href="ssl/">Encriptado SSL/TLS</a></dd>

<dt><a name="directive">Directiva</a></dt> <dd>Un comando de
configuraci&#243;n que controla uno o m&#225;s aspectos del
comportamiento de Apache.  Las directivas se ponen en el <a
href="#configurationfile">Fichero de Configuraci&#243;n</a><br />
Consulte: <a href="mod/directives.html">&#205;ndice de
Directivas</a></dd>

<dt><a name="dynamicsharedobject">Objetos Din&#225;micos
Compartidos</a> <a name="dso">(DSO)</a></dt> <dd>Los <a
href="#module">M&#243;dulos</a> compilados de forma separada al
binario httpd de Apache se pueden cargar seg&#250;n se necesiten.<br
/> Consulte: <a href="dso.html">Soporte de Objetos Din&#225;micos
Compartidos</a></dd>

<dt><a name="environmentvariable">Variable de Entorno</a> <a
name="env-variable">(env-variable)</a></dt> <dd>Variables que
gestionan el shell del sistema operativo y que se usan para guardar
informaci&#243;n y para la comunicaci&#243;n entre programas.  Apache
tambi&#233;n contiene variables internas que son referidas como
variables de entorno, pero que son almacenadas en las estructuras
internas de Apache, en lugar de en el entorno del shell.<br />
Consulte: <a href="env.html">Variables de entorno de Apache</a></dd>

<dt><a name="export-crippled">Export-Crippled</a></dt>
<dd>Disminuci&#243;n de la fortaleza criptogr&#225;fica (y seguridad)
para cumplir con las Regulaciones sobre Exportaci&#243;n de la
Administracci&#243;n de los Estados Unidos (EAR). El software
criptogr&#225;fico Export-crippled est&#225; limitado a una clave de
peque&#241;o tama&#241;o, de tal manera que el <em>texto cifrado</em>
que se consigue con &#233;l, puede desencriptarse por fuerza bruta.<br
/> Consulte: <a href="ssl/">Encriptado SSL/TLS</a></dd>

<dt><a name="filter">Filtro</a></dt> <dd>Un proceso que se aplica a la
informaci&#243;n que es enviada o recibida por el servidor. Los
ficheros de entrada procesan la informaci&#243;n enviada por un
cliente al servidor, mientras que los filtros de salida procesan la
informaci&#243;n en el servidor antes de envi&#225;rsela al
cliente. Por ejemplo, el filtro de salida <code>INCLUDES</code>
procesa documentos para <a href="#ssi">Server Side Includes</a>.<br />
Consulte: <a href="filter.html">Filtros</a></dd>

<dt><a name="fully-qualifieddomain-name">Nombre de dominio
completamente qualificado</a> <a name="fqdn">(FQDN)</a></dt> <dd>El
nombre &#250;nico de una entidad de red, que consiste en un nombre de
host y un nombre de dominio que puede traducirse a una direcci&#243;n
IP. Por ejemplo, <code>www</code> es un nombre de host,
<code>example.com</code> es un nombre de dominio, y
<code>www.example.com</code> es un nombre de dominio completamente
qualificado.</dd>

<dt><a name="handler">Handler</a></dt> <dd>Es una representaci&#243;n
interna de Apache de una acci&#243;n a ser ejecutada cuando se llama a
un fichero. Generalmente, los ficheros tienen un handler
impl&#237;cito, basado en el tipo de fichero. Normalmente, todos los
ficheros son simplemente servidos por el servidor, pero sobre algunos
tipos de ficheros se ejecutan acciones complementarias.  Por ejemplo,
el handler <code>cgi-script</code> designa los ficheros a ser
procesados como <a href="#cgi">CGIs</a>.<br /> Consulte: <a
href="handler.html">Uso de Handlers en Apache</a></dd>

<dt><a name="header">Cabecera</a></dt> <dd>La parte de la
petici&#243;n y la respuesta <a href="#http">HTTP</a> que se
env&#237;a antes del contenido propiamente dicho, y que contiene
meta-informaci&#243;n describiendo el contenido.</dd>

<dt><a name="htaccess">.htaccess</a></dt> <dd>Un <a
href="#configurationfile">fichero de configuraci&#243;n</a> que se
pone dentro de la estructura de directorios del sitio web y aplica <a
href="#directive">directivas</a> de configuraci&#243;n al directorio
en el que est&#225; y a sus subdirectorios. A pesar de su nombre, este
fichero puede contener cualquier tipo de directivas, no solo
directivas de control de acceso.<br /> Consulte: <a
href="configuring.html">Ficheros de Configuraci&#243;n</a></dd>

<dt><a name="httpd.conf">httpd.conf</a></dt> <dd>Es el <a
href="#configurationfile">fichero de configuraci&#243;n</a> principal
de Apache.  Su ubicaci&#243;n por defecto es
<code>/usr/local/apache2/conf/httpd.conf</code>, pero puede moverse
usando opciones de configuraci&#243;n al compilar o al iniciar
Apache.<br /> Consulte: <a href="configuring.html">Ficheros de
Configuraci&#243;n</a></dd>

<dt><a name="hypertexttransferprotocol">Protocolo de Tranferencia de
Hipertexto</a> <a name="http">(HTTP)</a></dt> <dd>Es el protocolo de
transmisi&#243;n est&#225;dar usado en la World Wide Web.  Apache
implementa la versi&#243;n 1.1 de este protocolo, al que se hace
referencia como HTTP/1.1 y definido por el <a
href="http://ietf.org/rfc/rfc2616.txt">RFC 2616</a>.</dd>

<dt><a name="https">HTTPS</a></dt> <dd>Protocolo de transferencia de
Hipertext (Seguro), es el mecanismo de comunicaci&#243;n encriptado
est&#225;ndar en World Wide Web. En realidad es HTTP sobre <a
href="#ssl">SSL</a>.<br /> Consulte: <a href="ssl/">Encriptado
SSL/TLS</a></dd>

<dt><a name="method">M&#233;todo</a></dt> <dd>En el contexto de <a
href="#http">HTTP</a>, es una acci&#243;n a ejecutar sobre un recurso,
especificado en la l&#237;neas de petici&#243;n por el cliente.
Algunos de los metodos diponibles en HTTP son <code>GET</code>,
<code>POST</code>, y <code>PUT</code>.</dd>

<dt><a name="messagedigest">Message Digest</a></dt> <dd>Un hash de un
mensaje, el cual pude ser usado para verificar que el contenido del
mensaje no ha sido alterado durante la transmisi&#243;n.<br />
Consulte: <a href="ssl/">Encriptado SSL/TLS</a></dd>

<dt><a name="mime-type">MIME-type</a></dt> <dd>Una manera de describir
el tipo de documento a ser transmitido.  Su nombre viene del hecho de
que su formato se toma de las Extensiones del Multipurpose Internet
Mail.  Consiste en dos componentes, uno principal y otro secundario,
separados por una barra.  Algunos ejemplos son <code>text/html</code>,
<code>image/gif</code>, y <code>application/octet-stream</code>.  En
HTTP, el tipo MIME se transmite en la <a href="#header">cabecera</a>
del <code>Tipo Contenido</code>.<br /> Consulte: <a
href="mod/mod_mime.html">mod_mime</a></dd>

<dt><a name="module">M&#243;dulo</a></dt> <dd>Una parte independiente
de un programa.  La mayor parte de la funcionalidad de Apache
est&#225; contenida en m&#243;dulos que pueden incluirse o excluirse.
Los m&#243;dulos que se compilan con el binario httpd de Apache se
llaman <em>m&#243;dulos est&#225;ticos</em>, mientras que los que se
almacenan de forma separada y pueden ser cargados de forma opcional,
se llaman <em>m&#243;dulos dinamicos</em> o <a href="#dso">DSOs</a>.
Los m&#243;dulos que est&#225;n incluidos por sefecto de llaman
<em>m&#243;dulos base</em>.  Hay muchos m&#243;dulos disponibles para
Apache que no se distribuyen con la <a href="#tarball">tarball</a> del
Servidor HTTP Apache .  Estos m&#243;dulos son llamados
<em>m&#243;dulos de terceros</em>.<br /> Consulte: <a
href="mod/">&#205;ndice de M&#243;dulos</a></dd>

<dt><a name="modulemagicnumber">N&#250;mero M&#225;gico de
M&#243;dulo</a> (<a name="mmn">MMN</a>)</dt> <dd> El n&#250;mero
m&#225;gico de m&#243;dulo es una constante definida en el c&#243;digo
fuente de Apache que est&#225; asociado con la compatibilidad binaria
de los m&#243;dulos. Ese n&#250;mero cambia cuando cambian las
estructuras internas de Apache, las llamadas a funciones y otras
partes significativas de la interfaz de programaci&#243;n de manera
que la compatibilidad binaria no puede garantizarse sin cambiarlo.  Si
cambia el n&#250;mero m&#225;gico de m&#243;dulo, todos los
m&#243;dulos de terceros tienen que ser al menos recompilados, y
algunas veces, incluso hay que introducir ligeras modificaciones para
que funcionen con la nueva versi&#243;n de Apache </dd>

<dt><a name="openssl">OpenSSL</a></dt>
<dd>El toolkit Open Source para SSL/TLS<br />
    see <a href="http://www.openssl.org/">http://www.openssl.org/</a></dd>

<dt><a name="passphrase">Pass Phrase</a></dt> <dd>La palabra o frase
que protege los archivos de clave privada.  Evita que usuarios no
autorizados los encripten. Normalmente es solo la clave de
encriptado/desencriptado usada por los <a name="cipher">Algoritmos de
Cifrado</a>.<br /> Consulte: <a href="ssl/">Encriptado
SSL/TLS</a></dd>

<dt><a name="plaintext">Plaintext</a></dt>
<dd>Un texto no encriptado.</dd>

<dt><a name="privatekey">Clave Privada</a></dt> <dd>La clave secreta
de un <a href="#publickeycryptography">sistema criptogr&#225;fico de
Clave P&#250;blica</a>, usada para desencriptar los mensajes entrantes
y firmar los salientes.<br /> Consulte: <a href="ssl/">Encriptado
SSL/TLS</a></dd>

<dt><a name="proxy">Proxy</a></dt> <dd>Un servidor intermedio que se
pone entre el cliente y el <em>servidor de origen</em>.  Acepta las
peticiones de los clientes, las transmite al servidor de origen, y
despu&#233;s devuelve la respuesta del servidor de origen al
cliente. Si varios clientes piden el mismo contenido, el proxy sirve
el contenido desde su cach&#233;, en lugar de pedirlo cada vez que lo
necesita al servidor de origen, reduciendo con esto el tiempo de
respuesta.<br /> Consulte: <a
href="mod/mod_proxy.html">mod_proxy</a></dd>

<dt><a name="publickey">Clave Publica</a></dt> <dd>La clave disponible
p&#250;blicamente en un <a href="#publickeycryptography">sistema
criptogr&#225;fico de Clave P&#250;blica</a>, usado para encriptar
mensajes destinados a su propietario y para desencriptar firmas hechas
por su propietario.<br /> Consulte: <a href="ssl/">Encriptado
SSL/TLS</a></dd>

<dt><a name="publickeycryptography">Criptogr&#225;fia de Clave
P&#250;blica</a></dt> <dd>El estudio y aplicaci&#243;n de sistemas de
encriptado asim&#233;tricos, que usa una clave para encriptar y otra
para desencriptar. Una clave de cada uno de estos tipos constituye un
par de claves. Tambien se llama Criptografia Asim&#233;trica.<br />
Consulte: <a href="ssl/">Encriptado SSL/TLS</a></dd>

<dt><a name="regularexpresion">Expresiones Regulares</a> <a
name="regex">(Regex)</a></dt> <dd>Una forma de describir un modelo de
texto - por ejemplo, "todas las palabras que empiezan con la letra "A"
o "todos los n&#250;meros de tel&#233;fono que contienen 10
d&#237;gitos" o incluso "Todas las frases entre comas, y que no
contengan ninguna letra Q". Las Expresiones Regulares son utiles en
Apache porque permiten aplicar ciertos atributos a colecciones de
ficheros o recursos de una forma flexible - por ejemplo, todos los
archivos .gif y .jpg que est&#233;n en un directorio "im&#225;genes"
podr&#237;an ser escritos como "<code>/images/.*(jpg|gif)$</code>".
Apache usa Expresiones Regulares compatibles con Perl gracias a la
librer&#237;a <a href="http://www.pcre.org/">PCRE</a>.</dd>

<dt><a name="reverseproxy">Reverse Proxy</a></dt> <dd>Es un servidor
<a href="#proxy">proxy</a> que se presenta al cliente como si fuera un
<em>servidor de origen</em>.  Es &#250;til para esconder el
aut&#233;ntico servidor de origen a los clientes por cuestiones de
seguridad, o para equilibrar la carga.</dd>

<dt><a name="securesocketslayer">Secure Sockets Layer</a> <a
name="ssl">(SSL)</a></dt> <dd>Un protocolo creado por Netscape
Communications Corporation para la autentificaci&#243;n en
comunicaciones en general y encriptado sobre redes TCP/IP.  Su
aplicaci&#243;n m&#225;s popular es <em>HTTPS</em>, el Protocolo de
Transferencia de Hipertexto (HTTP) sobre SSL.<br /> Consulte: <a
href="ssl/">Encriptado SSL/TLS</a></dd>

<dt><a name="serversideincludes">Server Side Includes</a> <a
name="ssi">(SSI)</a></dt> <dd>Una tecnica para incluir directivas de
proceso en archivos HTML.<br /> Consulte: <a
href="howto/ssi.html">Introducci&#243;n al Server Side
Includes</a></dd>

<dt><a name="session">Sesion</a></dt> <dd>Informaci&#243;n del
contexto de una comunicaci&#243;n en general.</dd>

<dt><a name="ssleay">SSLeay</a></dt> <dd>La implementaci&#243;n
original de la librer&#237;a SSL/TLS desarrollada por Eric
A. Young</dd>

<dt><a name="symmetriccryptophraphy">Criptograf&#237;a
Sim&#233;trica</a></dt> <dd>El estudio y aplicaci&#243;n de
<em>Algoritmos de Cifrado</em> que usan una solo clave secreta tanto
para encriptar como para desencriptar.<br /> Consulte: <a
href="ssl/">Encriptado SSL/TLS</a></dd>

<dt><a name="tarball">Tarball</a></dt> <dd>Un grupo de ficheros
puestos en un solo paquete usando la utilidad <code>tar</code>.  Las
distribuciones Apache se almacenan en ficheros comprimidos con tar o
con pkzip.</dd>

<dt><a name="transportlayersecurity">Transport Layer Security</a> <a
name="tls">(TLS)</a></dt> <dd>Es el sucesor del protocolo SSL, creado
por el Internet Engineering Task Force (IETF) para la
autentificaci&#243;n en comunicaciones en general y encriptado sobre
redes TCP/IP. La versi&#243;n 1 de TLS es casi id&#233;ntica a la
versi&#243;n 3 de SSL.<br /> Consulte: <a href="ssl/">Encriptado
SSL/TLS</a></dd>

<dt><a name="uniformresourcelocator">Localizador de Recursos
Uniforme</a> <a name="url">(URL)</a></dt> <dd>El nombre de un recurso
en Internet.  Es la manera informal de decir lo que formalmente se
llama un <a href="#uniformresourceidentifier">Identificador de
Recursos Uniforme</a>.  Las URLs est&#225;n compuestas normalmente por
un esquema, tal como <code>http</code> o <code>https</code>, un nombre
de host, y una ruta.  Una URL para esta p&#225;gina es
<code>http://httpd.apache.org/docs/&httpd.docs;/glossary.html</code>.</dd>

<dt><a name="uniformresourceidentifier">Identificador de Recursos
Uniforme</a> <a name="URI">(URI)</a></dt> <dd>Una cadena de caracteres
compacta para identificar un recurso f&#237;sico o abstracto.  Se
define formalmente en la <a
href="http://www.ietf.org/rfc/rfc2396.txt">RFC 2396</a>.  Los URIs que
se usan en world-wide web se refieren normalmente como <a
href="#url">URLs</a>.</dd>

<dt><a name="virtualhosting">Hosting Virtual</a></dt> <dd>Se trata de
servir diferentes sitios web con una sola entidad de Apache.  <em>El
hosting virtual de IPs</em> diferencia los sitios web basandose en sus
direcciones IP, mientras que el <em>hosting virtual basado en
nombres</em> usa solo el nombre del host y de esta manera puede alojar
muchos sitios web con la misma direcci&#243;n IP.<br /> Consulte: <a
href="vhosts/">Documentaci&#243;n sobre Hosting Virtual en
Apache</a></dd>

<dt><a name="x.509">X.509</a></dt> <dd>Un esquema de certificado de
autentificaci&#243;n recomendado por la International
Telecommunication Union (ITU-T) que se usa en la autentificaci&#243;n
SSL/TLS.<br /> Consulte: <a href="ssl/">Encriptado SSL/TLS</a></dd>

</dl>
</section>
</manualpage>

