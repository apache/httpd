<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1817381:1884552 (outdated) -->
<!-- Spanish Translation: Daniel Ferradal <dferradal@apache.org> -->
<!-- Updated and reviewed: Luis Gil de bernabe <lgilbernabe@apache.org> -->

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

<modulesynopsis metafile="mod_ssl.xml.meta">

<name>mod_ssl</name>
<description>Criptografía fuerte usando una Capa de Sockets Seguros (Secure 
  Sockets Layer SSL) y protocolos de Seguridad de la Capa de Transporte 
  (Transport Layer Security TLS)</description>
<status>Extension</status>
<sourcefile>mod_ssl.c</sourcefile>
<identifier>ssl_module</identifier>

<summary>
<p>Este módulo ofrece soporte para SSL v3 y TLS v1.x para el Servidor Apache
  HTTP. SSL v2 ya no está soportado.</p>

<p>Este módulo depende de <a href="http://www.openssl.org/">OpenSSL</a> para
proveer el motor criptográfico.</p>

<p>Se facilitan más detalles, discusión y ejemplos en la 
<a href="../ssl/">documentación SSL</a>.</p>
</summary>

<section id="envvars"><title>Variables de Entorno</title>

<p>Este módulo puede ser configurado para proveer muchos elementos de información
SSL como variables de entorno adicionales para el espacio de nombres de SSI y 
CGI. Esta información no se facilita por defecto por razones de rendimiento. 
(Vea StdEnvVars de <directive>SSLOptions</directive> más adelante.) Las 
variables generadas se listan en la tabla a continuación. Para 
retrocompatibilidad la información también puede estar disponible bajo distintos 
nombres. Vea el capítulo <a href="../ssl/ssl_compat.html">Compatibilidad</a> 
para más detalles sobre las variables de compatibilidad.</p>

<table border="1">
<columnspec><column width=".3"/><column width=".2"/><column width=".5"/>
</columnspec>
<tr>
 <th><a name="table3">Nombre de Variable:</a></th>
 <th>Valor Tipo:</th>
 <th>Descripción:</th>
</tr>
<tr><td><code>HTTPS</code></td>                         <td>flag</td>      <td>Se está usando HTTPS.</td></tr>
<tr><td><code>SSL_PROTOCOL</code></td>                  <td>string</td>    <td>El protocolo SSL versión (SSLv3, TLSv1, TLSv1.1, TLSv1.2)</td></tr>
<tr><td><code>SSL_SESSION_ID</code></td>                <td>string</td>    <td>El id de sesión SSL codificado en hexadecimal</td></tr>
<tr><td><code>SSL_SESSION_RESUMED</code></td>           <td>string</td>    <td>Sesión SSL inicial o reanudada.  Nota: múltiples peticiones pueden servirse a través de la misma sesión SSL (Inicial o Reanudada) si el KeepAlive de HTTP está en uso</td></tr>
<tr><td><code>SSL_SECURE_RENEG</code></td>              <td>string</td>    <td><code>true</code> si la renegociación segura está soportada, si no <code>false</code></td></tr>
<tr><td><code>SSL_CIPHER</code></td>                    <td>string</td>    <td>El nombre de la especificación del cifrado</td></tr>
<tr><td><code>SSL_CIPHER_EXPORT</code></td>             <td>string</td>    <td><code>true</code> si el cifrado es un cifrado export</td></tr>
<tr><td><code>SSL_CIPHER_USEKEYSIZE</code></td>         <td>number</td>    <td>Número de bits de cifrado (en uso actualmente)</td></tr>
<tr><td><code>SSL_CIPHER_ALGKEYSIZE</code></td>         <td>number</td>    <td>Número de bits de cifrado (posibles)</td></tr>
<tr><td><code>SSL_COMPRESS_METHOD</code></td>           <td>string</td>    <td>Método de compresión SSL negociado</td></tr>
<tr><td><code>SSL_VERSION_INTERFACE</code></td>         <td>string</td>    <td>La versión de mod_ssl</td></tr>
<tr><td><code>SSL_VERSION_LIBRARY</code></td>           <td>string</td>    <td>La versión del programa OpenSSL</td></tr>
<tr><td><code>SSL_CLIENT_M_VERSION</code></td>          <td>string</td>    <td>La versión del certificado cliente</td></tr>
<tr><td><code>SSL_CLIENT_M_SERIAL</code></td>           <td>string</td>    <td>El serial del certificado cliente</td></tr>
<tr><td><code>SSL_CLIENT_S_DN</code></td>               <td>string</td>    <td>Sujeto DN en el certificado cliente</td></tr>
<tr><td><code>SSL_CLIENT_S_DN_</code><em>x509</em></td> <td>string</td>    <td>Componente del Sujeto DN cliente</td></tr>
<tr><td><code>SSL_CLIENT_SAN_Email_</code><em>n</em></td> <td>string</td>  <td>Entradas de extensión subjectAltName del certificado cliente del tipo rfc822Name</td></tr>
<tr><td><code>SSL_CLIENT_SAN_DNS_</code><em>n</em></td> <td>string</td>    <td>Entradas de extensión subjectAltName del tipo dNSName</td></tr>
<tr><td><code>SSL_CLIENT_SAN_OTHER_msUPN_</code><em>n</em></td> <td>string</td>    <td>Entradas de extensión subjectAltName del certificado cliente del tipo otherName, Microsoft User Principal Name form (OID 1.3.6.1.4.1.311.20.2.3)</td></tr>
<tr><td><code>SSL_CLIENT_I_DN</code></td>               <td>string</td>    <td>DN del firmante en el certificado cliente</td></tr>
<tr><td><code>SSL_CLIENT_I_DN_</code><em>x509</em></td> <td>string</td>    <td>Componente del DN en el firmante del certificado cliente</td></tr>
<tr><td><code>SSL_CLIENT_V_START</code></td>            <td>string</td>    <td>Validez del certificado cliente (fecha de inicio)</td></tr>
<tr><td><code>SSL_CLIENT_V_END</code></td>              <td>string</td>    <td>Validez del certificado cliente (fecha fin)</td></tr>
<tr><td><code>SSL_CLIENT_V_REMAIN</code></td>           <td>string</td>    <td>Número de días hasta que el certificado cliente expira</td></tr>
<tr><td><code>SSL_CLIENT_A_SIG</code></td>              <td>string</td>    <td>Algoritmo usado para la firma del certificado cliente</td></tr>
<tr><td><code>SSL_CLIENT_A_KEY</code></td>              <td>string</td>    <td>Algoritmo usado para la clave pública del certificado cliente.</td></tr>
<tr><td><code>SSL_CLIENT_CERT</code></td>               <td>string</td>    <td>Certificado cliente codificado en PEM</td></tr>
<tr><td><code>SSL_CLIENT_CERT_CHAIN_</code><em>n</em></td> <td>string</td>    <td>Certificados codificados en PEM en la cadena de certificados cliente</td></tr>
<tr><td><code>SSL_CLIENT_CERT_RFC4523_CEA</code></td>   <td>string</td>    <td>Número de serie y distribuidor del certificado. El formato coincide con el CertificateExactAssertion en RFC4523</td></tr>
<tr><td><code>SSL_CLIENT_VERIFY</code></td>             <td>string</td>    <td><code>NONE</code>, <code>SUCCESS</code>, <code>GENEROUS</code> or <code>FAILED:</code><em>reason</em></td></tr>
<tr><td><code>SSL_SERVER_M_VERSION</code></td>          <td>string</td>    <td>La versión del certificado del servidor</td></tr>
<tr><td><code>SSL_SERVER_M_SERIAL</code></td>           <td>string</td>    <td>El serial del certificado del servidor</td></tr>
<tr><td><code>SSL_SERVER_S_DN</code></td>               <td>string</td>    <td>Nombre DN en el certificado del servidor</td></tr>
<tr><td><code>SSL_SERVER_SAN_Email_</code><em>n</em></td> <td>string</td>  <td>Entradas de extensión subjectAltName en el certificado del servidor del tipo rfc822Name</td></tr>
<tr><td><code>SSL_SERVER_SAN_DNS_</code><em>n</em></td> <td>string</td>    <td>Entradas de Extensión subjectAltName del tipo Server dNSName del certificado del Servidor</td></tr>
<tr><td><code>SSL_SERVER_SAN_OTHER_dnsSRV_</code><em>n</em></td> <td>string</td>    <td>Entradas de extensión subjectAltName del tipo otherName, forma SRVName (OID 1.3.6.1.5.5.7.8.7, RFC 4985) del certificado del servidor.</td></tr>
<tr><td><code>SSL_SERVER_S_DN_</code><em>x509</em></td> <td>string</td>    <td>Componente del Sujeto DN del servidor</td></tr>
<tr><td><code>SSL_SERVER_I_DN</code></td>               <td>string</td>    <td>DN del Firmante del certificado del servidor</td></tr>
<tr><td><code>SSL_SERVER_I_DN_</code><em>x509</em></td> <td>string</td>    <td>Componente en el DN del firmante del servidor</td></tr>
<tr><td><code>SSL_SERVER_V_START</code></td>            <td>string</td>    <td>Validez del certificado del servidor (fecha de inicio)</td></tr>
<tr><td><code>SSL_SERVER_V_END</code></td>              <td>string</td>    <td>Validez del certificado del servidor (fecha de fin)</td></tr>
<tr><td><code>SSL_SERVER_A_SIG</code></td>              <td>string</td>    <td>Algoritmo utilizado para la firma del certificado del servidor</td></tr>
<tr><td><code>SSL_SERVER_A_KEY</code></td>              <td>string</td>    <td>Algoritmo utilizado para la clave pública del certificado del servidor</td></tr>
<tr><td><code>SSL_SERVER_CERT</code></td>               <td>string</td>    <td>Certificado del servidor codificado en PEM</td></tr>
<tr><td><code>SSL_SRP_USER</code></td>                  <td>string</td>    <td>Nombre de usuario SRP</td></tr>
<tr><td><code>SSL_SRP_USERINFO</code></td>              <td>string</td>    <td>Información de usuario SRP</td></tr>
<tr><td><code>SSL_TLS_SNI</code></td>                   <td>string</td>    <td>Contenido de la extensión TLS SNI (si se provee en el ClientHello)</td></tr>
</table>

<p><em>x509</em> especifica un componente de un DN X.509; uno entre
<code>C,ST,L,O,OU,CN,T,I,G,S,D,UID,Email</code>.  En Apache 2.2.0 en
posterior, <em>x509</em> también puede incluir un sufijo <code>_n</code>
numérico. Si el DN en cuestión contiene múltiples atributos del mismo
nombre, este sufijo se usa para un índice basado en ceros para seleccionar
un atributo en particular.  Por ejemplo, donde el sujeto del DN del 
certificado del servidor incluirá dos atributos OU,
 <code>SSL_SERVER_S_DN_OU_0</code> y
<code>SSL_SERVER_S_DN_OU_1</code> podría usarse para referenciar cada una. 
Una variable sin un sufijo <code>_n</code> es equivalente a ese nombre con un
sufijo <code>_0</code>; el primer (y único) atributo.
Cuando la tabla del entorno se llena usando la opción <code>StdEnvVars</code> 
de la directiva <directive module="mod_ssl">SSLOptions</directive>, el primer
(o único) atributo de cualquier DN se añade sólo bajo un nombre sin sufijo; 
p. ej. no se añaden entradas con sufijo <code>_0</code>.</p>

<p>En httpd 2.5.0 y posterior, se puede añadir un sufijo <em>_RAW</em> a
<em>x509</em> en un componente DN para suprimir la conversión del valor
del atributo a UTF-8. Esto se debe colocar después del sufijo de indice (si lo 
hay). Por ejemplo, se podría usar <code>SSL_SERVER_S_DN_OU_RAW</code> o
<code>SSL_SERVER_S_DN_OU_0_RAW</code>.</p>

<p>El formato de las variables <em>*_DN</em> ha cambiado en Apache HTTPD
2.3.11. Vea la opción <code>LegacyDNStringFormat</code> para
<directive module="mod_ssl">SSLOptions</directive> para más detalles.</p>

<p><code>SSL_CLIENT_V_REMAIN</code> sólo está disponible en la versión 2.1 y
posterior.</p>

<p>Se puede usar varias variables de entorno adicionales con expresiones en
<directive>SSLRequire</directive>, o en formatos de log personalizados:</p>

<note><pre>HTTP_USER_AGENT        PATH_INFO             AUTH_TYPE
HTTP_REFERER           QUERY_STRING          SERVER_SOFTWARE
HTTP_COOKIE            REMOTE_HOST           API_VERSION
HTTP_FORWARDED         REMOTE_IDENT          TIME_YEAR
HTTP_HOST              IS_SUBREQ             TIME_MON
HTTP_PROXY_CONNECTION  DOCUMENT_ROOT         TIME_DAY
HTTP_ACCEPT            SERVER_ADMIN          TIME_HOUR
THE_REQUEST            SERVER_NAME           TIME_MIN
REQUEST_FILENAME       SERVER_PORT           TIME_SEC
REQUEST_METHOD         SERVER_PROTOCOL       TIME_WDAY
REQUEST_SCHEME         REMOTE_ADDR           TIME
REQUEST_URI            REMOTE_USER</pre></note>

<p>En estos contextos, también se pueden usar dos formatos especiales:</p>

<dl>
  <dt><code>ENV:<em>nombredevariable</em></code></dt>
  <dd>Esto se rellenará al valor de la variable de entorno estándar 
    <em>nombredevariable</em>.</dd>

  <dt><code>HTTP:<em>nombredecabecera</em></code></dt>
  <dd>Esto se rellenará con el valor de la cabecera de solicitud con el nombre
  <em>nombredecabecera</em>.</dd>
</dl>

</section>

<section id="logformats"><title>Formatos de Log Personalizados</title>

<p>Cuando se compila <module>mod_ssl</module> en Apache o al menos se carga (en
situación de DSO) existen funciones adicionales para el
<a href="mod_log_config.html#formats">Formatos de Log Personalizados</a> de
<module>mod_log_config</module>. Primero hay una función de extensión de formato 
adicional ``<code>%{</code><em>varname</em><code>}x</code>'' que puede usarse
para extender cualquier variable facilitada por cualquier módulo, especialmente 
aquellas que son facilitadas por mod_ssl que puede encontrar en la tabla de más
arriba.</p>
<p>

Para retro compatibilidad adicionalmente se facilita  una función de formato de 
criptografía ``<code>%{</code><em>nombre</em><code>}c</code>''. Información sobre
esta función se facilita en capítulo de <a 
href="../ssl/ssl_compat.html">Compatibilidad</a>.</p>
<example><title>Ejemplo</title>
<highlight language="config">
CustomLog "logs/ssl_request_log" "%t %h %{SSL_PROTOCOL}x %{SSL_CIPHER}x \"%r\" %b"
</highlight>
</example>
<p>Estos formatos incluso funcionan sin la opción de configuración
<code>StdEnvVars</code> de la directiva 
<directive module="mod_ssl">SSLOptions</directive>.</p>
</section>

<section id="notes"><title>Notas de Solicitud</title>

<p><module>mod_ssl</module> configura "notas" para la petición que pueden 
usarse en el registro de logs con la cadena de caracteres 
<code>%{<em>nombre</em>}n</code> en <module>mod_log_config</module>.</p>

<p>A continuación se indican las notas soportadas:</p>

<dl>
  <dt><code>ssl-access-forbidden</code></dt>
  <dd>Esta nota se configura al valor <code>1</code> si el acceso fue
  denegado debido a una directiva <directive>SSLRequire</directive> o
  <directive>SSLRequireSSL</directive>.</dd>

  <dt><code>ssl-secure-reneg</code></dt>
  <dd>Si se compila <module>mod_ssl</module> con una versión de OpenSSL que 
  soporta la extensión de renegociación segura, esta nota se configura con el 
  valor <code>1</code> si se usa SSL para la conexión actual y el cliente
  también soporta la extensión de renegociación segura.  Si el cliente no 
  soporta la extensión de renegociación segura, esta nota se configura con el valor
  <code>0</code>.
  Si se compila <module>mod_ssl</module> con una versión de OpenSSL que no
  soporta renegociación segura, o si SSL no se usa en la conexión actual, esta
  nota no se configura.</dd>
</dl>

</section>

<section id="expressionparser">
  <title>Extensión Intérprete de Expresiones</title>

<p>Cuando se compila <module>mod_ssl</module> en Apache o se carga 
(bajo situación DSO) cualquier <a name="envvars">variable</a>
facilitada por <module>mod_ssl</module> puede usarse en expresiones para el
 <a href="../expr.html">Intérprete de Expresiones ap_expr</a>.
Se puede hacer referencia a las variables usando la sintaxis
``<code>%{</code><em>varname</em><code>}</code>''. Comenzando con la versión
2.4.18 uno también puede usar el estilo de sintaxis de
<module>mod_rewrite</module> 
``<code>%{SSL:</code><em>nombredevariable</em><code>}</code>'' o el estilo de 
sintaxis de la función 
``<code>ssl(</code><em>nombredevariable</em><code>)</code>''.</p>

<example><title>Ejemplo (usando <module>mod_headers</module>)</title>
<highlight language="config">
Header set X-SSL-PROTOCOL "expr=%{SSL_PROTOCOL}"
Header set X-SSL-CIPHER "expr=%{SSL:SSL_CIPHER}"
</highlight>
</example>

<p>Esta característica funciona incluso sin configurar la opción
 <code>StdEnvVars</code> de la directiva 
 <directive module="mod_ssl">SSLOptions</directive>.</p>
</section>

<section id="authzproviders"><title>Proveedores de Autorización para su uso con
  Require</title>
  <p><module>mod_ssl</module> facilita unos pocos proveedores de autenticación
  para usarse con la directiva <directive module="mod_authz_core">Require</directive>
  de <module>mod_authz_core</module>.</p>

  <section id="reqssl"><title>Require ssl</title>
    <p>El proveedor de <code>ssl</code> deniega el acceso si la conexión no está
    encriptada con SSL. Esto es similar a la directiva 
    <directive>SSLRequireSSL</directive>.</p>
    <highlight language="config">
      Require ssl
    </highlight>
  </section>

  <section id="reqverifyclient"><title>Require ssl-verify-client</title>
    <p>El proveedor de <code>ssl</code> permite acceso si el usuario se autentica
    con un certificado cliente válido. Esto sólo es útil si se está usando
    <code>SSLVerifyClient optional</code>.</p>

    <p>El siguiente ejemplo permite acceso si el usuario se autentica o bien
      con certificado cliente o con usuario y contraseña.</p>
    <highlight language="config">
Require ssl-verify-client
Require valid-user
    </highlight>

  </section>

</section>

<directivesynopsis>
<name>SSLPassPhraseDialog</name>
<description>Tipo de díalogo de solicitud de contraseña para claves privadas 
  encriptadas</description>
<syntax>SSLPassPhraseDialog <em>tipo</em></syntax>
<default>SSLPassPhraseDialog builtin</default>
<contextlist><context>server config</context></contextlist>

<usage>
<p>
Cuando Apache arranca tiene que leer varios ficheros Certificado (vea
<directive module="mod_ssl">SSLCertificateFile</directive>) y Clave Privada 
(vea 
<directive module="mod_ssl">SSLCertificateKeyFile</directive>) de los servidores
virtuales que tienen SSL activado. Por razones de seguridad los ficheros
de clave privada están generalmente cifrados, mod_ssl necesita preguntar al
administrador por la contraseña para desencriptar esos ficheros. Esta solicitud
puede hacerse de dos maneras que se pueden configurar por
<em>tipo</em>:</p>
<ul>
<li><code>builtin</code>
    <p>
    Este es el método por defecto donde una ventana de terminal interactiva
    aparece al inicio antes que Apache pase a segundo plano. Aquí un
    administrador tiene que introducir manualmente la contraseña para cada
    fichero de Clave Privada cifrado. Puesto que puede haber muchos 
    hosts virtuales configurados con SSL, se usa el siguiente esquema de 
    reutilización para minimizar el número de veces que se pide la contraseña:
    Cuanto un fichero de clave privada está encriptado, se intentará usar
    todas las Contraseñas conocidas (al principio no hay ninguna, por supuesto). 
    Si una de esas contraseñas conocidas funciona no se abre ventana de diálogo
    para este fichero de clave privada en particular. Si ninguna funciona, 
    se vuelve a solicitar la contraseña en la terminal y se recuerda para las
    siguientes (donde quizás se pueden reutilizar).</p>
    <p>
    Este esquema permite a mod_ssl ser flexible al máximo (porque para N 
    ficheros de Clave Privada cifrados <em>usted puede</em> usar N 
    contraseñas diferentes - pero entonces tiene que introducir todas ellas, por
    supuesto) al mismo tiempo que se minimizan las solicitudes de contraseña
    por terminal (p.ej. cuando usa una sola contraseña para todos los N ficheros
    de Clave Privada esta contraseña sólo se pide una vez).</p></li>

<li><code>|/path/to/program [args...]</code>

   <p>Este modo permite que se use un programa externo que actúa como tubería a
    un dispositivo de entrada en particular; al programa se le envía la 
    solicitud estándar de texto que se usa para el modo <code>builtin</code> en
   <code>stdin</code>, y se espera que escriba cadenas de caracteres de 
   contraseñas en <code>stdout</code>. Si se necesitan varias contraseñas (o si
   se introduce una contraseña incorrecta), se escribirán solicitudes de 
   contraseña adicionales y se tendrá que devolver más contraseñas a través
   de dicho programa.</p></li>

<li><code>exec:/path/to/program</code>
    <p>
    Aquí se configura un programa externo que se lanza en el arranque para cada
    uno de los ficheros de Clave Privada encriptados. Se le llama con un sólo
    parámetro, una cadena de caracteres de la forma 
    ``<code>servername:portnumber:index</code>'' (cuando <code>index</code> es 
    un número basado en una secuencia de ceros), que indica para qué servidor,
    puerto TCP y número de certificado debe imprimir la Contraseña
    correspondiente a <code>stdout</code>.  La intención es que este programa 
    externo primero ejecuta comprobaciones de seguridad para asegurar que el 
    sistema no se ha visto comprometido por un atacante, y sólo cuando estas
    comprobaciones se realizan satisfactoriamente entonces facilita la
    Contraseña.</p>

    <p>
    Ambas comprobaciones de seguridad y el método en que se determina la 
    contraseña, puede ser tan complejo como usted desee. Mod_ssl sólo define 
    el interfaz: un programa ejecutable que provee la contraseña en 
    <code>stdout</code>. Ni más y ni menos. Así que, si usted es realmente
    paranoico con la seguridad, este es su interfaz. Cualquier otra cosa se debe
    dejar como un trabajo para el administrador, porque los requerimientos de 
    seguridad local son muy diferentes.</p>
    
    <p>
    El algoritmo de reutilización descrito previamente se usa aquí también. En 
    otras palabras: se llama sólo una vez al programa externo cuando hay una 
    única contraseña.</p></li>
</ul>
<example><title>Ejemplo</title>
<highlight language="config">
SSLPassPhraseDialog "exec:/usr/local/apache/sbin/pp-filter"
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLRandomSeed</name>
<description>Fuente de generación de semilla pseudoaleatoria de números 
  (PRNG)</description>
<syntax>SSLRandomSeed <em>contexto</em> <em>fuente</em>
[<em>bytes</em>]</syntax>
<contextlist><context>server config</context></contextlist>

<usage>
  <p>
  Esto configura una o más fuentes de generación de semilla pseudoaleatoria de 
  números "Pseudo Random Number Generator (PRNG)" en OpenSSL en el arranque 
  (<em>contexto</em> es <code>startup</code>) y/o justo antes de que se 
  establezca una nueva conexión SSL
  (<em>contexto</em> es <code>connect</code>). Esta directiva sólo se puede usar
  en el contexto global de configuración del servidor porque PRNG es una
  característica global.</p>
  <p>
  Las siguientes variante de <em>fuente</em> están disponibles:</p>
  <ul>
  <li><code>builtin</code>
    <p>Esta es siempre la fuente de generación de semilla que está siempre 
    disponible. Usa el mínimo de ciclos de CPU en tiempo real así que se puede
    usar siempre sin contratiempos. La fuente utilizada para la generación de
    semilla de PRNG contiene la hora actual, el id de proceso actual y 
    (cuando es aplicable) un extracto de 1KB escogido aleatoriamente de la
    estructura de scoreboard de Apache. La pega es que no es realmente una 
    fuente muy compleja y en el momento del arranque (cuando el scoreboard 
    todavía no está disponible) esta fuente sólo produce unos pocos bytes de 
    entropía. Así que usted debería, al menos en el arranque, usar una fuente
    adicional de generación de semilla.</p></li>

    <li><code>file:/ruta/hacia/la/fuente</code>
    <p>
    Esta variante usa un fichero externo <code>/ruta/hacia/la/fuente</code> con
    la fuente de generación de semilla para PRNG. Cuando se especifica 
    <em>bytes</em>, sólo los primeros <em>bytes</em> del número de bytes del 
    fichero forman la entropía (y <em>bytes</em> se da a 
    <code>/ruta/hacia/la/fuente</code> como el primer parámetro). Cuando
    no se especifica <em>bytes</em> el fichero al completo forma la entropía
    (y <code>0</code> se da a <code>/ruta/hacia/la/fuente</code> como primer
    parámetro). Use esto especialmente en el arranque, por ejemplo con 
    dispositivos disponibles <code>/dev/random</code> y/o
    <code>/dev/urandom</code> (que generalmente existen en derivados de Unix
    modernos como FreeBSD y Linux).</p>
    <p>
    <em>Pero tenga cuidado</em>: Generalmente <code>/dev/random</code> facilita
    sólo tantos datos de entropía como tiene en ese momento, p.ej. cuando solicita
    512 bytes de entropía, pero el dispositivo sólo tiene 100 bytes disponibles
    dos cosas pasan: En algunas plataformas recibe sólo 100 bytes mientras que 
    en otras plataformas la lectura se bloquea hasta que hay suficientes bytes 
    disponibles (lo cual puede llevar bastante tiempo). Aquí usar un
    <code>/dev/urandom</code> existente es mejor, porque nunca bloquea y porque
    facilita la cantidad de datos solicitada. La pega es que la calidad de los 
    datos recibidos puede que no sea la mejor.</p></li>

<li><code>exec:/ruta/al/programa</code>
    <p>
    Esta variante usa un ejecutable externo
    <code>/ruta/al/programa</code> como la fuente de generación de semilla de
    PRNG. Cuando se especifica <em>bytes</em>, sólo los primeros
    <em>bytes</em> del número de bytes de su contenido de <code>stdout</code> 
    forman la entropía. Cuando no se especifica <em>bytes</em>, el total de los
    datos producidos en <code>stdout</code> forman la entropía. Use esto sólo
    en el tiempo de arranque cuando necesita una generación de semilla muy 
    compleja con la ayuda de un programa externo (como en el
    ejemplo de más arriba con la utilidad <code>truerand</code> que puede
    encontrar en la distribución de mod_ssl que está basada en la librería 
    <em>truerand</em> de  AT&amp;T). Usar esto en contexto de conexión
    ralentiza al servidor de manera dramática, por supuesto. Así que debería 
    evitar programas externos en ese contexto. </p></li>

<li><code>egd:/ruta/al/egd-socket</code> (Sólo Unix)
    <p>
    Esta variante usa el socket de dominio Unix del Demonio de Recolección de 
    Entropía externo (Entropy Gathering Daemon (EGD)) (vea <a
    href="http://www.lothar.com/tech/crypto/">http://www.lothar.com/tech
    /crypto/</a>) para generar semilla de PRNG. Use esto si no hay un 
    dispositivo de generación de datos aleatorios en su sistema.</p></li>
</ul>

<example><title>Ejemplo</title>
<highlight language="config">
SSLRandomSeed startup builtin
SSLRandomSeed startup "file:/dev/random"
SSLRandomSeed startup "file:/dev/urandom" 1024
SSLRandomSeed startup "exec:/usr/local/bin/truerand" 16
SSLRandomSeed connect builtin
SSLRandomSeed connect "file:/dev/random"
SSLRandomSeed connect "file:/dev/urandom" 1024
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLSessionCache</name>
<description>Tipo de la Caché global/interproceso de la sesión SSL</description>
<syntax>SSLSessionCache <em>tipo</em></syntax>
<default>SSLSessionCache none</default>
<contextlist><context>server config</context></contextlist>

<usage>
<p>
Esto configura el tipo de almacenamiento para la Cache global/interproceso de 
la sesión SSL. Esta cache es una característica opcional que acelera el 
procesamiento de peticiones en paralelo. Para peticiones con el mismo
proceso de servidor (a través de keep-alive HTTP), OpenSSL ya cachea la 
información de sesión de SSL localmente. Pero puesto que los clientes modernos
solicitan imágenes y otros datos a través de peticiones en paralelo 
(generalmente hasta cuatro peticiones en paralelo es lo típico) esas peticiones 
se sirven por procesos de servidor <em>diferentes</em>. Aquí la cache de
inter-proceso ayuda para evitar saludos de sesión SSL innecesarios.</p>
<p>

Los cinto <em>tipos</em> de almacenamientos siguientes están soportados:</p>
<ul>
<li><code>none</code>

    <p>Esto desactiva la Cache de Sesión de interproceso/global. Esto 
    repercutirá en un descenso de la velocidad notable y puede causar problemas
    con ciertos navegadores, particularmente si están activados los certificados
    cliente. Esta configuración no se recomienda.</p></li>

<li><code>nonenotnull</code>

    <p>Esto sólo desactiva la Cache de Sesión de interproceso/global. Aun así no
    fuerza a OpenSSL a enviar ID de sesión no-nula para adaptarse a clientes
    que requieren una.</p></li>

<li><code>dbm:/ruta/al/ficherodedatos</code>

    <p>Esto hace uso del fichero de hash DBM en el disco local para sincronizar 
    las caches de memoria del OpenSSL de los procesos del servidor. Esta caché 
    de sesión puede tener problemas de fiabilidad cuando hay carga alta. Para
    usarla, asegúrese de que 
    <module>mod_socache_dbm</module> está cargado.</p></li>

<li><code>shmcb:/ruta/al/ficherodedatos</code>[<code>(</code><em>tamaño</em><code>)</code>]

    <p>Esto hace uso del búfer cíclico de alto rendimiento
    (approx. <em>tamaño</em> bytes de tamaño) dentro de un segmento de memoria
    compartida en RAM (establecida con <code>/ruta/al/ficherodedatos</code>) 
    para sincronizar las caches de memoria del OpenSSL local de los procesos del
    servidor. Esta es la caché de sesión recomendada. Para usarla, asegúrese de 
    que <module>mod_socache_shmcb</module> está cargado.</p></li>

<li><code>dc:UNIX:/ruta/al/socket</code>

    <p>Esto hace uso de las librerías de almacenamiento en caché de sesión 
      distribuida.<a href="http://distcache.sourceforge.net/">distcache</a>.
      El parámetro debería especificar la ubicación del servidor o proxy para 
      ser usado con distcache usando sintaxis de dirección; por ejemplo, 
    <code>UNIX:/ruta/al/socket</code> especifica un socket de dominio UNIX
    (típicamente un proxy dc_client local);
    <code>IP:server.example.com:9001</code> especifica una dirección IP. Para
    usar esto, asegúrese de que <module>mod_socache_dc</module> está 
    cargado.</p></li>

</ul>

<example><title>Ejemplos</title>
<highlight language="config">
SSLSessionCache "dbm:/usr/local/apache/logs/ssl_gcache_data"
SSLSessionCache "shmcb:/usr/local/apache/logs/ssl_gcache_data(512000)"
</highlight>
</example>

<p>El mutex <code>ssl-cache</code> se usa para serializar el acceso a la cache 
de sesión para prevenir corrupción. Este mutex puede configurarse usando la 
directiva <directive module="core">Mutex</directive>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLSessionCacheTimeout</name>
<description>Número de segundos antes de que la sesión SSL expira 
  en la Cache de Sesión</description>
<syntax>SSLSessionCacheTimeout <em>segundos</em></syntax>
<default>SSLSessionCacheTimeout 300</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Aplica también al RFC 5077 de reanudación de sesión en
  Apache 2.4.10 o posterior</compatibility>

<usage>
<p>
Esta directiva configura el tiemplo límite en segundos para la información 
guardada en  la caché de sesión SSL de interproceso/global, la caché de memoria 
interna de OpenSSL y para las sesiones reanudadas por la reanudación de sesión 
de TLS (RFC 5077). Puede ponerse hasta un mínimo de 15 para hacer pruebas, pero 
debería configurarse con valores como 300 en entornos funcionales.</p>
<example><title>Ejemplo</title>
<highlight language="config">
SSLSessionCacheTimeout 600
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLEngine</name>
<description>Interruptor de Activación del motor SSL</description>
<syntax>SSLEngine on|off|optional|addr[:port] [addr[:port]] ...</syntax>
<default>SSLEngine off</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>El parámetro <code>addr:port</code> está disponible en Apache 
2.4.30 y posterior.</compatibility>

<usage>
<p>
Esta directiva sirve para activar o desactivar el uso del motor del protocolo
SSL/TLS. Los valores 'on', 'off' y 'optional' deberían usarse dentro de una
sección <directive module="core" type="section">VirtualHost</directive> para
activar SSL/TLS para un host virtual. Por defecto el motor de SSL/TLS está
deshabilitado para ambos el servidor principal y todos los host virtuales
configurados.</p>

<example><title>Ejemplo</title>
<highlight language="config">
&lt;VirtualHost _default_:443&gt;
SSLEngine on
#...
&lt;/VirtualHost&gt;
</highlight>
</example>
<p>Se deberían usar los valores <code>addr:port</code> en la configuración 
global del servidor para activar el motor del Protocolo SSL/TLS para 
<em>todos</em> los
<directive module="core" type="section">VirtualHost</directive> 
que coincidan con una de las direcciones de la lista.</p>
<example><title>Ejemplo</title>
<highlight language="config">
SSLEngine *:443
&lt;VirtualHost *:443&gt;
#...
&lt;/VirtualHost&gt;
</highlight>
</example>
<p><directive>SSLEngine</directive> puede ser configurado a
<code>optional</code>: esto activa el soporte de 
<a href="http://www.ietf.org/rfc/rfc2817.txt">RFC 2817</a>.
</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLFIPS</name>
<description>Interruptor del modo SSL FIPS</description>
<syntax>SSLFIPS on|off</syntax>
<default>SSLFIPS off</default>
<contextlist><context>server config</context></contextlist>

<usage>
<p>
Esta directiva activa o desactiva el uso de FIPS_mode en la librería SSL. Esto
debe ponerse en el contexto de la configuración global del servidor y no puede 
configurarse con otras configuraciones que especifiquen lo contrario (SSLFIPS on 
seguido de SSLFIPS off o similar). Este modo se aplica a todas las operaciones
de la librería SSL.
</p>

<p>
Si httpd fuera compilado contra una librería SSL que no soporta FIPS_mode, 
<code>SSLFIPS on</code> fallará. Vea el documento de Políticas de Seguridad
FIPS 140-2 de su proveedor de librería SSL para requerimientos específicos para
usar mod_ssl en un modo de operación aprobado; tenga en cuenta que mod_ssl
en sí mismo no está validado, pero puede ser descrito como un módulo 
validado de criptografía FIPS 140-2, cuando todos los componentes son montados
y gestionados bajo las reglas impuestas por la Política de Seguridad aplicable.
</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLProtocol</name>
<description>Configura versiones de protocolo SSL/TLS utilizables</description>
<syntax>SSLProtocol [+|-]<em>protocol</em> ...</syntax>
<default>SSLProtocol all -SSLv3</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>

<usage>
<p>
Se puede usar esta directiva para controlar que versiones del protocolo SSL/TLS
serán aceptadas en las nuevas conexiones.</p>
<p>
Los <em>protocolos</em> disponibles (no sensibles a mayúsculas) son:</p>
<ul>
<li><code>SSLv3</code>
    <p>
    Este es el protocolo de Secure Sockets Layer (SSL), versión 3.0, de la 
    empresa Netscape. Es el sucesor a SSLv2 y el predecesor de TLSv1, pero
    se ha marcado ya como obsoleto en 
    <a href="http://www.ietf.org/rfc/rfc7568.txt">RFC 7568</a>.</p></li>

<li><code>TLSv1</code>
    <p>
    Este es el protocolo Transport Layer Security (TLS), versión 1.0.
    Es el sucesor de SSLv3 y está definido en
    <a href="http://www.ietf.org/rfc/rfc2246.txt">RFC 2246</a>.
    Está soportado por casi cualquier cliente.</p></li>

<li><code>TLSv1.1</code> (cuando se usa OpenSSL 1.0.1 y posterior)
    <p>
    Una revisión del protocolo TLS 1.0, tal y como se define en
    <a href="http://www.ietf.org/rfc/rfc4346.txt">RFC 4346</a>.</p></li>

<li><code>TLSv1.2</code> (cuando se usa OpenSSL 1.0.1 y posterior)
    <p>
    Una revisión del protocolo TLS 1.1, tal y como se define en
    <a href="http://www.ietf.org/rfc/rfc5246.txt">RFC 5246</a>.</p></li>

<li><code>all</code>
    <p>
    Esto es un atajo para ``<code>+SSLv3 +TLSv1</code>'' o
    - cuando se usa OpenSSL 1.0.1 y posterior -
    ``<code>+SSLv3 +TLSv1 +TLSv1.1 +TLSv1.2</code>'', respectivamente
    (excepto para versiones de OpenSSL compiladas con la opción de configuración
    ``no-ssl3'', donde <code>all</code> no incluye <code>+SSLv3</code>).
  </p></li>
</ul>
<example><title>Ejemplo</title>
<highlight language="config">
SSLProtocol TLSv1
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLCipherSuite</name>
<description>Conjunto de Cifrados disponibles para negociación en el saludo SSL
</description>
<syntax>SSLCipherSuite <em>especificación-de-cifrado</em></syntax>
<default>SSLCipherSuite DEFAULT (depende de la versión de OpenSSL)</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context></contextlist>
<override>AuthConfig</override>

<usage>
<p>
Esta compleja directiva usa una cadena de <em>cifrados</em> separados por comas
que consiste en especificaciones de cifrado OpenSSL para configurar el conjunto
de cifrados que se le permite negociar al cliente en la fase de saludo SSL. 
Tenga en cuenta que esta directiva se puede usar en contexto de servidor y de
directorio. En contexto de servidor aplica el saludo estándar de SSL cuando se
establece una conexión. En contexto directorio fuerza una renegociación SSL con 
el juego de cifrados después de que la solicitud HTTP ha sido leída pero antes de
que se envíe la respuesta.</p>
<p>
Una especificación de cifrado SSL en <em>especificación-de-cifrado</em> se compone de 4 
atributos principales más unos cuantos menores extra:</p>
<ul>
<li><em>Algoritmo de Intercambio de Clave</em>:<br />
    RSA, Diffie-Hellman, Elliptic Curve Diffie-Hellman, Secure Remote Password
</li>
<li><em>Algoritmo de Autenticación</em>:<br />
    RSA, Diffie-Hellman, DSS, ECDSA, or none.
</li>
<li><em>Algoritmo de Cifrado/Encriptación</em>:<br />
    AES, DES, Triple-DES, RC4, RC2, IDEA, etc.
</li>
<li><em>Algoritmo de Resúmen de MAC</em>:<br />
    MD5, SHA or SHA1, SHA256, SHA384.
</li>
</ul>

<p>Un cifrado SSL puede ser un cifrado export. Los cifrados SSLv2 ya no están
soportados. Para especificar qué cifrados usar, uno puede especificar todos
los cifrados a utilizar, de uno en uno, o puede usar alias para
especificar la preferencia y orden de los cifrados (vea <a href="#table1">Tabla
1</a>). La lista actual de cifrados y alias depende de la versión openssl
utilizada. Versiones más modernas de openssl pueden incluir cifrados 
adicionales.</p>

<table border="1">
<columnspec><column width=".5"/><column width=".5"/></columnspec>
<tr><th><a name="table1">Tag</a></th> <th>Description</th></tr>
<tr><td colspan="2"><em>Algoritmo de Intercambio de Clave:</em></td></tr>
<tr><td><code>kRSA</code></td>   <td>RSA key exchange</td></tr>
<tr><td><code>kDHr</code></td>   <td>Diffie-Hellman key exchange with RSA key</td></tr>
<tr><td><code>kDHd</code></td>   <td>Diffie-Hellman key exchange with DSA key</td></tr>
<tr><td><code>kEDH</code></td>   <td>Ephemeral (temp.key) Diffie-Hellman key exchange (no cert)</td>   </tr>
<tr><td><code>kSRP</code></td>   <td>Secure Remote Password (SRP) key exchange</td></tr>
<tr><td colspan="2"><em>Algoritmo de Autenticación:</em></td></tr>
<tr><td><code>aNULL</code></td>  <td>No authentication</td></tr>
<tr><td><code>aRSA</code></td>   <td>RSA authentication</td></tr>
<tr><td><code>aDSS</code></td>   <td>DSS authentication</td> </tr>
<tr><td><code>aDH</code></td>    <td>Diffie-Hellman authentication</td></tr>
<tr><td colspan="2"><em>Algoritmo de Codificación de Cifrado:</em></td></tr>
<tr><td><code>eNULL</code></td>  <td>No encryption</td>         </tr>
<tr><td><code>NULL</code></td>   <td>alias for eNULL</td>         </tr>
<tr><td><code>AES</code></td>    <td>AES encryption</td>        </tr>
<tr><td><code>DES</code></td>    <td>DES encryption</td>        </tr>
<tr><td><code>3DES</code></td>   <td>Triple-DES encryption</td> </tr>
<tr><td><code>RC4</code></td>    <td>RC4 encryption</td>       </tr>
<tr><td><code>RC2</code></td>    <td>RC2 encryption</td>       </tr>
<tr><td><code>IDEA</code></td>   <td>IDEA encryption</td>       </tr>
<tr><td colspan="2"><em>Algoritmo de Resumen de MAC</em>:</td></tr>
<tr><td><code>MD5</code></td>    <td>MD5 hash function</td></tr>
<tr><td><code>SHA1</code></td>   <td>SHA1 hash function</td></tr>
<tr><td><code>SHA</code></td>    <td>alias for SHA1</td> </tr>
<tr><td><code>SHA256</code></td> <td>SHA256 hash function</td> </tr>
<tr><td><code>SHA384</code></td> <td>SHA384 hash function</td> </tr>
<tr><td colspan="2"><em>Aliases:</em></td></tr>
<tr><td><code>SSLv3</code></td>  <td>all SSL version 3.0 ciphers</td> </tr>
<tr><td><code>TLSv1</code></td>  <td>all TLS version 1.0 ciphers</td> </tr>
<tr><td><code>EXP</code></td>    <td>all export ciphers</td>  </tr>
<tr><td><code>EXPORT40</code></td> <td>all 40-bit export ciphers only</td>  </tr>
<tr><td><code>EXPORT56</code></td> <td>all 56-bit export ciphers only</td>  </tr>
<tr><td><code>LOW</code></td>    <td>all low strength ciphers (no export, single DES)</td></tr>
<tr><td><code>MEDIUM</code></td> <td>all ciphers with 128 bit encryption</td> </tr>
<tr><td><code>HIGH</code></td>   <td>all ciphers using Triple-DES</td>     </tr>
<tr><td><code>RSA</code></td>    <td>all ciphers using RSA key exchange</td> </tr>
<tr><td><code>DH</code></td>     <td>all ciphers using Diffie-Hellman key exchange</td> </tr>
<tr><td><code>EDH</code></td>    <td>all ciphers using Ephemeral Diffie-Hellman key exchange</td> </tr>
<tr><td><code>ECDH</code></td>   <td>Elliptic Curve Diffie-Hellman key exchange</td>   </tr>
<tr><td><code>ADH</code></td>    <td>all ciphers using Anonymous Diffie-Hellman key exchange</td> </tr>
<tr><td><code>AECDH</code></td>    <td>all ciphers using Anonymous Elliptic Curve Diffie-Hellman key exchange</td> </tr>
<tr><td><code>SRP</code></td>    <td>all ciphers using Secure Remote Password (SRP) key exchange</td> </tr>
<tr><td><code>DSS</code></td>    <td>all ciphers using DSS authentication</td> </tr>
<tr><td><code>ECDSA</code></td>    <td>all ciphers using ECDSA authentication</td> </tr>
<tr><td><code>aNULL</code></td>   <td>all ciphers using no authentication</td> </tr>
</table>

<p>
La parte en que ésto se vuelve interesante es que éstos se pueden poner juntos
para especificar el orden y los cifrados que quiere usar. Para acelerar esto
también hay pseudónimos (<code>SSLv3, TLSv1, EXP, LOW, MEDIUM,
HIGH</code>) para ciertos grupos de cifrados. Estas etiquetas se pueden juntar
con prefijos para formar <em>especificación-de-cifrado</em>. Los prefijos disponibles son:</p>

<ul>
<li>none: añade cifrado a la lista</li>
<li><code>+</code>: mueve los cifrados coincidentes a la ubicación actual en la 
lista</li>
<li><code>-</code>: borra los cifrados de la lista (se pueden añadir más 
adelante)</li>
<li><code>!</code>: mata el cifrado de la lista completamente 
(<strong>no</strong> puede añadirse después)</li>
</ul>

<note>
<title>Los cifrados <code>aNULL</code>, <code>eNULL</code> y <code>EXP</code>
siempre están deshabilitados</title>
<p>Empezando con la versión 2.4.7, null y cifrados de grado export
están siempre deshabilitados, asi que mod_ssl añade incondicionalmente 
<code>!aNULL:!eNULL:!EXP</code> a cualquier lista de cifrados en la 
inicialización.</p>
</note>

<p>Una forma más sencilla de ver todo esto es usar el comando 
``<code>openssl ciphers -v</code>'' que facilita una buena forma de crear una
cadena correcta de <em>especificación-de-cifrado</em>. La cadena <em>especificación-de-cifrado</em> depende
de la versión de librerías OpenSSL utilizadas. Supongamos que es
``<code>RC4-SHA:AES128-SHA:HIGH:MEDIUM:!aNULL:!MD5</code>'' que significa
lo siguiente: Pon <code>RC4-SHA</code> y <code>AES128-SHA</code> al principio.
Hacemos esto, porque estos cifrados ofrecen un buen compromiso entre velocidad y
seguridad. Después, incluye los cifrados de seguridad alta y media. Finalmente,
elimina todos los cifrados que no autentican, p.ej. para SSL los cifrados 
Anónimos Diffie-Hellman, así como todos los cifrados que usan <code>MD5</code> 
como algoritmo de hash porque se ha probado que son insuficientes.</p>
<example>
<pre>
$ openssl ciphers -v 'RC4-SHA:AES128-SHA:HIGH:MEDIUM:!aNULL:!MD5'
RC4-SHA                 SSLv3 Kx=RSA      Au=RSA  Enc=RC4(128)  Mac=SHA1
AES128-SHA              SSLv3 Kx=RSA      Au=RSA  Enc=AES(128)  Mac=SHA1
DHE-RSA-AES256-SHA      SSLv3 Kx=DH       Au=RSA  Enc=AES(256)  Mac=SHA1
...                     ...               ...     ...           ...
SEED-SHA                SSLv3 Kx=RSA      Au=RSA  Enc=SEED(128) Mac=SHA1
PSK-RC4-SHA             SSLv3 Kx=PSK      Au=PSK  Enc=RC4(128)  Mac=SHA1
KRB5-RC4-SHA            SSLv3 Kx=KRB5     Au=KRB5 Enc=RC4(128)  Mac=SHA1
</pre>
</example>
<p>La lista completa de cifrados RSA &amp; DH concretos para SSL se facilita en
la <a href="#table2">Tabla 2</a>.</p>
<example><title>Ejemplo</title>
<highlight language="config">
SSLCipherSuite RSA:!EXP:!NULL:+HIGH:+MEDIUM:-LOW
</highlight>
</example>
<table border="1">
<columnspec><column width=".3"/><column width=".1"/><column width=".13"/>
<column width=".1"/><column width=".13"/><column width=".1"/>
<column width=".13"/></columnspec>
<tr><th><a name="table2">Cipher-Tag</a></th> <th>Protocol</th> <th>Key Ex.</th> <th>Auth.</th> <th>Enc.</th> <th>MAC</th> <th>Type</th> </tr>
<tr><td colspan="7"><em>RSA Ciphers:</em></td></tr>
<tr><td><code>DES-CBC3-SHA</code></td> <td>SSLv3</td> <td>RSA</td> <td>RSA</td> <td>3DES(168)</td> <td>SHA1</td> <td></td> </tr>
<tr><td><code>IDEA-CBC-SHA</code></td> <td>SSLv3</td> <td>RSA</td> <td>RSA</td> <td>IDEA(128)</td> <td>SHA1</td> <td></td> </tr>
<tr><td><code>RC4-SHA</code></td> <td>SSLv3</td> <td>RSA</td> <td>RSA</td> <td>RC4(128)</td> <td>SHA1</td> <td></td> </tr>
<tr><td><code>RC4-MD5</code></td> <td>SSLv3</td> <td>RSA</td> <td>RSA</td> <td>RC4(128)</td> <td>MD5</td> <td></td> </tr>
<tr><td><code>DES-CBC-SHA</code></td> <td>SSLv3</td> <td>RSA</td> <td>RSA</td> <td>DES(56)</td> <td>SHA1</td> <td></td> </tr>
<tr><td><code>EXP-DES-CBC-SHA</code></td> <td>SSLv3</td> <td>RSA(512)</td> <td>RSA</td> <td>DES(40)</td> <td>SHA1</td> <td> export</td> </tr>
<tr><td><code>EXP-RC2-CBC-MD5</code></td> <td>SSLv3</td> <td>RSA(512)</td> <td>RSA</td> <td>RC2(40)</td> <td>MD5</td> <td>  export</td> </tr>
<tr><td><code>EXP-RC4-MD5</code></td> <td>SSLv3</td> <td>RSA(512)</td> <td>RSA</td> <td>RC4(40)</td> <td>MD5</td> <td>  export</td> </tr>
<tr><td><code>NULL-SHA</code></td> <td>SSLv3</td> <td>RSA</td> <td>RSA</td> <td>None</td> <td>SHA1</td> <td></td> </tr>
<tr><td><code>NULL-MD5</code></td> <td>SSLv3</td> <td>RSA</td> <td>RSA</td> <td>None</td> <td>MD5</td> <td></td> </tr>
<tr><td colspan="7"><em>Diffie-Hellman Ciphers:</em></td></tr>
<tr><td><code>ADH-DES-CBC3-SHA</code></td> <td>SSLv3</td> <td>DH</td> <td>None</td> <td>3DES(168)</td> <td>SHA1</td> <td></td> </tr>
<tr><td><code>ADH-DES-CBC-SHA</code></td> <td>SSLv3</td> <td>DH</td> <td>None</td> <td>DES(56)</td> <td>SHA1</td> <td></td> </tr>
<tr><td><code>ADH-RC4-MD5</code></td> <td>SSLv3</td> <td>DH</td> <td>None</td> <td>RC4(128)</td> <td>MD5</td> <td></td> </tr>
<tr><td><code>EDH-RSA-DES-CBC3-SHA</code></td> <td>SSLv3</td> <td>DH</td> <td>RSA</td> <td>3DES(168)</td> <td>SHA1</td> <td></td> </tr>
<tr><td><code>EDH-DSS-DES-CBC3-SHA</code></td> <td>SSLv3</td> <td>DH</td> <td>DSS</td> <td>3DES(168)</td> <td>SHA1</td> <td></td> </tr>
<tr><td><code>EDH-RSA-DES-CBC-SHA</code></td> <td>SSLv3</td> <td>DH</td> <td>RSA</td> <td>DES(56)</td> <td>SHA1</td> <td></td> </tr>
<tr><td><code>EDH-DSS-DES-CBC-SHA</code></td> <td>SSLv3</td> <td>DH</td> <td>DSS</td> <td>DES(56)</td> <td>SHA1</td> <td></td> </tr>
<tr><td><code>EXP-EDH-RSA-DES-CBC-SHA</code></td> <td>SSLv3</td> <td>DH(512)</td> <td>RSA</td> <td>DES(40)</td> <td>SHA1</td> <td> export</td> </tr>
<tr><td><code>EXP-EDH-DSS-DES-CBC-SHA</code></td> <td>SSLv3</td> <td>DH(512)</td> <td>DSS</td> <td>DES(40)</td> <td>SHA1</td> <td> export</td> </tr>
<tr><td><code>EXP-ADH-DES-CBC-SHA</code></td> <td>SSLv3</td> <td>DH(512)</td> <td>None</td> <td>DES(40)</td> <td>SHA1</td> <td> export</td> </tr>
<tr><td><code>EXP-ADH-RC4-MD5</code></td> <td>SSLv3</td> <td>DH(512)</td> <td>None</td> <td>RC4(40)</td> <td>MD5</td> <td>  export</td> </tr>
</table>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLCertificateFile</name>
<description>Fichero de datos Certificado X.509 codificado en PEM</description>
<syntax>SSLCertificateFile <em>ruta-al-fichero</em></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>

<usage>
<p>
Esta directiva apunta a un fichero con datos de certificado en formato PEM. Como
mínimo, el fichero debe incluir un certificado final (no sólo CA a menos que sea
autofirmado). La directiva puede usarse multiples veces (haciendo referencia a
ficheros distintos) para dar soporte a múltiples algoritmos para la 
autenticación de servidor - típicamente RSA, DSA y ECC. El número de algoritmos
soportados depende de la versión de OpenSSL utilizada por mod_ssl: con la versión
1.0.0 o posterior,
<code>openssl list-public-key-algorithms</code> sacará una lista de algoritmos
soportados, vea también la nota más adelante sobre limitaciones de versiones
OpenSSL previas a 1.0.2 y la forma de sortearlas.
</p>

<p>
Los ficheros pueden también incluir certificados de CA intermedias, ordenados 
desde el certificado firmado hasta el certificado raíz. Esto está soportado con 
la versión 2.4.8 y posterior, y deja obsoleta la directiva 
<directive module="mod_ssl">SSLCertificateChainFile</directive>.
Cuando se trabaja con OpenSSL 1.0.2 o posterior, esto permite que se configuren
la cadena de CAs intermedias por certificado.
</p>

<p>
También se pueden añadir parámetros personalizados DH y un nombre de curva EC 
para claves efímeras al final del primer fichero configurado usando 
<directive module="mod_ssl">SSLCertificateFile</directive>.
Esto está soportado en la versión 2.4.7 y posterior.

Tales parámetros pueden ser generados usando los comandos
<code>openssl dhparam</code> y <code>openssl ecparam</code>. Los parámetros se 
pueden añadir tal cual al final del primer fichero de certificado. sólo se puede
usar el primer fichero para los parámetros personalizados, puesto que estos
se aplican independientemente del tipo de algoritmo de autenticación.
</p>

<p>
Finalmente la clave privada del certificado también se puede añadir al fichero
de certificado en lugar de usar por separado la directiva 
<directive module="mod_ssl">SSLCertificateKeyFile</directive>. Esta práctica
está muy desaconsejada. Si se usa, los ficheros de certificado usando tales
ficheros de claves embebidas deben configurarse después de los certificados que
usan una clave privada en un fichero aparte. Si la clave privada está encriptada
, el diálogo de solicitud de contraseña se fuerza en el arranque.
</p>

<note>
<title>Interoperabilidad de parámetro DH con primos > 1024 bits</title>
<p>
Comenzando con la versión 2.4.7, mod_ssl hace uso de parámetros DH 
estandarizados con longitud de primos de 2048, 3072 y 4096 bits y con longitud 
adicional de primos de 6144 y 8192 bits comenzando con la versión 2.4.10
(from <a href="http://www.ietf.org/rfc/rfc3526.txt">RFC 3526</a>), y los
envía a clientes basándose en la longitud de la clave RSA/DSA del certificado.
Con clientes basados en Java en particular (Java 7 o anterior), esto puede
llevar a fallos de saludo inicial SSL - vea esta
<a href="../ssl/ssl_faq.html#javadh">respuesta de FAQ </a> para sortear estos
problemas.
</p>
</note>

<note>
<title>Parámetros DH por defecto cuando se usan multiples certificados y 
y versiones de OpenSSL anteriores a 1.0.2</title>
<p>
Cuando se usan múltiples certificados para dar soporte a algoritmos de 
autenticación diferentes (como RSA, DSA pero principalmente ECC) y OpenSSL 
anterior a 1.0.2, se recomienda usar o bien parámetros DH personalizados 
(preferiblemente) añadiéndolos al primer fichero de certificado (como se 
describe más arriba), o ordenar las directivas
<directive>SSLCertificateFile</directive> para que los certificados RSA/DSA
estén colocadas <strong>después</strong> del ECC.
</p>

<p>
Esto se debe a una limitación en versiones más antiguas de OpenSSL que no 
permiten que el servidor HTTP Apache determine el certificado seleccionado
actualmente en el momento del saludo SSL (cuando se deben mandar los parámetros
DH al cliente) pero en su lugar siempre se provee el último certificado 
configurado. Consecuentemente, el servidor puede seleccionar parámetros DH
por defecto basado en la longitud de la clave privada incorrecta (las clacves 
ECC son mucho más pequeñas que las RSA/DSA y su longitud no es relevante para
seleccionar primos DH).
</p>

<p>
Puesto que los parámetros personalizados DH siempre tienen precedencia sobre
los de por defecto, este problema se puede evitar creando y configurándolos 
(como se describe arriba), y así usar una longitud adecuada/personalizada.
</p>
</note>

<example><title>Ejemplo</title>
<highlight language="config">
SSLCertificateFile "/usr/local/apache2/conf/ssl.crt/server.crt"
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLCertificateKeyFile</name>
<description>Fichero de clave privada de Servidor codificada en PEM</description>
<syntax>SSLCertificateKeyFile <em>ruta-al-fichero</em></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>

<usage>
<p>
Esta directiva apunta al fichero de clave privada codificado en PEM para el 
servidor. Si la clave privada contenida en el fichero está encriptada, se 
forzará un diálogo de solicitud de contraseña en el arranque.</p>

<p>
La directiva puede usarse múltiples veces (haciendo referencia a ficheros 
distintos) para dar soporte a múltiples algoritmos de autenticación para el 
servidor. Por cada directiva
<directive module="mod_ssl">SSLCertificateKeyFile</directive>
directive, debe haber una directiva <directive>SSLCertificateFile</directive>
relacionada.</p>

<p>
La clave privada se puede combinar con el certificado en el fichero indicado en
<directive module="mod_ssl">SSLCertificateFile</directive>, pero esta práctica
es muy desaconsejable. Si se usa, los ficheros de certificado con la clave
privada dentro deben configurarse después de los certificados que tienen una
clave privada en otro fichero.</p>

<example><title>Ejemplo</title>
<highlight language="config">
SSLCertificateKeyFile "/usr/local/apache2/conf/ssl.key/server.key"
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLCertificateChainFile</name>
<description>Fichero de Certificados CA de Servidor codificado en 
  PEM</description>
<syntax>SSLCertificateChainFile <em>ruta-al-fichero</em></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>

<usage>
<note><title>SSLCertificateChainFile está obsoleto</title>
<p><code>SSLCertificateChainFile</code> quedó obsoleto con la versión 2.4.8, 
cuando se extendió <directive module="mod_ssl">SSLCertificateFile</directive>
para cargar también los certificados de CA intermedias del fichero de 
certificados del servidor.</p>
</note>

<p>
Esta directiva configura el fichero <em>todo-en-uno</em> donde puede ensamblar los
certificados de Autoridades de Certificación (CA - Certification Authorities) 
que forman la cadena del certificado del servidor. Este comienza con el 
certificado de la CA firmante del certificado del servidor y puede ir hasta el
certificado de la CA raíz. Tal fichero es simplemente la concatenación de varios
ficheros de Certificado CA codificado en PEM, generalmente siguiendo la cadena
de certificación.</p>

<p>
Esto debería usarse alternativamente y/o adicionalmente a 
<directive module="mod_ssl">SSLCACertificatePath</directive> para construir
explicitamente la cadena de CA del certificado del servidor que se envía al 
navegador además del certificado del servidor. Es especialmente últil
para evitar conflictos con certificados CA cuando se usa autenticación de 
cliente. Porque aunque colocar los CA de la cadena de certificados del servidor
en  <directive module="mod_ssl">SSLCACertificatePath</directive> tiene el mismo
efecto para la construcción de la cadena de certificados, tiene un efecto 
adicional en la que los certificados cliente firmados por el mismo certificado CA
también se aceptan en la autenticación de cliente.</p>

<p>
Pero tenga cuidado: Proveer la cadena de certificados funciona sólo si está
usando <em>un sólo</em> certificado de servidor basado en RSA <em>o</em> DSA. Si
está usando un par de certificados juntos RSA+DSA, esto sólo funcionará si
ambos certificados usan <em>la misma</em> cadena de certificados. Si no los 
navegadores se confundirán en esta situación.</p>
<example><title>Ejemplo</title>
<highlight language="config">
SSLCertificateChainFile "/usr/local/apache2/conf/ssl.crt/ca.crt"
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLCACertificatePath</name>
<description>Directorio de certificados CA codificados en PEM para la 
autenticación de Cliente</description>
<syntax>SSLCACertificatePath <em>ruta-de-directorio</em></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<override>AuthConfig</override>

<usage>
<p>
Esta directiva configura el directorio donde guarda los certificados de 
Autoridades de Certificación (CAs) de los clientes que accederán a su servidor. 
Esto se usarán para verificar el certificado cliente en la Autenticación de
Cliente.</p>

<p>
Los ficheros en este directorio tienen que ser codificados en PEM y se acceden a
través de nombres de ficheros con hash. Así que generalmente no puede poner 
simplemente los ficheros ahí: también tiene que crear enlaces simbólicos con 
nombre <em>valor-hash</em><code>.N</code>. Y siempre debería asegurarse de que
este directorio contiene los enlaces simbólicos apropiados.</p>
<example><title>Ejemplo</title>
<highlight language="config">
SSLCACertificatePath "/usr/local/apache2/conf/ssl.crt/"
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLCACertificateFile</name>
<description>Fichero de Certificados CA concatenados y codificados en PEM para
la Autenticación de Cliente</description>
<syntax>SSLCACertificateFile <em>ruta-al-fichero</em></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<override>AuthConfig</override>

<usage>
<p>
Esta directiva configura el fichero <em>todo-en-uno</em> donde puede ensamblar
los Certificados de las Autoridades de Certificación (CA) de los 
<em>clientes</em> que acceden a su servidor. Esto se usan para la Autenticación
de Cliente. Tal fichero es sencillamente la concatenación, en orden de preferencia,
de varios ficheros de Certificado codificados en PEM. Esto puede usarse
alternativamente y/o adicionalmente a 
<directive module="mod_ssl">SSLCACertificatePath</directive>.</p>
<example><title>Ejemplo</title>
<highlight language="config">
SSLCACertificateFile "/usr/local/apache2/conf/ssl.crt/ca-bundle-client.crt"
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLCADNRequestFile</name>
<description>Fichero de certificados CA concatenados codificados en PEM para
  definir nombres de CA aceptables</description>
<syntax>SSLCADNRequestFile <em>ruta-al-fichero</em></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>

<usage>
<p>Cuando se solicita un certificado cliente por mod_ssl, una lista de 
<em>nombres de Autoridad Certificadora aceptables</em> se envía al cliente en
el saludo SSL. Estos nombres de CA se pueden usar por el cliente para 
seleccionar un certificado cliente apropiado entre los que tiene disponibles.</p>

<p>Si no están las directivas <directive
module="mod_ssl">SSLCADNRequestPath</directive> o 
<directive module="mod_ssl">SSLCADNRequestFile</directive>, entonces el 
conjunto de nombres aceptables de CA enviados al cliente es la de los nombres
de todos los certificados de CA cargados en las directivas
<directive module="mod_ssl">SSLCACertificateFile</directive> y 
<directive module="mod_ssl">SSLCACertificatePath</directive>; en otras palabras,
los nombres de las CAs que se usarán actualmente para verificar el certificado
cliente.</p>

<p>En algunas circunstancias, es útil poder enviar un conjunto de nombres de CA
aceptables diferente de las CAs usadas para verificar el certificado cliente - 
por ejemplo, si los certificados cliente están firmados CAs intermedias. En tales
casos, <directive module="mod_ssl">SSLCADNRequestPath</directive> y/o 
<directive module="mod_ssl">SSLCADNRequestFile</directive> se pueden usar; los
nombres de CA aceptables se toman del conjunto completo de certificados en el 
directorio y/o fichero especificados por este par de directivas.</p>

<p><directive module="mod_ssl">SSLCADNRequestFile</directive> debe especificar
un fichero <em>todo-en-uno</em> que contenga una concatenación de certificados
CA codificados en PEM.</p>

<example><title>Ejemplo</title>
<highlight language="config">
SSLCADNRequestFile "/usr/local/apache2/conf/ca-names.crt"
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLCADNRequestPath</name>
<description>Directorio de Certificados CA codificados en PEM para definir
nombres de CA aceptables</description>
<syntax>SSLCADNRequestPath <em>ruta-al-directorio</em></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>

<usage>

<p>Esta directiva opcional puede usarse para especificar un conjunto de
<em>nombres de CA aceptables</em> que serán enviados al cliente cuando se 
solicita un certificado cliente. Vea la directiva 
<directive module="mod_ssl">SSLCADNRequestFile</directive> para más 
detalles.</p>

<p>Los ficheros en este directorio tienen que estar codificados en PEM y se
accede a ellos con nombres de ficheros con hash. Así que generalmente no puede
poner sin más los ficheros de Certificado ahí: también tiene que crear enlaces
simbólicos llamados <em>valor-de-hash</em><code>.N</code>. Y siempre debería
estar seguro de que este directorio contiene los enlaces simbólicos 
apropiados.</p>

<example><title>Ejemplo</title>
<highlight language="config">
SSLCADNRequestPath "/usr/local/apache2/conf/ca-names.crt/"
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLCARevocationPath</name>
<description>Directorio de CRLs de CA codificados en PEM para la Autenticación
de Cliente</description>
<syntax>SSLCARevocationPath <em>ruta-al-directorio</em></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>

<usage>
<p>
Esta directiva configura el directorio donde usted alojará las Listas de
Revocación de Certificados (CRL) de las Autoridades de Certificación (CAs) para
los clientes que conectan al servidor. Estas se usan para revocar el 
certificado cliente en la Autenticación de Cliente.</p>

<p>
Los ficheros en este directorio tienen que ser codificados en PEM y se accede a
ellos con nombres de ficheros con hash. Así que generalmente no sólo tiene que
poner los ficheros CRL ahí. Adicionalmente tiene que crear enlaces simbólicos
llamados <em>valor-de-hash</em><code>.rN</code>. Y debería asegurarse siempre 
que este directorio contiene los enlaces simbólicos apropiados.</p>
<example><title>Ejemplo</title>
<highlight language="config">
SSLCARevocationPath "/usr/local/apache2/conf/ssl.crl/"
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLCARevocationFile</name>
<description>Fichero de CRL's de CA concatenados y codificados en PEM para la
  Autenticación de ClienteFile of concatenated PEM-encoded CA CRLs for
</description>
<syntax>SSLCARevocationFile <em>ruta-al-fichero</em></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>

<usage>
<p>
Esta directiva configura el fichero <em>todo-en-uno</em> donde puede ensamblar
las Listas de Revocación de Certificados (CRL) de las Autoridades de
Certificación (CA) para los <em>clientes</em> que conectan a su servidor. Estos
se usan para la Autenticación de Cliente. Tal fichero es simplemente la 
concatenación de varios ficheros CRL codificados en PEM, en orden de 
preferencia. Esto se puede usar alternativamente a/o adicionalmente a 
<directive module="mod_ssl">SSLCARevocationPath</directive>.</p>
<example><title>Ejemplo</title>
<highlight language="config">
SSLCARevocationFile "/usr/local/apache2/conf/ssl.crl/ca-bundle-client.crl"
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLCARevocationCheck</name>
<description>Activar comprobación de revocación basada en CRL</description>
<syntax>SSLCARevocationCheck chain|leaf|none <em>modificador</em>es</syntax>
<default>SSLCARevocationCheck none</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility><em>Modificador</em>es Opcionales disponibles en httpd 2.4.21 o 
posterior</compatibility>

<usage>
<p>
Activa la comprobación de la lista de revocación de certificados (CRL). Al menos
<directive module="mod_ssl">SSLCARevocationFile</directive>
o <directive module="mod_ssl">SSLCARevocationPath</directive> deben estar 
configuradas. Cuando se configuran a <code>chain</code> (configuración 
recomendada), las comprobaciones de CRL se aplican a todos los certificados
en la cadena, mientras que si se configura a <code>leaf</code> limita las
comprobaciones al certificado firmado final.
</p>

<p>Los <em>modificador</em>es disponibles son:</p>
<ul>
<li><code>no_crl_for_cert_ok</code>
    <p>
    Previamente a la versión 2.3.15, la comprobación de CRL en mod_ssl también
    tenía éxito cuando no se encontraban CRL/s para los certificados comprobados
    en ninguna de las ubicaciones configuradas con 
    <directive module="mod_ssl">SSLCARevocationFile</directive>
    o <directive module="mod_ssl">SSLCARevocationPath</directive>.
    </p>

    <p>
    Con la introducción de <directive>SSLCARevocationFile</directive>,
    el comportamiento ha cambiado: por defecto con <code>chain</code> o
    <code>leaf</code>, los CRLs <strong>deben</strong> estar presentes
    para que la validación tenga éxito, si no fallará con un error
    <code>"unable to get certificate CRL"</code>.
    </p>

    <p>
    El <em>modificador</em> <code>no_crl_for_cert_ok</code> permite 
    restaurar el comportamiento anterior..
    </p>
</li>
</ul>
<example><title>Ejemplo</title>
<highlight language="config">
SSLCARevocationCheck chain
</highlight>
</example>
<example><title>Compatibilidad con versiones 2.2</title>
<highlight language="config">
SSLCARevocationCheck chain no_crl_for_cert_ok
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLVerifyClient</name>
<description>Tipo de verificación de Certificado Cliente</description>
<syntax>SSLVerifyClient <em>nivel</em></syntax>
<default>SSLVerifyClient none</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context></contextlist>
<override>AuthConfig</override>

<usage>
<p>
Esta directiva configura el nivel de verificación de Certificado para la 
Autenticación de Cliente. Tenga en cuenta que esta directiva se puede usar tanto
en contexto servidor como en contexto directorio. En contexto de servidor se 
aplica al proceso de autenticación de cliente usado en el saludo estándar de SSL
cuando se establece una conexión. En el contexto directorio fuerza una 
renegociación SSL con el nivel de verificación reconfigurado después de que se 
lee la petiicón HTTP pero antes de que se responda la respuesta HTTP.</p>

<p>
Los siguientes niveles están disponibles para <em>nivel</em>:</p>
<ul>
<li><strong>none</strong>:
     no se requiere Certificado cliente ninguno</li>
<li><strong>optional</strong>:
     el cliente <em>puede</em> presentar un Certificado válido</li>
<li><strong>require</strong>:
     el cliente <em>tiene que</em> presentar un Certificado válido</li>
<li><strong>optional_no_ca</strong>:
     el cliente puede presentar un Certificado válido<br />
     pero no tiene por qué ser verificable (satisfactoriamente). No se puede
     depender de esta opción para la autenticación de cliente.  </li>
</ul>
<example><title>Ejemplo</title>
<highlight language="config">
SSLVerifyClient require
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLVerifyDepth</name>
<description>Profundidad máxima de Certificados CA en la verificación de 
Certificado Cliente</description>
<syntax>SSLVerifyDepth <em>number</em></syntax>
<default>SSLVerifyDepth 1</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context></contextlist>
<override>AuthConfig</override>

<usage>
<p>
Esta directiva configura hasta qué nivel debe mod_ssl verificar antes de decidir
cuando los clientes no tienen un certificado válido. Tenga en cuenta que esta
directiva puede usarse tanto en contexto servidor como en contexto directorio.
En contexto servidor se aplica al proceso de autenticación de cliente en el
salido SSL estándar cuando se establece una conexión. En el contexto directorio
fuerza una renegociación SSL con la profundidad de verficiación de cliente
reconfigurada después de que se lea la petición HTTP pero antes de que sé haya 
enviado la respuesta HTTP.</p>
<p>
La profundidad es en realidad el número máximo de certificados CA intermedios,
p. ej. el número de certificados CA máximo permitido a seguir en la verificación
del certificado cliente. Una profundidad de 0 significa que sólo se 
aceptan los certificados cliente autofirmados, la profundidad por defecto de 1
significa que el cliente puede ser autofirmado o tiene que estar firmado por una
CA que es directamente conocida por el servidor (p. ej. los certificados CA 
están bajo
<directive module="mod_ssl">SSLCACertificatePath</directive>), etc.</p>
<example><title>Ejemplo</title>
<highlight language="config">
SSLVerifyDepth 10
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLSRPVerifierFile</name>
<description>Ruta hacia el fichero verificador SRP</description>
<syntax>SSLSRPVerifierFile <em>ruta-al-fichero</em></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible en httpd 2.4.4 y posterior si se usa OpenSSL 1.0.1 o
posterior</compatibility>

<usage>
<p>
Esta directiva activa TLS-SRP y configura la ruta al fichero verificador 
OpenSSL SRP (Secure Remote Password) que contiene nombres de usuario, 
verificadores, salts y parámetros de grupo TLS-SRP.</p>
<example><title>Ejemplo</title>
SSLSRPVerifierFile "/ruta/al/fichero.srpv"
</example>

<p>
El fichero verificador puede generarse con la utilidad de línea de comandos
<code>openssl</code>:</p>

<example><title>Creando el fichero verificador SRP</title>
openssl srp -srpvfile passwd.srpv -userinfo "some info" -add username
</example>

<p> El valor dado con el parámetro opcional <code>-userinfo</code> está 
disponible en la variable de entorno de petición 
<code>SSL_SRP_USERINFO</code>.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLSRPUnknownUserSeed</name>
<description>Semilla de usuario desconocido SRP</description>
<syntax>SSLSRPUnknownUserSeed <em>cadenadecaracteres-secreta</em></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible en httpd 2.4.4 y posterior si se usa OpenSSL 1.0.1 o
posterior</compatibility>

<usage>
<p>
Esta directiva configura la semilla usada para aparentar parámetros de usuario 
SRP para usuarios desconocidos, para evitar dar a conocer si el usuario 
facilitado existe, se especifica una cadena de caracteres secreta. Si no se usa 
esta directiva, entonces Apache deolverá la alerta UNKNOWN_PSK_IDENTITY a 
clientes que espcifican un nombre de usuario desconocido.
</p>
<example><title>Ejemplo</title>
SSLSRPUnknownUserSeed "secret"
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLOptions</name>
<description>Configurar varias opciones del motor SSL en tiempo 
  real</description>
<syntax>SSLOptions [+|-]<em>opción</em> ...</syntax>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context></contextlist>
<override>Options</override>

<usage>
<p>
Esta directiva puede usarse para controlar varias opciones en tiempo real en 
contexto directorio. Normalmente, si múltiples <code>SSLOptions</code>
pueden aplicar a un directorio, entonces se usará la más 
específica; las opciones no se fusionan. Sin embargo, si <em>todas</em> las 
opciones en la directiva <code>SSLOptions</code> están precedidas de un signo
más (<code>+</code>) o menos (<code>-</code>), las opciones se fusionan.
Cualquier opción precedida de un  <code>+</code> es añadida a las opciones que
se están aplicando en ese momento, y cualquier opción precedida de un 
<code>-</code> se elimina de las opciones aplicadas en ese momento.</p>
<p>
Las <em>opciones</em> disponibles son:</p>
<ul>
<li><code>StdEnvVars</code>
    <p>
    Cuando esta opción está habilitada, se generan las variables de entorno 
    estándar de SSL relacionadas con CGI/SSI. Esto está desactivado por defecto
    por razones de rendimiento, porque el paso de extracción de la información
    es una operación bastante costosa. Así que uno sólo activaría esta opción 
    para peticiones CGI o SSI.</p>
</li>
<li><code>ExportCertData</code>
    <p>
    Cuando se activa esta opción, se generan variables de entorno CGI/SSI 
    adicionales: <code>SSL_SERVER_CERT</code>, <code>SSL_CLIENT_CERT</code> y
    <code>SSL_CLIENT_CERT_CHAIN_</code><em>n</em> (con <em>n</em> = 0,1,2,..).
    Estas contienen los certificados X.509 codificados en PEM del servidor
    y el cliente para la conexión actual HTTPs y pueden usarse por scripts CGI
    para una comprobación más detallada de los Certificados. Adicionalmente 
    también se facilitan todos los demás certificados de la cadena  del 
    certificado cliente. Esto carga el entorno de variables un poco, así
    que por esto deberá usar esta opción para activarla sólo cuando sea 
    necesario.</p>
</li>
<li><code>FakeBasicAuth</code>
    <p>
    Cuando se activa esta opción, el Nombre Distinguido de Sujeto (DN) del 
    Certificado Cliente X509 se traduce a un nombre de Autenticación HTTP Básica.
    Esto significa que se pueden usar los métodos estándar de autenticación para
    control de acceso. El nombre de usuario es tan sólo el Sujeto del 
    Certificado Cliente X509 (se puede determinar ejecutando el comando 
    de OpenSSL <code>openssl x509</code>: <code>openssl x509 -noout -subject -in
    </code><em>certificado</em><code>.crt</code>). La directiva 
    <directive module="mod_ssl">SSLUserName</directive> puede usarse para 
    especificar qué
    parte del Sujeto del Certificado está embebida en el nombre de usuario.
    Tenga en cuenta que no se obtiene ninguna contraseña del usuario. Cada 
    entrada en el fichero de usuario necesita esta contraseña: 
    ``<code>xxj31ZMTZzkVA</code>'', que es la versión encriptada en DES de la
    palabra `<code>password</code>''. Aquellos que viven bajo la encriptación
    basada en MD5 (por ejemplo bajo FreeBSD or BSD/OS, etc.) debería usar
    el siguiente hash MD5 de la misma palabra:
     ``<code>$1$OXLyS...$Owx8s2/m9/gfkcRVXzgoE/</code>''.</p>

    <p>Tenga en cuenta que 
    la directiva <directive module="mod_auth_basic">AuthBasicFake</directive>
    dentro de <module>mod_auth_basic</module> puede usarse como un mecanismo
    general para fingir la autenticación básica, dando control sobre la 
    estructura tanto del nombre como de la contraseña.</p>

    <note type="warning">
      <p>Los nombres de usuarios utilizados para <code>FakeBasicAuth</code> no
      deben incluir caracteres no-ASCII, caracteres de escape ASCII (tales como
      el de nueva línea), o una coma. Si se encuentra una coma, se generará
      un error 403 Forbidden con httpd 2.5.1 y posterior.</p>
    </note>
</li>
<li><code>StrictRequire</code>
    <p>
    Esto <em>fuerza</em> acceso prohibido cuando <code>SSLRequireSSL</code> o
    <code>SSLRequire</code> deciden satisfactoriamente que el acceso debería
    denegarse. Generalmente por defecto en el caso donde se usa una
    directiva ``<code>Satisfy any</code>'', y se pasan otras restricciones de 
    acceso, se sobreescribe la denegación del acceso debido a 
    <code>SSLRequireSSL</code> o <code>SSLRequire</code> (porque así es como
    debería funcionar el mecanismo <code>Satisfy</code> de Apache .) Pero para
    la restricción estricta de acceso puede usar <code>SSLRequireSSL</code> y/o 
    <code>SSLRequire</code> en combinación con un 
    ``<code>SSLOptions +StrictRequire</code>''. Entonces un 
    ``<code>Satisfy Any</code>'' adicional no tiene oportunidad una vez que
    mod_ssl ha decidido denegar el acceso.</p>
</li>
<li><code>OptRenegotiate</code>
    <p>
    Esto activa la gestión optimizada de renegociación de conexión SSL cuando
    se usan directivas SSL en contexto de directorio. Por defecto un esquema
    estricto está habilitado donde <em>cada</em> reconfiguración de directorio de
    parámetros SSL provoca una renegociación <em>total</em> del saludo SSL. 
    Cuando se usa esta opción mod_ssl intenta evitar saludos SSL innecesarios
    haciendo comprobaciones más específicas (pero todavía seguras) de parámetros.
    Sin embargo estas comprobaciones más específicas pueden no ser lo que espera
    el usuario, así que, lo recomendable es que active ésto sólo en contexto
    directorio.</p>
</li>
<li><code>LegacyDNStringFormat</code>
    <p>
    Esta opción influencia cómo se formatean los valores de las variables
    <code>SSL_{CLIENT,SERVER}_{I,S}_DN</code>. Desde la versión 2.3.11, Apache 
    HTTPD usa un formato compatible RFC 2253 por defecto. Esto usa comas como 
    delimitadores entre atributos, permite el uso de caracteres no-ASCII (que 
    son convertidos a UTF-8), escapa varios caracteres especiales con barra 
    invertida "\", y ordena los atributos con el atributo "C" al final.</p>

    <p>Si se activa <code>LegacyDNStringFormat</code>, el formato antiguo 
    que ordena el atributo "C" el primero será utilizado, usa barras como 
    separadores y no manipula caracteres no-ASCII y especiales de ninguna forma 
    consistente.
    </p>
</li>
</ul>
<example><title>Ejemplo</title>
<highlight language="config">
SSLOptions +FakeBasicAuth -StrictRequire
&lt;Files ~ "\.(cgi|shtml)$"&gt;
    SSLOptions +StdEnvVars -ExportCertData
&lt;/Files&gt;
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLRequireSSL</name>
<description>Denegar el acceso cuando no se usa SSL para la petición 
  HTTP</description>
<syntax>SSLRequireSSL</syntax>
<contextlist><context>directory</context>
<context>.htaccess</context></contextlist>
<override>AuthConfig</override>

<usage>
<p><!-- XXX: I think the syntax is wrong -->
Esta directiva prohibe el acceso a menos que esté habilitado HTTP sobre SSL
(p. ej. HTTPS) para la conexión en cuestión. Esto es muy útil dentro de
hosts virtuales con SSL activado o directorios, para defenderse de errores
de configuración que exponen cosas que deberían estar protegidas. Cuando esta 
directiva está presente todas las peticiones que no usen SSL son denegadas.</p>
<example><title>Ejemplo</title>
<highlight language="config">
SSLRequireSSL
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLRequire</name>
<description>Permite acceso sólo cuando una compleja expresión booleana 
  arbitraría es cierta</description>
<syntax>SSLRequire <em>expresión</em></syntax>
<contextlist><context>directory</context>
<context>.htaccess</context></contextlist>
<override>AuthConfig</override>

<usage>

<note><title>SSLRequire está obsoleta</title>
<p><code>SSLRequire</code> está obsoleta y debería en general ser sustituida por
<a href="mod_authz_core.html#reqexpr">Require expr</a>. La tal llamada 
sintaxis de <a href="../expr.html">ap_expr</a> en <code>Require expr</code> es
la sustitución de la sintaxis de <code>SSLRequire</code>, con la siguiente
excepción:</p>

<p>En <code>SSLRequire</code>, los operadores de comparación <code>&lt;</code>,
<code>&lt;=</code>, ... son equivalentes completamente a los operadores
<code>lt</code>, <code>le</code>, ... y funionan de una manera un tanto peculiar
que primero compara la longitud de dos cadenas de caracteres y después el orden
léxico. Por otro lado, <a href="../expr.html">ap_expr</a> tiene dos conjuntos
de operadores de comparación: Los operadores <code>&lt;</code>,
<code>&lt;=</code>, ... hacen compraciones léxicas de cadenas de caracteres, 
mientras que los operadores <code>-lt</code>, <code>-le</code>, ... hacen
comparación de números integrales.
Para los últimos, también hay aliases sin el guión inicial:
<code>lt</code>, <code>le</code>, ...
</p>
</note>

<p>
Esta directiva especifica un requerimiento de acceso general que tiene
que pasarse para que se permita el acceso. Es una directiva muy versátil porque
la especificación del requerimiento es una compleja expresión booleana arbitraria
que contiene cualquier número de comprobaciones.</p>
<p>

La <em>expresión</em> debe coincidir en la siguiente sintaxis (dada una notación
gramatical BNF):</p>
<blockquote>
<pre>
expr     ::= "<strong>true</strong>" | "<strong>false</strong>"
           | "<strong>!</strong>" expr
           | expr "<strong>&amp;&amp;</strong>" expr
           | expr "<strong>||</strong>" expr
           | "<strong>(</strong>" expr "<strong>)</strong>"
           | comp

comp     ::= word "<strong>==</strong>" word | word "<strong>eq</strong>" word
           | word "<strong>!=</strong>" word | word "<strong>ne</strong>" word
           | word "<strong>&lt;</strong>"  word | word "<strong>lt</strong>" word
           | word "<strong>&lt;=</strong>" word | word "<strong>le</strong>" word
           | word "<strong>&gt;</strong>"  word | word "<strong>gt</strong>" word
           | word "<strong>&gt;=</strong>" word | word "<strong>ge</strong>" word
           | word "<strong>in</strong>" "<strong>{</strong>" wordlist "<strong>}</strong>"
           | word "<strong>in</strong>" "<strong>PeerExtList(</strong>" word "<strong>)</strong>"
           | word "<strong>=~</strong>" regex
           | word "<strong>!~</strong>" regex

wordlist ::= word
           | wordlist "<strong>,</strong>" word

word     ::= digit
           | cstring
           | variable
           | function

digit    ::= [0-9]+
cstring  ::= "..."
variable ::= "<strong>%{</strong>" varname "<strong>}</strong>"
function ::= funcname "<strong>(</strong>" funcargs "<strong>)</strong>"
</pre>
</blockquote>

<p>Para <code>varname</code> se puede usar cualquiera de las variables descritas 
en <a href="#envvars">Variables de Entorno</a>.  Para
<code>funcname</code> las funciones disponibles están listadas en la
<a href="../expr.html#functions">documentación de ap_expr</a>.</p>

<p>La <em>expresión</em> es interpretada dentro de una representación interna 
de máquina cuando se carga la configuración, y es después evaluada durante 
el procesamiento de la petición. En contexto .htaccess, la <em>expresión</em> es
en ambos casos interpretada y ejecutada cada vez que se encuentra un fichero
.htaccess durante el procesamiento de la petición.</p>

<example><title>Ejemplo</title>
<highlight language="config">
SSLRequire (    %{SSL_CIPHER} !~ m/^(EXP|NULL)-/                   \
            and %{SSL_CLIENT_S_DN_O} eq "Snake Oil, Ltd."          \
            and %{SSL_CLIENT_S_DN_OU} in {"Staff", "CA", "Dev"}    \
            and %{TIME_WDAY} -ge 1 and %{TIME_WDAY} -le 5          \
            and %{TIME_HOUR} -ge 8 and %{TIME_HOUR} -le 20       ) \
           or %{REMOTE_ADDR} =~ m/^192\.76\.162\.[0-9]+$/
</highlight>
</example>

<p>La función <code>PeerExtList(<em>object-ID</em>)</code> espera encontrar
cero o más instancias de la extensión de certificado X.509 identificadas por
un <em>ID de objecto</em> (OID) dado en el certificado cliente. La expresión
se evalúa a cierta si la cadena de caracteres de la izquierda coincide 
exactamente contra el valor de la extensión identificada por este OID. (Si están
presentes múltiples extensiones con el mismo OID, al menos uno debe 
coincidir).</p>

<example><title>Ejemplo</title>
<highlight language="config">
SSLRequire "foobar" in PeerExtList("1.2.3.4.5.6")
</highlight>
</example>

<note><title>Notas sobre la función PeerExtList</title>

<ul>

<li><p>El ID de objeto puede ser especificado o bien como un 
nombre descriptivo reconocido por la librería SSL, tal como 
<code>"nsComment"</code>, o como un OID numérico, tal como
 <code>"1.2.3.4.5.6"</code>.</p></li>

<li><p>Expresiones con tipos conocidos para la librería SSL se expresan como una 
cadena de caracteres antes de su comparación. Para una extensión con un tipo no
reconocido por la librería SSL, mod_ssl interpretará el valor si es uno de los
tipos primitivos ASN.1 types UTF8String, IA5String, VisibleString,
o BMPString.  Para una extensión de uno de estos tipos, el valor de la cadena
de caracteres se convertirá en UTF-8 si es necesario, y entonces comparada 
contra la expresión de la izquierda.</p></li>

</ul>
</note>

</usage>
<seealso><a href="../env.html">Variables de entorno en el Servidor HTTP 
  Apache</a>, para más ejemplos.
</seealso>
<seealso><a href="mod_authz_core.html#reqexpr">Require expr</a></seealso>
<seealso><a href="../expr.html">Sintaxis general de expresión en el Servidor
HTTP Apache</a>
</seealso>
</directivesynopsis>

<directivesynopsis>
<name>SSLRenegBufferSize</name>
<description>Configure el tamaño para el búfer de renegociación 
  SSL</description>
<syntax>SSLRenegBufferSize <var>bytes</var></syntax>
<default>SSLRenegBufferSize 131072</default>
<contextlist><context>directory</context>
<context>.htaccess</context></contextlist>
<override>AuthConfig</override>

<usage>

<p>Si se requiere una renegociación SSL por el contexto location, por ejemplo,
cualquier uso de <directive module="mod_ssl">SSLVerifyClient</directive> en un
bloque Directory o Location, entonces <module>mod_ssl</module> debe hacer búfer
del cuerpo de la petición HTTP en memoria hasta que el nuevo saludo SSL
puede realizarse. Esta directiva se puede usar para especificar la cantidad
de memoria que se usará para este búfer.</p>

<note type="warning"><p>
Tenga en cuenta que en muchas configuraciones, el cliente enviando el cuerpo de 
la petición no es confiable así que se debe considerar un ataque de denegación
de servicio por consumo de memoria cuando se cambie este valor de 
configuración.
</p></note>

<example><title>Ejemplo</title>
<highlight language="config">
SSLRenegBufferSize 262144
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLStrictSNIVHostCheck</name>
<description>Permitir o no a clientes no-SNI acceder a host virtuales basados
  en nombre.
</description>
<syntax>SSLStrictSNIVHostCheck on|off</syntax>
<default>SSLStrictSNIVHostCheck off</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>

<usage>
<p>
Esta directiva configura si un cliente no-SNI tiene permiso para acceder a un 
host virtual basado en nombre. Si se configura a <code>on</code> en el host
virtual por defecto basado en nombre, los clientes que no son compatibles con
SNI no se les permitirá el acceso a <em>ningún</em> host virtual que pertenezca
a esta combinación de ip/puerto. Si se configura a <code>on</code> en cualquier
otro host virtual, los clientes no compatibles con SNI no tendrán acceso a ese
host virtual en particular.
</p>

<note type="warning"><p>
Esta opción sólo está disponible si httpd fue compilado contra una versión 
compatible con SNI de OpenSSL.
</p></note>

<example><title>Ejemplo</title>
<highlight language="config">
SSLStrictSNIVHostCheck on
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLProxyMachineCertificatePath</name>
<description>Directorio de certificados cliente codificados en PEM y claves
  para ser usadas por el proxy</description>
<syntax>SSLProxyMachineCertificatePath <em>directorio</em></syntax>
<contextlist><context>server config</context> <context>virtual host</context>
<context>proxy section</context></contextlist>

<usage>
<p>
Esta directiva configura el directorio donde se guardan los certificados y claves
usadas para la autenticación del servidor proxy en servidores remotos.
</p>

<p>Los ficheros en este directorio deben ser codificados en PEM y accesibles
con nombres de ficheros con hash. Además, debe crear enlaces simbólicos 
llamados <code><em>valor-del-hash</em>.N</code>. Y siempre debería asegurarse
de que este directorio contiene los enlaces simbólicos apropiados.</p>
<note type="warning">
<p>Actualmente no hay soporte para claves privadas encriptadas</p>
</note>
<example><title>Ejemplo</title>
<highlight language="config">
SSLProxyMachineCertificatePath "/usr/local/apache2/conf/proxy.crt/"
</highlight>
</example>
</usage>
</directivesynopsis>


<directivesynopsis>
<name>SSLProxyMachineCertificateFile</name>
<description>Fichero de certificados cliente codificados en PEM y claves para
ser usadas por el proxy</description>
<syntax>SSLProxyMachineCertificateFile <em>ruta-al-fichero</em></syntax>
<contextlist><context>server config</context> <context>virtual host</context>
<context>proxy section</context></contextlist>

<usage>
<p>
Esta directiva configura el fichero todo-en-uno donde guarda los certificados y
claves usadas para la autenticación del servidor proxy en servidores remotos.
</p>
<p>
Este fichero es simplemente la concatenación de varios ficheros de certificado
codificados en PEM, en orden de preferencia. Use esta directiva alternativamente
o adicionalmente a <code>SSLProxyMachineCertificatePath</code>.
</p>
<note type="warning">
<p>Actualmente no hay soporte para claves privadas encriptadas</p>
</note>
<example><title>Ejemplo</title>
<highlight language="config">
SSLProxyMachineCertificateFile "/usr/local/apache2/conf/ssl.crt/proxy.pem"
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLProxyMachineCertificateChainFile</name>
<description>Fichero de certificados CA concatenados y codificados en PEM para
ser usados por el proxy para elegir un certificado</description>
<syntax>SSLProxyMachineCertificateChainFile <em>ruta-al-fichero</em></syntax>
<contextlist><context>server config</context> <context>virtual host</context>
<context>proxy section</context></contextlist>

<usage>
<p>
Esta directiva configura el fichero todo-en-uno donde guarda la cadena de 
certificados para todos los certificados cliente en uso. Esta directiva se 
necesitará si los servidores remotos presentan una lista de certificados CA
que no son firmantes directos de uno de los certificados cliente configurados.
</p>
<p>
Este fichero es simplemente la concatenciación de varios ficheros de certificado
codificado en PEM. En el arranque, cada certificado cliente configurado será
examinado y se construirá una cadena de confianza.
</p>
<note type="warning"><title>Aviso de Seguridad</title>
<p>Si se activa esta directiva, se confiará en todos los certificados en el 
fichero como si también estuvieran en 
<directive module="mod_ssl">SSLProxyCACertificateFile</directive>.</p>
</note>
<example><title>Ejemplo</title>
<highlight language="config">
SSLProxyMachineCertificateChainFile "/usr/local/apache2/conf/ssl.crt/proxyCA.pem"
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLProxyVerify</name>
<description>Tipo de verficación de certificado del servidor remoto</description>
<syntax>SSLProxyVerify <em>level</em></syntax>
<default>SSLProxyVerify none</default>
<contextlist><context>server config</context> <context>virtual host</context>
<context>proxy section</context></contextlist>

<usage>

<p>Cuando se configura un proxy para enviar peticiones a un servidor remoto SSL,
esta directiva se puede usar para configurar verificación de certificado del
servidor remoto.</p>

<p>
Los siguientes niveles están disponibles para <em>nivel</em>:</p>
<ul>
<li><strong>none</strong>:
     No se requiere Certificado del servidor remoto para nada</li>
<li><strong>optional</strong>:
     el servidor remoto <em>puede</em> presentar un Certificado válido</li>
<li><strong>require</strong>:
     el servidor remoto <em>tiene que</em> presenta un Certificado válido</li>
<li><strong>optional_no_ca</strong>:
     el servidor remoto puede presentar un Certificado válido<br />
     pero no tiene por qué ser verificable (con éxito).</li>
</ul>
<p>En la práctica sólo los niveles <strong>none</strong> y
<strong>require</strong> son realmente interesantes, porque el nivel 
<strong>optional</strong> no funciona en todos los servidores y el nivel
<strong>optional_no_ca</strong> va actualmente contra la idea de autenticación
(pero se puede usar para establecer páginas de test SSL, etc.)</p>
<example><title>Ejemplo</title>
<highlight language="config">
SSLProxyVerify require
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLProxyVerifyDepth</name>
<description>Máxima profundidad de los Certificados CA en la verificación del
Certificado en el Servidor Remoto</description>
<syntax>SSLProxyVerifyDepth <em>number</em></syntax>
<default>SSLProxyVerifyDepth 1</default>
<contextlist><context>server config</context> <context>virtual host</context>
<context>proxy section</context></contextlist>

<usage>
<p>
Esta directiva configura hasta dónde mod_ssl debería verificar antes de decidir
que el servidor remoto not tiene un certificado válido.</p>

<p>
La profundidad actualmente es el número máximo de expedidores intermedios de 
certificados, p. ej. el número de certificados CA que se permiten seguir como 
máximo para verificar el certificado del servidor remoto. Una profundidad de 0
sigifnica que sólo se permiten certificados auto-firmados, la profundidad por
defecto de 1 significa que el servidor remoto puede ser autofirmado o fimado por 
una CA que es directamente conocida por el servidor (p. ej. el certificado CA
bajo <directive module="mod_ssl">SSLProxyCACertificatePath</directive>), 
etc.</p>
<example><title>Ejemplo</title>
<highlight language="config">
SSLProxyVerifyDepth 10
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLProxyCheckPeerExpire</name>
<description>Comprobar si el certificado del servidor remoto está expirado
</description>
<syntax>SSLProxyCheckPeerExpire on|off</syntax>
<default>SSLProxyCheckPeerExpire on</default>
<contextlist><context>server config</context> <context>virtual host</context>
<context>proxy section</context></contextlist>

<usage>
<p>
Esta directiva configura si se debe comprobar si el certificado del servidor
remoto está expirado o no. Si la comprobación falla se devuelve un error 502 
(Bad Gateway).
</p>
<example><title>Ejemplo</title>
<highlight language="config">
SSLProxyCheckPeerExpire on
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLProxyCheckPeerCN</name>
<description>Comprobar el campo CN del certificado del servidor remoto
</description>
<syntax>SSLProxyCheckPeerCN on|off</syntax>
<default>SSLProxyCheckPeerCN on</default>
<contextlist><context>server config</context> <context>virtual host</context>
<context>proxy section</context></contextlist>

<usage>
<p>
Esta directiva configura si se debe comparar el campo CN del certificado del 
servidor remoto contra el nombre de host de la URL solicitada. Si ambos no son
iguales se envía un código de estado 502 (Bad Gateway). 
<code>SSLProxyCheckPeerCN</code> ha sido sustituido por 
<directive module="mod_ssl">SSLProxyCheckPeerName</directive> en la versión
2.4.5 y posterior.
</p>

<p>
En todas las versiones desde 2.4.5 hasta 2.4.20, configurar
<code>SSLProxyCheckPeerName off</code> era suficiente para activar este
comportamiento (puesto que el valor por defecto de 
<code>SSLProxyCheckPeerCN</code> era <code>on</code>.) En estas versiones, ambas
directivas deben configurarse a <code>off</code> para evitar completamente que 
se valide el nombre del certificado del servidor remoto. Muchos usuarios 
reportaron que esto es bastante confuso.
</p>

<p>
Desde la versión 2.4.21, todas las configuraciones que permiten una de las
opciones <code>SSLProxyCheckPeerName</code> o <code>SSLProxyCheckPeerCN</code>
usarán el nuevo comportamiento de 
<directive module="mod_ssl">SSLProxyCheckPeerName</directive>, y todas las
configuraciones que deshabilitan una de las opciones de
<code>SSLProxyCheckPeerName</code> o <code>SSLProxyCheckPeerCN</code> 
suprimirán la validación del nombre del certificado del servidor remoto. sólo
la siguiente configuración habilitará la comparación antigua del CN en 2.4.21 y
versiones posteriores;
</p>
<example><title>Ejemplo</title>
<highlight language="config">
SSLProxyCheckPeerCN on
SSLProxyCheckPeerName off
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLProxyCheckPeerName</name>
<description>Configure comprobación de nombre de host para certificados de 
  servidor remoto
</description>
<syntax>SSLProxyCheckPeerName on|off</syntax>
<default>SSLProxyCheckPeerName on</default>
<contextlist><context>server config</context> <context>virtual host</context>
<context>proxy section</context></contextlist>
<compatibility>Apache HTTP Server 2.4.5 and later</compatibility>

<usage>
<p>
Esta directiva configura la comprobación del nombre de host de certificados de
servidor cuando mod_ssl está actuando como un cliente SSL. La comprobación 
tendrá éxito si el nombre de host de la petición coincide con uno de los 
CN del sujeto del certificado, o coincide con la extensión subjectAltName. Si la
comprobación falla, la petición SSL se aborta y se devuelve un código de 
estado 502.
</p>

<p>
Se soportan coincidencias con certificados wildcard para casos específicos: una 
entrada subjectAltName del tipo dNSName, o atributos CN que comienzan con 
<code>*.</code> coincidirán con cualquier nombre de host del mismo número de 
elementos de nombre y el mismo sufijo.
P. ej. <code>*.example.org</code> coinciderá con <code>foo.example.org</code>,
pero no coincidirá con <code>foo.bar.example.org</code>, porque el número de 
elementos en el nombre de host respectivo es diferente.
</p>

<p>
Esta característica fue introducida en 2.4.5 y sustituye el comportamiento de
la directiva <directive module="mod_ssl">SSLProxyCheckPeerCN</directive>, que
sólo comprobaba el valor exacto en el primer atributo CN contra el nombre de
host. Sin embargo, muchos usuarios estaban confundidos por el comportamiento de
usar estas directivas individualmente, así que el comportamiento mutuo de las 
directivas <code>SSLProxyCheckPeerName</code> y <code>SSLProxyCheckPeerCN</code> 
fue mejorado en la versión 2.4.21. Vea la descripción de la directiva
<directive module="mod_ssl">SSLProxyCheckPeerCN</directive> para el 
comportamiento original y detalles de estas mejoras.
</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLProxyEngine</name>
<description>Interruptor de Operación del Motor de Proxy SSL</description>
<syntax>SSLProxyEngine on|off</syntax>
<default>SSLProxyEngine off</default>
<contextlist><context>server config</context> <context>virtual host</context>
<context>proxy section</context></contextlist>

<usage>
<p>
Esta directiva activa el uso del motor de protocolo SSL/TLS para proxy. Esto
se usa actualmente dentro de una sección 
<directive module="core" type="section">VirtualHost</directive> para activar el
uso de proxy con SSL/TLS en un host virtual en particular. Por defecto el Motor
de Protocolo SSL/TLS está desactivado para tanto el servidor principal como todos
los hosts virtuales.</p>

<p>Tenga en cuenta que la directiva <directive>SSLProxyEngine</directive> no 
debería en general, ser incluida en un host virtual que actuará como forward 
proxy (usando las directivas 
<directive module="mod_proxy" type="section">Proxy</directive>
o <directive module="mod_proxy">ProxyRequests</directive>).
<directive>SSLProxyEngine</directive> no es necesario para activar un servidor
forward proxy para hacer proxy de peticiones SSL/TLS.</p>

<example><title>Ejemplo</title>
<highlight language="config">
&lt;VirtualHost _default_:443&gt;
    SSLProxyEngine on
    #...
&lt;/VirtualHost&gt;
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLProxyProtocol</name>
<description>Configure sabores de protocolo SSL utilizables para uso de 
  proxy</description>
<syntax>SSLProxyProtocol [+|-]<em>protocolo</em> ...</syntax>
<default>SSLProxyProtocol all -SSLv3</default>
<contextlist><context>server config</context> <context>virtual host</context>
<context>proxy section</context></contextlist>

<usage>
<!-- XXX Why does this have an override and not .htaccess context? -->
<p>
Esta directiva puede usarse para controlar los sabores de protocolo SSL que
mod_ssl debería usar cuando establece si entorno de servidor para proxy. sólo
conectará con servidores usando uno de sus protocolos facilitados.</p>
<p>Por favor vea <directive module="mod_ssl">SSLProtocol</directive> para 
información adicional.
</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLProxyCipherSuite</name>
<description>Conjunto de Cifrados disponibles para negociación en el saludo SSL
de proxy</description>
<syntax>SSLProxyCipherSuite <em>especificación-de-cifrado</em></syntax>
<default>SSLProxyCipherSuite ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+EXP</default>
<contextlist><context>server config</context> <context>virtual host</context>
<context>proxy section</context></contextlist>

<usage>
<p>Equivalente a <directive module="mod_ssl">SSLCipherSuite</directive>, pero 
para la conexión de proxy.
Por favor consulte <directive module="mod_ssl">SSLCipherSuite</directive>
para información adicional.</p>
</usage>

</directivesynopsis>
<directivesynopsis>
<name>SSLProxyCACertificatePath</name>
<description>Directorio de Certificados CA codificados en PEM para la 
Autenticación de Servidor Remoto</description>
<syntax>SSLProxyCACertificatePath <em>ruta-al-directorio</em></syntax>
<contextlist><context>server config</context> <context>virtual host</context>
<context>proxy section</context></contextlist>

<usage>
<p>
Esta directiva configura el directorio donde guarda los Certificados de 
Autoridades de Certificación (CAs) de los servidores remotos a los que conecta. 
Estos se usan para verificar el certificado del servidor remoto en la 
Autenticación de Servidor Remoto.</p>

<p>
Los ficheros en este directorio tienen que estar codificados en PEM y se accede
a ellos a través de nombres de ficheros con hash. Así que generalmente no puede
tan sólo colocar los ficheros de Certificado ahí: también tiene que crear 
enlaces simbólicos llamados <em>valor-de-hash</em><code>.N</code>. Y debería
asegurarse siempre de que este directorio contiene los enlaces símbólicos 
apropiados.</p>
<example><title>Ejemplo</title>
<highlight language="config">
SSLProxyCACertificatePath "/usr/local/apache2/conf/ssl.crt/"
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLProxyCACertificateFile</name>
<description>Fichero de Certificados CA concatenados codificados en PEM para
la Autenticación Remota del Servidor</description>
<syntax>SSLProxyCACertificateFile <em>ruta-al-fichero</em></syntax>
<contextlist><context>server config</context> <context>virtual host</context>
<context>proxy section</context></contextlist>

<usage>
<p>
Esta directiva configura el fichero <em>todo-en-uno</em> donde ensambla los
Certificados de Autoridades de Certificación (CA) de los <em>servidores 
remotos</em> a los que conecta. Estos se usan como Autenticación de Servidor
Remoto. Tal fichero es simplemente la concatenación de varios ficheros de 
Certificado codificados en PEM en orden de preferencia. Esto se puede usar
alternativamente y/o adicionalmente a
<directive module="mod_ssl">SSLProxyCACertificatePath</directive>.</p>
<example><title>Ejemplo</title>
<highlight language="config">
SSLProxyCACertificateFile "/usr/local/apache2/conf/ssl.crt/ca-bundle-remote-server.crt"
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLProxyCARevocationPath</name>
<description>Directorio de CRLs de CA codificadas en PEM para la Autenticación
Remota de Servidor</description>
<syntax>SSLProxyCARevocationPath <em>ruta-al-directorio</em></syntax>
<contextlist><context>server config</context> <context>virtual host</context>
<context>proxy section</context></contextlist>

<usage>
<p>
Esta directiva configura el directorio donde se alojan las Listas de Revocación de
Certificado (CRL) de las Autoridades de Certificación (CA) de los servidores a 
los que conecta. Estas se usan para revocar el certificado del servidor remoto
en la Autenticación del Servidor Remoto.</p>
<p>
Los ficheros en este directorio tienen que ser codificados en PEM y se acceden
con nombres de ficheros con hash. Así que generalmente no sólo tiene que poner
los ficheros CRL ahí. También tiene que crear enlaces simbólicos llamados
<em>valor-de-hash</em><code>.rN</code>. Y siempre debería asegurarse de que este
directorio tiene los enlaces simbólicos apropiados.</p>
<example><title>Ejemplo</title>
<highlight language="config">
SSLProxyCARevocationPath "/usr/local/apache2/conf/ssl.crl/"
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLProxyCARevocationFile</name>
<description>Fichero de CRLs de CA codificados en PEM concatenados para la 
Autenticación Remota de Servidor</description>
<syntax>SSLProxyCARevocationFile <em>ruta-al-fichero</em></syntax>
<contextlist><context>server config</context> <context>virtual host</context>
<context>proxy section</context></contextlist>

<usage>
<p>
Esta directiva configura el fichero <em>todo-en-uno</em> donde puede ensamblar
las Listas de Revocación de Certificados (CRL) de las Autoridades de 
Certificación (CA) de los <em>servidores remotos</em> a los que conecta. Estos
se usan para la Autenticación Remota de Servidor. Tal fichero es simplemente la
concatenación de varios ficheros CRL codificados en PEM, en orden de preferencia.
Esto se puede usar alternativamente a/o adicionalmente a 
<directive module="mod_ssl">SSLProxyCARevocationPath</directive>.</p>
<example><title>Ejemplo</title>
<highlight language="config">
SSLProxyCARevocationFile "/usr/local/apache2/conf/ssl.crl/ca-bundle-remote-server.crl"
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLProxyCARevocationCheck</name>
<description>Activa la comprobación de revocación basada en CRL para la
Autenticación Remota de Servidor</description>
<syntax>SSLProxyCARevocationCheck chain|leaf|none</syntax>
<default>SSLProxyCARevocationCheck none</default>
<contextlist><context>server config</context> <context>virtual host</context>
<context>proxy section</context></contextlist>

<usage>
<p>
Activa la comprobación de listas de revocación de certificado (CRL) para
los <em>servidores remotos</em> a los que conecta. Al menos una de las directivas
<directive module="mod_ssl">SSLProxyCARevocationFile</directive>
o <directive module="mod_ssl">SSLProxyCARevocationPath</directive> debe estar
configurada. Cuando se configura a <code>chain</code> (configuración recomendada),
las comprobaciones de CRL se aplican a todos los certificados en la cadena de
certificación, mientras que configurándolo a <code>leaf</code> limita las
comprobaciones al certificado firmado final.
</p>

<note>
<title>Cuando se configura a <code>chain</code> o <code>leaf</code>,
las CRLs <em>deben</em> estar disponibles para la validación con éxito.</title>

<p>
Antes de la versión 2.4.15, la comprobación de CRL en mod_ssl también tenía
éxito cuando no se encontraban CRLs en ninguna de las ubicaciones configuradas 
con <directive module="mod_ssl">SSLProxyCARevocationFile</directive>
o <directive module="mod_ssl">SSLProxyCARevocationPath</directive>.
Con la introducción de esta directiva, el comportamiento ha cambiado: cuando
la comprobación está habilitada, las CRLs <em>deben</em> estar presentes para 
que la validación pueda tener éxito - si no fallará con un error 
<code>"unable to get certificate CRL"</code>.
</p>
</note>
<example><title>Ejemplo</title>
<highlight language="config">
SSLProxyCARevocationCheck chain
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLUserName</name>
<description>Nombre de variable para determinar el nombre de usuario</description>
<syntax>SSLUserName <em>nombre de variable</em></syntax>
<contextlist><context>server config</context>
<context>directory</context>
<context>.htaccess</context></contextlist>
<override>AuthConfig</override>

<usage>
<p>
Esta directiva configura el campo "usuario" en el objeto de solicitud de Apache.
Esto se usa por módulos menores para identificar el usuario con una cadena
de caracteres. En particular esto puede causar que la variable de entorno
<code>REMOTE_USER</code> sea configurada. El <em>nombre de variable</em> puede 
ser cualquiera de las <a href="#envvars">variables de entorno SSL</a>.</p>

<p>Cuando se activa la opción <code>FakeBasicAuth</code>, esta directiva
controla en su lgar el valor del nombre de usuario embebido dentro de la 
cabecera de autenticación básica (vea <a href="#ssloptions">SSLOptions</a>).</p>

<example><title>Ejemplo</title>
<highlight language="config">
SSLUserName SSL_CLIENT_S_DN_CN
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLHonorCipherOrder</name>
<description>Opción para forzar el orden de preferencia de cifrados del 
  servidor</description>
<syntax>SSLHonorCipherOrder on|off</syntax>
<default>SSLHonorCipherOrder off</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>

<usage>
<p>Cuando se selecciona un cifrado durante el saludo SSLv3 o TLSv1, normalmente
se selecciona en función de las preferencias del cliente. Con esta directiva
activada, se usará la preferencia del servidor en su lugar.</p>
<example><title>Ejemplo</title>
<highlight language="config">
SSLHonorCipherOrder on
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLCryptoDevice</name>
<description>Activar el uso de un hardware acelerador criptográfico</description>
<syntax>SSLCryptoDevice <em>engine</em></syntax>
<default>SSLCryptoDevice builtin</default>
<contextlist><context>server config</context></contextlist>

<usage>
<p>
Esta directiva activa el uso de una placa hardware acelerador criptográfico 
para aliviar parte de la carga del procesamiento de SSL. Esta directiva
sólo puede usarse si el kit de herramientas SSL está compilado con soporte de
"engine"; OpenSSL 0.9.7 y posteriores versiones tienen soporte de "engine" por
defecto, en versiones Openssl 0.9.6 debe usarse "-engine".</p>

<p>Para descubrir qué nombres de "engine" están soportados, ejecute el comando
&quot;<code>openssl engine</code>&quot;.</p>

<example><title>Ejemplo</title>
<highlight language="config">
# For a Broadcom accelerator:
SSLCryptoDevice ubsec
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLOCSPEnable</name>
<description>Activa la validación OCSP para la cadena de certificados del 
cliente</description>
<syntax>SSLOCSPEnable on|off</syntax>
<default>SSLOCSPEnable off</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>

<usage>
<p>Esta opción activa la validación OCSP de la cadena de certificados del 
cliente. Si esta opción está activada, los certificados en la cadena de 
certificados del cliente se validarán contra un respondedor OCSP después de que
se hayan hecho las verificaciones normales (incluidas las comprobaciones de 
CRL).</p>

<p>El respondedor OCSP utilizado o bien se extrae del mismo certificado, o 
derivado de la configuración; vea las directivas 
<directive module="mod_ssl">SSLOCSPDefaultResponder</directive> y
<directive module="mod_ssl">SSLOCSPOverrideResponder</directive>
directives.</p>

<example><title>Ejemplo</title>
<highlight language="config">
SSLVerifyClient on
SSLOCSPEnable on
SSLOCSPDefaultResponder "http://responder.example.com:8888/responder"
SSLOCSPOverrideResponder on
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLOCSPDefaultResponder</name>
<description>Configura la URI por defecto del respondedor para la validación
OCSP</description>
<syntax>SSLOCSDefaultResponder <em>uri</em></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>

<usage>
<p>Esta opción configura el respondedor OCSP por defecto a usar. Si 
<directive module="mod_ssl">SSLOCSPOverrideResponder</directive> no está
activada, la URI facilitada se usará si no hay una URI de respondedor en el
certificado que está siendo verificado.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLOCSPOverrideResponder</name>
<description>Fuerza el uso de una URI de respondedor por defecto para la 
validación OCSP</description>
<syntax>SSLOCSPOverrideResponder on|off</syntax>
<default>SSLOCSPOverrideResponder off</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>

<usage>
<p>Esta opción fuerza que se use el respondedor OCSP por defecto para la 
validación OCSP del certificado, independientemente de si el certificado que
se está validando referencia un respondedor OCSP o no.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLOCSPResponseTimeSkew</name>
<description>Desviación máxima de tiempo permitida para la validación de la
respuesta OCSP</description>
<syntax>SSLOCSPResponseTimeSkew <em>segundos</em></syntax>
<default>SSLOCSPResponseTimeSkew 300</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>

<usage>
<p>Esta opción configura el tiempo máximo permitido de desviación para las
respuestas OCSP
(cuando se están comprobando sus campos <code>thisUpdate</code> y 
<code>nextUpdate</code>).</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLOCSPResponseMaxAge</name>
<description>Edad máxima permitida para las respuestas OCSP</description>
<syntax>SSLOCSPResponseMaxAge <em>segundos</em></syntax>
<default>SSLOCSPResponseMaxAge -1</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>

<usage>
<p>Esta opción configura la edad máxima permitida de las respuestas
OCSP. El valor por defecto (<code>-1</code>) no fuerza una edad máxima, lo que
significa que las respuestas OCSP se consideran válidas mientras su campo
<code>nextUpdate</code> está en una fecha futura.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLOCSPResponderTimeout</name>
<description>Expiración de las consultas OCSP</description>
<syntax>SSLOCSPResponderTimeout <em>segundos</em></syntax>
<default>SSLOCSPResponderTimeout 10</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>

<usage>
<p>Esta opción configura el tiempo de expiración para las consultas a los 
respondedores OCSP, cuando <directive module="mod_ssl">SSLOCSPEnable</directive> 
está activado.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLOCSPUseRequestNonce</name>
<description>Usar un nonce dentro de las consultas OCSP</description>
<syntax>SSLOCSPUseRequestNonce on|off</syntax>
<default>SSLOCSPUseRequestNonce on</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible en httpd 2.4.10 y posterior</compatibility>

<usage>
<p>Esta opción determina si las consultas a respondedores OCSP deberían contener
un "nonce" o no. Por defecto, una consulta "nonce" siempre se comprueba y se usa
contra la de la respuesta. Cuando el responderdor no usa "nonce"s (p.ej. Microsoft
OCSP Responder), esta opción debería estar configuada a 
<code>off</code>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLOCSPNoverify</name>
<description>Salta la verificación de certificados de respondedor 
  OCSP</description>
<syntax>SSLOCSPNoverify <em>On/Off</em></syntax>
<default>SSLOCSPNoverify Off</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible en httpd 2.4.26 y posterior, si se usa OpenSSL 0.9.7 o
posterior</compatibility>
<usage>
<p>Salta la verificación de certificados del respondedor OCSP, generalmente
útil cuando se comprueba un servidor OCSP.</p>
</usage>
</directivesynopsis>


<directivesynopsis>
<name>SSLOCSPResponderCertificateFile</name>
<description>Conjunto de certificados de respondedor OCSP confiables codificados
  en PEM</description>
<syntax>SSLOCSPResponderCertificateFile <em>fichero</em></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible en httpd 2.4.26 y posterior, si se usa con OpenSSL 
  0.9.7 o posterior</compatibility>
<usage>

<p>Esto aporta una lista de certificados confiables de respondedor OCSP para
ser usados durante la validación de certificados de respondedor OCSP. Se confía
en los certificados facilitados de manera implícita sin ninguna comprobación
posterior. Esto se usa generalmente cuando el certificado del respondedor
OCSP es autofirmado o se omite de la respuesta.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLOCSPProxyURL</name>
<description>URL de Proxy a utilizar para las consultas OCSP</description>
<syntax>SSLOCSPProxyURL <em>url</em></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible en httpd 2.4.19 y posterior</compatibility>

<usage>
<p>Esta opción permite configurar la URL de un proxy HTTP que debería usarse para
todas las consultas a respondedores OCSP.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLInsecureRenegotiation</name>
<description>Opción para activar soporte de renegociación 
  insegura</description>
<syntax>SSLInsecureRenegotiation on|off</syntax>
<default>SSLInsecureRenegotiation off</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible si se usa OpenSSL 0.9.8m o posterior</compatibility>

<usage>
<p>Tal y como se especificó originalmente, todas las versiones de protocolo SSL y
TLS (incluído TLS/1.2) eran vulnerables a ataques tipo Man-in-the-Middle
(<a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2009-3555">CVE-2009-3555</a>)
durante una renegociación. Esta vulnerabilidad permitía a un atancante poner
un prefijo a un texto plano específico en la petición HTTP tal y como se veía 
en el servidor web. Se desarrolló una extensión del protocolo para esta vulnerabilidad si estaba soportada tanto por el cliente como por el 
servidor.</p>

<p>Si <module>mod_ssl</module> está compilado contra la versión OpenSSL 0.9.8m
o posterior, por defecto la renegociación sólo está soportada por clientes
que tengan soporte para la nueva extensión del protocolo. Si esta directiva está
activada, la renegociación se permitirá con los clientes antiguos (no 
parcheados), aunque de manera insegura.</p>

<note type="warning"><title>Aviso de Seguridad</title>
<p>Si se activa esta directiva, las conexiones SSL serán vulnerables a ataques
Man-in-the-Middle de prefijo tal y como se describe en
<a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2009-3555">CVE-2009-3555</a>.</p>
</note>

<example><title>Ejemplo</title>
<highlight language="config">
SSLInsecureRenegotiation on
</highlight>
</example>

<p>La variable de entorno <code>SSL_SECURE_RENEG</code> se puede usar desde un 
script CGI o desde SSI para determinar si la renegociación segura está soportada
para la conexión SSL en cuestión.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLUseStapling</name>
<description>Activa stapling de las respuestas OCSP en el saludo 
  TLS</description>
<syntax>SSLUseStapling on|off</syntax>
<default>SSLUseStapling off</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible si se usa OpenSSL 0.9.8h o posterior</compatibility>

<usage>
<p>Esta opción activa el stapling de OCSP, tal y como se define en la extensión
TLS "Solicitud de Estado de Certificado" especificada en el RFC 6066. Si está
activado (y solicitado por el cliente), mod_ssl incluirá una respuesta OCSP de
su propio certificado en el saludo TLS. Configurar una 
<directive module="mod_ssl">SSLStaplingCache</directive> es un pre-requisito para
activar stapling de OCSP.</p>

<p>El stapling de OCSP releva al cliente de consultar el respondedor OCSP por si
mismo, pero debería tenerse en cuenta que con la especificación RFC 6066, la 
respuesta de <code>CertificateStatus</code> del servidor podría sólo incluir 
una respuesta OCSP de un sólo certificado. Para los certificados de servidor
con certificados de CA intermedias en su cadena (lo típico hoy en día),
stapling en su implementación actual por tanto sólo consigue su objetivo
parcialmente de "ahorrar varias peticiones y consumo de recursos" - vea también
el <a href="http://www.ietf.org/rfc/rfc6961.txt">RFC 6961</a>
(Extensión de TLS del Estado de Múltiples Certificados).
</p>

<p>Cuando el stapling de OCSP está activado, se usa el mutex 
<code>ssl-stapling</code> para controlar el acceso a la cahe de stapling de OCSP
para prevenir corrupción, y se usa el mutex <code>sss-stapling-refresh</code> 
para controlar los refrescos a las respuestas OCSP. Estos mutexes pueden ser
configurados usando la directiva 
<directive module="core">Mutex</directive>.
</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLStaplingCache</name>
<description>Configura la cache del stapling de OCSP</description>
<syntax>SSLStaplingCache <em>tipo</em></syntax>
<contextlist><context>server config</context></contextlist>
<compatibility>Disponible si se usa OpenSSL 0.9.8h o posterior</compatibility>

<usage>
<p>Configura la cache utilizada para almacenar las respuestas OCSP que se 
incluyen en el saludo TLS si 
<directive module="mod_ssl">SSLUseStapling</directive> está activada. La 
coniguración de la cache es obligatoria para el stapling the OCSP. Con la
excepción de <code>none</code> y <code>nonenotnull</code>, se da soporte a
los mismos tipos de almacenamiento que con 
<directive module="mod_ssl">SSLSessionCache</directive>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLStaplingResponseTimeSkew</name>
<description>Tiempo máximo permitido para la validación del stapling 
  OCSP</description>
<syntax>SSLStaplingResponseTimeSkew <em>segundos</em></syntax>
<default>SSLStaplingResponseTimeSkew 300</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible si se usa OpenSSL 0.9.8h o posterior</compatibility>

<usage>
<p>Esta opción configura el tiempo máximo de desviación cuando mod_ssl comprueba 
los campos <code>thisUpdate</code> y <code>nextUpdate</code> de las respuestas
OCSP que se incluyen en el saludo TLS (Stapling de OCSP). sólo aplicable si
<directive module="mod_ssl">SSLUseStapling</directive> está activada.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLStaplingResponderTimeout</name>
<description>Tiempo máximo para las consultas de stapling de OCSP</description>
<syntax>SSLStaplingResponderTimeout <em>segundos</em></syntax>
<default>SSLStaplingResponderTimeout 10</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible si se usa OpenSSL 0.9.8h o posterior</compatibility>

<usage>
<p>Esta opción configura el tiempo máximo para consultas a respondedores OCSP
cuando <directive module="mod_ssl">SSLUseStapling</directive> está activada y 
mod_ssl está consultando a un respondedor por motivos de stapling de OCSP.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLStaplingResponseMaxAge</name>
<description>Edad máxima permitida para respuesta de stapling OCSP</description>
<syntax>SSLStaplingResponseMaxAge <em>segundos</em></syntax>
<default>SSLStaplingResponseMaxAge -1</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible si se usa OpenSSL 0.9.8h o posterior</compatibility>

<usage>
<p>Esta opción configura la edad máxima permitida ("frescura") cuando se 
consideran las respuestas OCSP para stapling, p. ej. cuando
<directive module="mod_ssl">SSLUseStapling</directive> está activada.
El valor por defecto (<code>-1</code>) no fuerza una edad máxima, lo que 
significa que las respuestas OCSP se consideran válidas mientras el valor del
campo <code>nextUpdate</code> está en una fecha futura.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLStaplingStandardCacheTimeout</name>
<description>Número de segundos antes de expirar las respuestas en la cache del
stapling de OCSP</description>
<syntax>SSLStaplingStandardCacheTimeout <em>segundos</em></syntax>
<default>SSLStaplingStandardCacheTimeout 3600</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible si se usa OpenSSL 0.9.8h o posterior</compatibility>

<usage>
<p>Configura el límite de tiempo en segundos antes de que las respuestas en el 
cache de stapling de OCSP (configuradas con 
<directive module="mod_ssl">SSLStaplingCache</directive>) expiren. Esta 
directiva aplica a respuestas <em>válidas</em>, mientras que
<directive module="mod_ssl">SSLStaplingErrorCacheTimeout</directive> se
usa para controlar el límite de tiempo para respuestas inválidas/indisponibles.
</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLStaplingReturnResponderErrors</name>
<description>Pasa los errores relacionados con stapling de OCSP al cliente
</description>
<syntax>SSLStaplingReturnResponderErrors on|off</syntax>
<default>SSLStaplingReturnResponderErrors on</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible si se usa OpenSSL 0.9.8h o posterior</compatibility>

<usage>
<p>Cuando se activa, mod_ssl pasará las respuestas de consultas sin éxito 
relacionadas con el stapling OCSP (tales como respuestas con un estado general
que no sea otro que "con éxito", respuestas con un estado de certificado que no
sea otro que "bueno", respuestas de expirado, etc.) al cliente.
Si la configura a <code>off</code>, sólo respuestas indicando un estado de 
certificado "bueno" se incluirán en el saludo TLS.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLStaplingFakeTryLater</name>
<description>Sintetiza respuestas "tryLater" para consultas fallidas de stapling
de OCSP</description>
<syntax>SSLStaplingFakeTryLater on|off</syntax>
<default>SSLStaplingFakeTryLater on</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible si se usa OpenSSL 0.9.8h o posterior</compatibility>

<usage>
<p>Cuando se activa y una consulta de stapling a un respondedor OCSP falla, 
mod_ssl sintetizará una respuesta "tryLater" para el cliente. sólo efectiva si
<directive module="mod_ssl">SSLStaplingReturnResponderErrors</directive> 
también está activada.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLStaplingErrorCacheTimeout</name>
<description>Número de segundos antes de expirar respuestas inválidas en la 
cache del stapling de OCSP</description>
<syntax>SSLStaplingErrorCacheTimeout <em>segundos</em></syntax>
<default>SSLStaplingErrorCacheTimeout 600</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible si se usa OpenSSL 0.9.8h o posterior</compatibility>

<usage>
<p>Configura el tiempo límite en segundos antes de que las respuestas 
<em>inválidas</em> en la cache de stapling OCSP (configuradas con 
<directive module="mod_ssl">SSLStaplingCache</directive>) expiren. Para 
configurar el tiempo límite de respuestas válidas, vea
<directive module="mod_ssl">SSLStaplingStandardCacheTimeout</directive>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLStaplingForceURL</name>
<description>Sobreescribe la URI especificada por el respondedor OCSP 
  especificada en la extensión AIA del certificado</description>
<syntax>SSLStaplingForceURL <em>uri</em></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible si se usa OpenSSL 0.9.8h o posterior</compatibility>

<usage>
<p>Esta directiva sobreescribe la URI de un respondedor OCSP obtenida de la 
extensión authorityInfoAccess (AIA) del certificado.
Un uso potencial puede ser cuando se usa un proxy para hacer consultas OCSP.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLSessionTicketKeyFile</name>
<description>Clave persistente de encriptación/desencriptación para ticket de
sesión TLS</description>
<syntax>SSLSessionTicketKeyFile <em>ruta-al-fichero</em></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible en httpd 2.4.0 y posterior, si se usaOpenSSL 0.9.8h o
posterior</compatibility>

<usage>
<p>Opcionalmente configura una clave secreta para la encriptación y 
desencriptación de tickets de sesión TLS, tal y como se define en 
<a href="http://www.ietf.org/rfc/rfc5077.txt">RFC 5077</a>. Principalmente
adecuado para entornos clusterizados donde la información de sesiones TLS
debería ser compartida entre varios nodos. Para configuraciones de una sola
instancia http, es recomendable <em>no</em> configurar un fichero clave
de ticket, pero si depender de varias claves generadas (al azar) por mod_ssl 
en el arranque, en su lugar.</p>
<p>El fichero clave de ticket debe contener 48 bytes de datos aleatorios, 
preferiblemente credos de una fuente con alta entropía. En un sistema basado en
Unix, un fichero clave de ticket puede generarse como sigue:</p>

<example>
dd if=/dev/random of=/path/to/file.tkey bs=1 count=48
</example>

<p>Las claves de ticket deberían rotarse (sustituirse) frecuentemente, puesto
que esta es la única forma de invalidar sesiones de ticket existentes - Openssl 
actualmente no permite especificar un tiempo límite de validez de tickets. Una 
nueva clave de ticket sólo se usa después de reiniciar el servidor web.
Todas las sesiones de tickets existentes son inválidas después de un 
reinicio.</p>

<note type="warning">
<p>El fichero clave de ticket contiene material sensible de claves y debería
protegerse con permisos de fichero de una manera similar a las que se deben
usar para los ficheros utilizados con
<directive module="mod_ssl">SSLCertificateKeyFile</directive>.</p>
</note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLCompression</name>
<description>Activa la compresión a nivel de SSL</description>
<syntax>SSLCompression on|off</syntax>
<default>SSLCompression off</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible en httpd 2.4.3 y posterior, si se usa OpenSSL 0.9.8 o
posterior; disponible en el contexto de virtualhost si se usa OpenSSL 1.0.0 o
posterior. El valor por defecto solía ser <code>on</code> en la versión 
2.4.3</compatibility>

<usage>
<p>Esta directiva permite activar la compresión a nivel de SSL.</p>
<note type="warning">
<p>Activar la compresión provoca problemas de seguridad en la mayoría de las
configuraciones (como el conocido ataque CRIME).</p>
</note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLSessionTickets</name>
<description>Activa o desactiva el uso de tickets de sesión TLS</description>
<syntax>SSLSessionTickets on|off</syntax>
<default>SSLSessionTickets on</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible en httpd 2.4.11 y posterior, si se usa OpenSSL 0.9.8f
o posterior.</compatibility>

<usage>
<p>Esta directiva permite activar o desactivar el uso de los tickets de sesión
TLS (RFC 5077).</p>
<note type="warning">
<p>Los tickets de sesión TLS se activan por defecto. Usarlos sin reiniciar el
servidor web con una frecuencia apropiada (p. ej. diariamente) compromete
un "forward secrecy" perfecto</p>
</note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLOpenSSLConfCmd</name>
<description>Configura parámetros OpenSSL a través de su API <em>SSL_CONF</em>
</description>
<syntax>SSLOpenSSLConfCmd <em>nombre-de-comando</em> 
<em>parámetro-de-comando</em></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible en httpd 2.4.8 y posterior, si se usa OpenSSL 1.0.2 o
posterior</compatibility>

<usage>
<p>Esta directiva expone <em>SSL_CONF</em> de la API de OpenSSL para mod_ssl, 
permitiendo una configuración flexible de parámetros para OpenSSL sin la 
necesidad de implementar directivas adicionales de <module>mod_ssl</module> 
cuando se añaden nuevas características a OpenSSL.</p>

<p>El conjunto de comandos disponibles de 
<directive>SSLOpenSSLConfCmd</directive> depende de la versión OpenSSL utilizada 
para <module>mod_ssl</module> (al menos la versión 1.0.2 es necesaria). Para una 
lista de nombres de comandos
soportados, vea la sección <em>Comandos soportados para fichero de 
configuración</em> en la página de manual 
<a href="http://www.openssl.org/docs/man1.0.2/ssl/SSL_CONF_cmd.html#SUPPORTED-CONFIGURATION-FILE-COMMANDS">SSL_CONF_cmd(3)</a> 
de OpenSSL.</p>

<p>Algunos de los comandos de <directive>SSLOpenSSLConfCmd</directive> se pueden
usar como alternativa a directivas existentes (tales como
<directive module="mod_ssl">SSLCipherSuite</directive> o
<directive module="mod_ssl">SSLProtocol</directive>),
aunque debería tenerse en cuenta que la sintaxis / valores disponibles para
parámetros pueden ser diferentes.</p>

<example><title>Ejemplos</title>
<highlight language="config">
SSLOpenSSLConfCmd Options -SessionTicket,ServerPreference
SSLOpenSSLConfCmd ECDHParameters brainpoolP256r1
SSLOpenSSLConfCmd ServerInfoFile "/usr/local/apache2/conf/server-info.pem"
SSLOpenSSLConfCmd Protocol "-ALL, TLSv1.2"
SSLOpenSSLConfCmd SignatureAlgorithms RSA+SHA384:ECDSA+SHA256
</highlight>
</example>
</usage>
</directivesynopsis>

<directivesynopsis type="section" idtype="section">
<name>SSLPolicyDefine</name>
<description>Define un conjunto de nombres de configuraciones SSL</description>
<syntax>&lt;SSLPolicyDefine <em>nombre</em>&gt;</syntax>
<contextlist><context>server config</context></contextlist>
<compatibility>Disponible in httpd 2.4.30 y posterior</compatibility>

<usage>
<p>Esta directiva define un conjunto de configuraciones SSL y les da un nombre.
Este nombre se puede usar en las directivas <directive>SSLPolicy</directive> y 
<directive>SSLProxyPolicy</directive> para aplicar esta configuración en el 
contexto actual.</p>

<example><title>Definición y Uso de una Política</title>
<highlight language="config">
&lt;SSLPolicyDefine safe-stapling&gt;
   SSLUseStapling on
   SSLStaplingResponderTimeout 2
   SSLStaplingReturnResponderErrors off
   SSLStaplingFakeTryLater off
   SSLStaplingStandardCacheTimeout 86400
&lt;/SSLPolicyDefine&gt;

   ...
   &lt;VirtualHost...&gt;
      SSLPolicy safe-stapling
      ...
</highlight>
</example>

<p>Por un lado, esto puede hacer que la configuración del servidor sea mucho
más fácil de <em>leer</em> y <em>mantener</em>. Por otro lado, está destinada
a hacer SSL más fácil y seguro de <em>usar</em>. Para lo último, Apache httpd
viene con un conjunto de políticas pre-definidas que reflejan buenas prácticas
de código abierto. La política "modern", por ejemplo, lleva las configuraciones
para hacer que su servidor trabaje de manera segura y compatible con navegadores
actuales.</p>

<p>La lista de políticas predefinidas en su Apache pueden obtenerse lanzando
el siguiente comando. Esta lista muestra las configuraciones detalladas con
las que está definida cada política:</p>

<example><title>Lista todas las Políticas Definidas</title>
<highlight language="sh">
httpd -t -D DUMP_SSL_POLICIES
</highlight>
</example>

<p>Esta directiva sólo se puede usar en la configuración del servidor (contexto
global). Puede usar la mayoría de las directivas SSL*, sin embargo algunas sólo
se pueden usar una vez y no se pueden utilizar dentro de definiciones de 
política. Estas son  <directive>SSLCryptoDevice</directive>, 
<directive>SSLRandomSeed</directive>, 
<directive>SSLSessionCache</directive> y
<directive>SSLStaplingCache</directive>.
</p>

<p>Dos políticas no pueden tener el mismo nombre. Sin embargo, las políticas se
pueden redefinir:</p>

<example><title>Sobreescribir Políticas</title>
<highlight language="config">
&lt;SSLPolicyDefine proxy-trust&gt;
   SSLProxyVerify require
&lt;/SSLPolicyDefine&gt;
   ...
&lt;SSLPolicyDefine proxy-trust&gt;
   SSLProxyVerify none
&lt;/SSLPolicyDefine&gt;
</highlight>
</example>

<p>Las definiciones de Política se <em>añaden</em> en el orden que aparecen, 
pero se <em>aplican</em> cuando se ha leído toda la configuración. Esto 
significa que cualquier uso de 'proxy-trust' significará 'SSLProxyVerify none'. 
La primera definición no tiene ningún efecto. Esto permite que las políticas
pre-instaladas sean sustituidas sin la necesidad de desactivarlas.</p>

<p>Además de reemplazar políticas, redefiniciones pueden alterar un aspecto de
una política:</p>

<example><title>Policy Redefine</title>
<highlight language="config">
&lt;SSLPolicyDefine proxy-trust&gt;
   SSLProxyVerify require
&lt;/SSLPolicyDefine&gt;
   ...
&lt;SSLPolicyDefine proxy-trust&gt;
   SSLPolicy proxy-trust
   SSLProxyVerifyDepth 10
&lt;/SSLPolicyDefine&gt;
</highlight>
</example>

<p>Esto re-utiliza todas las configuraciones de un 'proxy-trust' previo y añade
una directiva encima de él. Todas las demás todavía aplican. Esto es muy útil
cuando las políticas pre-definidas (por Apache mismo o un distribuidor) son
 <em>casi</em> como lo que necesitas. Previamente, tales definiciones fueron
(copiadas y) editadas. Esto hacía que actualizarlas fuera difícil. Ahora pueden
configurarse así:</p>

<example><title>Ajusta una Política Pre-Definida</title>
<highlight language="config">
Include ssl-policies.conf

&lt;SSLPolicyDefine modern&gt;
   SSLPolicy modern
   SSLProxyVerify none
&lt;/SSLPolicyDefine&gt;
</highlight>
</example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLPolicy</name>
<description>Aplica una Política SSL por nombre</description>
<syntax>SSLPolicy <em>nombre</em></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible en httpd 2.5.0 y posterior</compatibility>

<usage>
<p>Esta directiva aplica el conjunto de directivas SSL definidas bajo
'nombre' (vea <directive type="section">SSLPolicyDefine</directive>) como las
configuraciones <em>base</em> en el contexto actual. Apache viene con las 
siguientes políticas pre-definidas de Mozilla, los desarrolladores del 
navegador Firefox 
(<a href="https://wiki.mozilla.org/Security/Server_Side_TLS#Recommended_configurations">
vea aquí para una descripción detallada de ellas.</a>):
</p>
<ul>
    <li><code>modern</code>: recomendada cuando su servidor es accesible desde
    Internet. Funciona con todos los navegadores modernos, pero dispositivos
    antiguos podrían no ser capaces de conectar.</li>
    <li><code>intermediate</code>: el recurso si necesita dar soporte a clientes
    antiguos (pero no muy antiguos).</li>
    <li><code>old</code>: cuando necesita dar acceso a Windows XP/Internet
    Explorer 7. El último recurso.</li>
</ul>

<p>Puede comprobar una descripción detallada de todas las políticas definidas
a través de la línea de comandos:</p>
<example><title>Listar Todas las Políticas Definidas</title>
<highlight language="sh">
httpd -t -D DUMP_SSL_POLICIES
</highlight>
</example>

<p>Una SSLPolicy define la línea base para el contexto en la que se utiliza. Eso
significa que cualquier otra directiva SSL en el mismo contexto la sobrescribirá.
Como ejemplo de esto, vea el valor efectivo de 
<directive>SSLProtocol</directive> en la siguiente configuración:</p>

<example><title>Precedencia de Política</title>
<highlight language="config">
&lt;VirtualHost...&gt; # efectivo en: 'all'
   SSLPolicy modern
   SSLProtocol all
&lt;/VirtualHost&gt;

&lt;VirtualHost...&gt; # efectivo en: 'all'
   SSLProtocol all
   SSLPolicy modern
&lt;/VirtualHost&gt;

SSLPolicy modern
&lt;VirtualHost...&gt; # efectivo en: 'all'
   SSLProtocol all
&lt;/VirtualHost&gt;
   
SSLProtocol all
&lt;VirtualHost...&gt; # efectivo en: '+TLSv1.2'
  SSLPolicy modern
&lt;/VirtualHost&gt;
</highlight>
</example>

<p>Puede haber más de una política aplicada en un contexto. La últimas 
sobrescribiendo las previas: :</p>

<example><title>Ordenando Políticas</title>
<highlight language="config">
&lt;VirtualHost...&gt; # protocolo efectivo: 'all -SSLv3'
   SSLPolicy modern
   SSLPolicy intermediate
&lt;/VirtualHost&gt;

&lt;VirtualHost...&gt; # protocolo efectivo: '+TLSv1.2'
   SSLPolicy intermediate
   SSLPolicy modern
&lt;/VirtualHost&gt;
</highlight>
</example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SSLProxyPolicy</name>
<description>Aplica directivas de tipo SSLProxy* en una SSLPolicy</description>
<syntax>SSLProxyPolicy <em>nombre</em></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<compatibility>Disponible en httpd 2.4.30 y posterior</compatibility>

<usage>
<p>Esta directiva es similar a <directive>SSLPolicy</directive>, pero aplica
sólo a directivas de SSLProxy* definidas en la política. Esto ayuda cuando 
necesita distintas políticas para los clientes y los backends:</p>

<example><title>Otras Políticas sólo para Proxy</title>
<highlight language="config">
SSLPolicy modern
SSLProxyPolicy intermediate
</highlight>
</example>

<p>En este ejemplo, la política 'modern' se aplica a los clientes y backends.
Entonces a las partes de los backend se sobrescriben con las configuraciones
de políticas de 'intermediate'.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
