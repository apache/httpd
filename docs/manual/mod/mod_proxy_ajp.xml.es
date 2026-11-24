<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1934059 -->
<!-- Spanish Translation: Arturo Bernal <arturobernalg@gmail.com> -->

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

<modulesynopsis metafile="mod_proxy_ajp.xml.meta">

<name>mod_proxy_ajp</name>
<description>Módulo de soporte AJP para
<module>mod_proxy</module></description>
<status>Extension</status>
<sourcefile>mod_proxy_ajp.c</sourcefile>
<identifier>proxy_ajp_module</identifier>

<summary>
    <p>Este módulo <em>requiere</em> el servicio de <module
    >mod_proxy</module>. Proporciona soporte para el
    <code>Apache JServ Protocol version 1.3</code> (en adelante
    <em>AJP13</em>).</p>

    <p>Así pues, para poder manejar el protocolo <code>AJP13</code>,
    <module>mod_proxy</module> y
    <module>mod_proxy_ajp</module> deben estar presentes en el servidor.</p>

    <note type="warning"><title>Advertencia</title>
      <p>No active el proxy hasta que haya <a
      href="mod_proxy.html#access">asegurado su servidor</a>. Los servidores
      proxy abiertos son peligrosos tanto para su red como para Internet en
      general.</p>
    </note>
</summary>

<seealso><module>mod_proxy</module></seealso>
<seealso><a href="../env.html">Documentación de variables de entorno</a></seealso>

<section id="usage"><title>Uso</title>
    <p>Este módulo se usa para hacer proxy inverso hacia un servidor de
    aplicaciones de backend (por ejemplo, Apache Tomcat) usando el protocolo
    AJP13. El uso es similar al de un proxy inverso HTTP, pero usa el
    prefijo <code>ajp://</code>:</p>

    <example><title>Proxy inverso simple</title>
    <highlight language="config">
ProxyPass "/app" "ajp://backend.example.com:8009/app"
    </highlight>
    </example>

    <p>Opciones como la opción <code>secret</code> de Tomcat (requerida por
    defecto desde Tomcat 8.5.51 y 9.0.31) pueden simplemente añadirse como un
    parámetro independiente al final de <directive module="mod_proxy">ProxyPass</directive>
    o <directive module="mod_proxy">BalancerMember</directive>. Este parámetro
    está disponible en Apache HTTP Server 2.4.42 y posteriores:</p>
    <example><title>Proxy inverso simple con la opción <code>secret</code></title>
    <highlight language="config">
ProxyPass "/app" "ajp://backend.example.com:8009/app" secret=YOUR_AJP_SECRET
    </highlight>
    </example>

    <p>También pueden usarse balanceadores:</p>
    <example><title>Proxy inverso con balanceador</title>
    <highlight language="config">
&lt;Proxy "balancer://cluster"&gt;
    BalancerMember "ajp://app1.example.com:8009" loadfactor=1
    BalancerMember "ajp://app2.example.com:8009" loadfactor=2
    ProxySet lbmethod=bytraffic
&lt;/Proxy&gt;
ProxyPass "/app" "balancer://cluster/app"
      </highlight>
    </example>

    <p>Tenga en cuenta que normalmente no es necesaria la directiva
    <directive module="mod_proxy">ProxyPassReverse</directive>.
    La petición AJP incluye la cabecera host original pasada al proxy, y se
    puede esperar que el servidor de aplicaciones genere cabeceras
    autorreferenciales relativas a este host, por lo que no es necesaria
    ninguna reescritura.</p>

    <p>La principal excepción es cuando la ruta URL en el proxy difiere de
    la del backend. En ese caso, se puede reescribir una cabecera de
    redirección en relación con la URL del host original (no con la URL
    <code>ajp://</code> del backend), por ejemplo:</p>
    <example><title>Reescritura de la ruta con proxy</title>
    <highlight language="config">
ProxyPass "/apps/foo" "ajp://backend.example.com:8009/foo"
ProxyPassReverse "/apps/foo" "http://www.example.com/foo"
    </highlight>
    </example>
    <p>Sin embargo, suele ser mejor desplegar la aplicación en el servidor de
    backend en la misma ruta que en el proxy, en lugar de usar este
    enfoque.</p>
</section>

<section id="env"><title>Variables de entorno</title>
    <p>Las variables de entorno cuyo nombre tiene el prefijo <code>AJP_</code>
    se reenvían al servidor de origen como atributos de la petición AJP
    (con el prefijo <code>AJP_</code> eliminado del nombre de la clave).</p>

    <p>Tenga en cuenta que estos atributos de la petición solo son
    accesibles cuando se solicitan directamente usando el método
    <code>HttpServletRequest.getAttribute</code>: la implementación de Tomcat
    del método
    <a href="https://tomcat.apache.org/tomcat-9.0-doc/api/org/apache/catalina/connector/Request.html#getAttributeNames--"><code>getAttributeNames</code></a>
    no los incluye, ya que se gestionan como atributos internos.</p>
</section>

<section id="overviewprotocol"><title>Resumen del protocolo</title>
    <p>El protocolo <code>AJP13</code> está orientado a paquetes. Es
    presumible que se eligiera un formato binario en lugar del texto plano,
    más legible, por motivos de rendimiento. El servidor web se comunica con
    el contenedor de servlets a través de conexiones TCP. Para reducir el
    coste de la creación de sockets, el servidor web intentará mantener
    conexiones TCP persistentes con el contenedor de servlets, y reutilizar
    una conexión para varios ciclos de petición/respuesta.</p>
    <p>Una vez que se asigna una conexión a una petición concreta, no se
    usará para ninguna otra hasta que el ciclo de gestión de esa petición
    haya terminado. En otras palabras, las peticiones no se multiplexan
    sobre las conexiones. Esto simplifica mucho el código en ambos extremos
    de la conexión, aunque provoca que haya más conexiones abiertas a la
    vez.</p>
    <p>Una vez que el servidor web ha abierto una conexión con el contenedor
    de servlets, la conexión puede estar en uno de los siguientes
    estados:</p>
    <ul>
    <li>Idle (inactiva) <br/> No se está gestionando ninguna petición sobre
    esta conexión.</li>
    <li>Assigned (asignada) <br/> La conexión está gestionando una petición
    concreta.</li>
    </ul>
    <p>Una vez que se asigna una conexión para gestionar una petición
    concreta, la información básica de la petición (por ejemplo, las
    cabeceras HTTP, etc.) se envía a través de la conexión en una forma
    muy condensada (por ejemplo, las cadenas comunes se codifican como
    enteros). Los detalles de ese formato se describen más abajo, en
    Estructura del paquete de petición. Si la petición tiene cuerpo
    <code>(content-length > 0)</code>, este se envía en un paquete
    independiente inmediatamente después.</p>
    <p>En este punto, se supone que el contenedor de servlets está listo
    para empezar a procesar la petición. Mientras lo hace, puede enviar los
    siguientes mensajes de vuelta al servidor web:</p>
    <ul>
    <li>SEND_HEADERS <br/>Enviar un conjunto de cabeceras de vuelta al
    navegador.</li>
    <li>SEND_BODY_CHUNK <br/>Enviar un fragmento de los datos del cuerpo de
    vuelta al navegador.
    </li>
    <li>GET_BODY_CHUNK <br/>Obtener más datos de la petición si todavía no
    se ha transferido por completo. Esto es necesario porque los paquetes
    tienen un tamaño máximo fijo y el cuerpo de una petición puede contener
    cantidades arbitrarias de datos (por ejemplo, en el caso de archivos
    subidos). (Nota: esto no tiene relación con la transferencia fragmentada
    "chunked" de HTTP).</li>
    <li>END_RESPONSE <br/> Finalizar el ciclo de gestión de la petición.</li>
    </ul>
    <p>Cada mensaje va acompañado de un paquete de datos con un formato
    distinto. Vea las estructuras del paquete de respuesta más abajo para más
    detalles.</p>
</section>

<section id="basppacketstruct"><title>Estructura básica del paquete</title>
    <p>Este protocolo tiene cierta herencia de XDR, pero difiere en muchos
    aspectos (por ejemplo, no tiene alineación de 4 bytes).</p>
    <p>AJP13 usa el orden de bytes de red para todos los tipos de datos.</p>
    <p>Hay cuatro tipos de datos en el protocolo: bytes, booleanos,
    enteros y cadenas.</p>
    <dl>
    <dt><strong>Byte</strong></dt><dd>Un único byte.</dd>
    <dt><strong>Booleano</strong></dt>
      <dd>Un único byte, <code>1 = verdadero</code>, <code>0 = falso</code>.
      Usar otros valores distintos de cero como verdadero (es decir, al
      estilo C) puede funcionar en algunos sitios, pero no en otros.</dd>
    <dt><strong>Entero</strong></dt>
      <dd>Un número en el rango de <code>0 a 2^16 (32768)</code>. Almacenado
      en 2 bytes, con el byte de mayor orden primero.</dd>
    <dt><strong>Cadena</strong></dt>
      <dd>Una cadena de tamaño variable (longitud limitada a 2^16).
      Codificada con la longitud empaquetada primero en dos bytes, seguida
      de la cadena (incluyendo el '\0' final). Tenga en cuenta que la
      longitud codificada <strong>no</strong> incluye el '\0' final; es como
      <code>strlen</code>. Esto resulta algo confuso en el lado de Java, que
      está repleto de extrañas instrucciones de autoincremento para saltarse
      estos terminadores. Creo que el motivo por el que se hizo así fue para
      permitir que el código C fuera extra eficiente al leer las cadenas que
      el contenedor de servlets va devolviendo, de forma que el código C
      pueda pasar referencias a un único búfer, sin copiar datos. Si
      faltara el \0, el código C tendría que copiar los datos para obtener
      su propia noción de cadena.</dd>
    </dl>

  <section><title>Tamaño del paquete</title>
    <p>Según gran parte del código, el tamaño máximo del paquete es de
    <code>8 * 1024 bytes (8K)</code>. La longitud real del paquete se
    codifica en la cabecera.</p>
  </section>
  <section><title>Cabeceras del paquete</title>
    <p>Los paquetes enviados del servidor al contenedor empiezan con
    <code>0x1234</code>. Los paquetes enviados del contenedor al servidor
    empiezan con <code>AB</code> (el código ASCII de A seguido del código
    ASCII de B). Después de esos dos primeros bytes, hay un entero
    (codificado como se describió antes) con la longitud de la carga útil.
    Aunque esto pudiera sugerir que la carga útil máxima podría llegar a
    2^16, en realidad el código fija el máximo en 8K.</p>
    <table>
       <columnspec><column width=".2"/><column width=".1"/><column width=".1"/><column width=".2"/><column width=".2"/><column width=".2"/></columnspec>
      <tr>
        <th colspan="6"><em>Formato del paquete (Servidor-&gt;Contenedor)</em></th>
      </tr>
      <tr>
        <th>Byte</th>
        <td>0</td>
        <td>1</td>
        <td>2</td>
        <td>3</td>
        <td>4...(n+3)</td>
      </tr>
      <tr>
        <th>Contenido</th>
        <td>0x12</td>
        <td>0x34</td>
        <td colspan="2">Longitud de los datos (n)</td>
        <td>Datos</td>
      </tr>
    </table>
    <table>
       <columnspec><column width=".2"/><column width=".1"/><column width=".1"/><column width=".2"/><column width=".2"/><column width=".2"/></columnspec>
      <tr>
        <th colspan="6"><em>Formato del paquete (Contenedor-&gt;Servidor)</em></th>
      </tr>
      <tr>
        <th>Byte</th>
        <td>0</td>
        <td>1</td>
        <td>2</td>
        <td>3</td>
        <td>4...(n+3)</td>
      </tr>
      <tr>
        <th>Contenido</th>
        <td>A</td>
        <td>B</td>
        <td colspan="2">Longitud de los datos (n)</td>
        <td>Datos</td>
      </tr>
    </table>
    <p>En la mayoría de los paquetes, el primer byte de la carga útil
     codifica el tipo de mensaje. La excepción son los paquetes de cuerpo de
     la petición enviados del servidor al contenedor: se envían con una
     cabecera de paquete estándar (<code>
     0x1234</code> y después la longitud del paquete), pero sin ningún
     código de prefijo después de eso.</p>
     <p>El servidor web puede enviar los siguientes mensajes al contenedor
     de servlets:</p>
    <table>
       <columnspec><column width=".2"/><column width=".3"/><column width=".5"/></columnspec>
      <tr>
        <td>Código</td>
        <td>Tipo de paquete</td>
        <td>Significado</td>
      </tr>
      <tr>
        <td>2</td>
        <td>Forward Request</td>
        <td>Empezar el ciclo de procesamiento de la petición con los
        siguientes datos</td>
      </tr>
      <tr>
        <td>7</td>
        <td>Shutdown</td>
        <td>El servidor web pide al contenedor que se apague.</td>
      </tr>
      <tr>
        <td>8</td>
        <td>Ping</td>
        <td>El servidor web pide al contenedor que tome el control
        (fase de inicio de sesión seguro).</td>
      </tr>
      <tr>
        <td>10</td>
        <td>CPing</td>
        <td>El servidor web pide al contenedor que responda rápidamente con
        un CPong.
        </td>
      </tr>
      <tr>
        <td>ninguno</td>
        <td>Data</td>
        <td>Tamaño (2 bytes) y los datos del cuerpo correspondientes.</td>
      </tr>
    </table>
    <p>Para garantizar un mínimo de seguridad, el contenedor solo llevará a
    cabo realmente el <code>Shutdown</code> si la petición procede de la
    misma máquina en la que está alojado.</p>
    <p>El primer paquete <code>Data</code> se envía inmediatamente después
    del <code>Forward Request</code> por parte del servidor web.</p>
    <p>El contenedor de servlets puede enviar los siguientes tipos de
    mensajes al servidor web:</p>
    <table>
       <columnspec><column width=".2"/><column width=".3"/><column width=".5"/></columnspec>
      <tr>
        <td>Código</td>
        <td>Tipo de paquete</td>
        <td>Significado</td>
      </tr>
      <tr>
        <td>3</td>
        <td>Send Body Chunk</td>
        <td>Enviar un fragmento del cuerpo desde el contenedor de servlets al
        servidor web (y, presumiblemente, al navegador).</td>
      </tr>
      <tr>
        <td>4</td>
        <td>Send Headers</td>
        <td>Enviar las cabeceras de respuesta desde el contenedor de servlets
        al servidor web (y, presumiblemente, al navegador).</td>
      </tr>
      <tr>
        <td>5</td>
        <td>End Response</td>
        <td>Marca el fin de la respuesta (y, por tanto, del ciclo de gestión
        de la petición).
        </td>
      </tr>
      <tr>
        <td>6</td>
        <td>Get Body Chunk</td>
        <td>Obtener más datos de la petición si todavía no se han
        transferido todos.</td>
      </tr>
      <tr>
        <td>9</td>
        <td>CPong Reply</td>
        <td>La respuesta a una petición CPing</td>
      </tr>
    </table>
    <p>Cada uno de los mensajes anteriores tiene una estructura interna
    distinta, que se detalla más abajo.</p>
  </section>
</section>
<section id="rpacetstruct"><title>Estructura del paquete de petición</title>
    <p>Para los mensajes del servidor al contenedor del tipo
    <em>Forward Request</em>:</p>
    <example><pre>
AJP13_FORWARD_REQUEST :=
    prefix_code      (byte) 0x02 = JK_AJP13_FORWARD_REQUEST
    method           (byte)
    protocol         (string)
    req_uri          (string)
    remote_addr      (string)
    remote_host      (string)
    server_name      (string)
    server_port      (integer)
    is_ssl           (boolean)
    num_headers      (integer)
    request_headers *(req_header_name req_header_value)
    attributes      *(attribut_name attribute_value)
    request_terminator (byte) OxFF
    </pre></example>
    <p>Los <code>request_headers</code> tienen la siguiente estructura:
    </p><example><pre>
req_header_name :=
    sc_req_header_name | (string)  [ver más abajo cómo se analiza esto]

sc_req_header_name := 0xA0xx (integer)

req_header_value := (string)
</pre></example>
    <p>Los <code>attributes</code> son opcionales y tienen la siguiente
    estructura:</p>
    <example><pre>
attribute_name := sc_a_name | (sc_a_req_attribute string)

attribute_value := (string)

    </pre></example>
    <p>Tenga en cuenta que la cabecera más importante es
    <code>content-length</code>, porque determina si el contenedor buscará
    o no otro paquete inmediatamente.</p>
  <section><title>Descripción detallada de los elementos de Forward Request
  </title></section>
  <section><title>Prefijo de la petición</title>
    <p>Para todas las peticiones, este será 2. Vea más arriba los detalles
    sobre los demás códigos de prefijo.</p>
  </section>
  <section><title>Method</title>
    <p>El método HTTP, codificado como un único byte:</p>
    <table>
      <tr><td>Nombre del comando</td><td>Código</td></tr>
      <tr><td>OPTIONS</td><td>1</td></tr>
      <tr><td>GET</td><td>2</td></tr>
      <tr><td>HEAD</td><td>3</td></tr>
      <tr><td>POST</td><td>4</td></tr>
      <tr><td>PUT</td><td>5</td></tr>
      <tr><td>DELETE</td><td>6</td></tr>
      <tr><td>TRACE</td><td>7</td></tr>
      <tr><td>PROPFIND</td><td>8</td></tr>
      <tr><td>PROPPATCH</td><td>9</td></tr>
      <tr><td>MKCOL</td><td>10</td></tr>
      <tr><td>COPY</td><td>11</td></tr>
      <tr><td>MOVE</td><td>12</td></tr>
      <tr><td>LOCK</td><td>13</td></tr>
      <tr><td>UNLOCK</td><td>14</td></tr>
      <tr><td>ACL</td><td>15</td></tr>
      <tr><td>REPORT</td><td>16</td></tr>
      <tr><td>VERSION-CONTROL</td><td>17</td></tr>
      <tr><td>CHECKIN</td><td>18</td></tr>
      <tr><td>CHECKOUT</td><td>19</td></tr>
      <tr><td>UNCHECKOUT</td><td>20</td></tr>
      <tr><td>SEARCH</td><td>21</td></tr>
      <tr><td>MKWORKSPACE</td><td>22</td></tr>
      <tr><td>UPDATE</td><td>23</td></tr>
      <tr><td>LABEL</td><td>24</td></tr>
      <tr><td>MERGE</td><td>25</td></tr>
      <tr><td>BASELINE_CONTROL</td><td>26</td></tr>
      <tr><td>MKACTIVITY</td><td>27</td></tr>
    </table>
    <p>Versiones posteriores de ajp13 transportarán métodos adicionales,
    aunque no estén en esta lista.</p>
  </section>
  <section><title>protocol, req_uri, remote_addr, remote_host, server_name,
  server_port, is_ssl</title>
    <p>Todos estos campos son bastante autoexplicativos. Cada uno de ellos
    es obligatorio y se enviará en cada petición.</p>
  </section>
  <section><title>Headers</title>
    <p>La estructura de <code>request_headers</code> es la siguiente:
    primero se codifica el número de cabeceras <code>num_headers</code>.
    Después, viene una serie de pares de nombre de cabecera
    <code>req_header_name</code> / valor
    <code>req_header_value</code>. Los nombres de cabecera comunes se
    codifican como enteros, para ahorrar espacio. Si el nombre de la
    cabecera no está en la lista de cabeceras básicas, se codifica de forma
    normal (como una cadena, con la longitud como prefijo). La lista de
    cabeceras comunes <code>sc_req_header_name</code> y sus códigos es la
    siguiente (todas distinguen mayúsculas y minúsculas):</p>
    <table>
      <tr><td>Nombre</td><td>Valor de código</td><td>Nombre de código</td></tr>
      <tr><td>accept</td><td>0xA001</td><td>SC_REQ_ACCEPT</td></tr>
      <tr><td>accept-charset</td><td>0xA002</td><td>SC_REQ_ACCEPT_CHARSET
      </td></tr>
      <tr><td>accept-encoding</td><td>0xA003</td><td>SC_REQ_ACCEPT_ENCODING
      </td></tr>
      <tr><td>accept-language</td><td>0xA004</td><td>SC_REQ_ACCEPT_LANGUAGE
      </td></tr>
      <tr><td>authorization</td><td>0xA005</td><td>SC_REQ_AUTHORIZATION</td>
      </tr>
      <tr><td>connection</td><td>0xA006</td><td>SC_REQ_CONNECTION</td></tr>
      <tr><td>content-type</td><td>0xA007</td><td>SC_REQ_CONTENT_TYPE</td>
      </tr>
      <tr><td>content-length</td><td>0xA008</td><td>SC_REQ_CONTENT_LENGTH</td>
      </tr>
      <tr><td>cookie</td><td>0xA009</td><td>SC_REQ_COOKIE</td></tr>
      <tr><td>cookie2</td><td>0xA00A</td><td>SC_REQ_COOKIE2</td></tr>
      <tr><td>host</td><td>0xA00B</td><td>SC_REQ_HOST</td></tr>
      <tr><td>pragma</td><td>0xA00C</td><td>SC_REQ_PRAGMA</td></tr>
      <tr><td>referer</td><td>0xA00D</td><td>SC_REQ_REFERER</td></tr>
      <tr><td>user-agent</td><td>0xA00E</td><td>SC_REQ_USER_AGENT</td></tr>
    </table>
    <p>El código Java que lee esto toma el primer entero de dos bytes y, si
    ve un <code>'0xA0'</code> en el byte más significativo, usa el entero
    del segundo byte como índice en una matriz de nombres de cabecera. Si el
    primer byte no es <code>0xA0</code>, asume que el entero de dos bytes es
    la longitud de una cadena, que se lee a continuación.</p>
    <p>Esto funciona bajo la suposición de que ningún nombre de cabecera
    tendrá una longitud mayor que <code>0x9FFF (==0xA000 - 1)</code>, lo cual
    es perfectamente razonable, aunque algo arbitrario.</p>
    <note><title>Nota:</title>
    La cabecera <code>content-length</code> es extremadamente
    importante. Si está presente y no es cero, el contenedor asume que la
    petición tiene cuerpo (por ejemplo, una petición POST), y
    inmediatamente lee un paquete independiente del flujo de entrada para
    obtener ese cuerpo.
    </note>
  </section>
  <section><title>Attributes</title>
    <p>Los atributos con el prefijo <code>?</code>
    (por ejemplo, <code>?context</code>) son todos opcionales. Para cada uno
    hay un único byte de código que indica el tipo de atributo, y después
    su valor (cadena o entero). Se pueden enviar en cualquier orden (aunque
    el código C siempre los envía en el orden indicado a continuación). Se
    envía un código especial de terminación para señalar el fin de la lista
    de atributos opcionales. La lista de códigos de byte es:</p>
    <table>
      <tr><td>Información</td><td>Valor de código</td><td>Tipo de valor</td><td>Nota</td></tr>
      <tr><td>?context</td><td>0x01</td><td>-</td><td>No está implementado
      actualmente
      </td></tr>
      <tr><td>?servlet_path</td><td>0x02</td><td>-</td><td>No está
      implementado actualmente
      </td></tr>
      <tr><td>?remote_user</td><td>0x03</td><td>String</td><td></td></tr>
      <tr><td>?auth_type</td><td>0x04</td><td>String</td><td></td></tr>
      <tr><td>?query_string</td><td>0x05</td><td>String</td><td></td></tr>
      <tr><td>?jvm_route</td><td>0x06</td><td>String</td><td></td></tr>
      <tr><td>?ssl_cert</td><td>0x07</td><td>String</td><td></td></tr>
      <tr><td>?ssl_cipher</td><td>0x08</td><td>String</td><td></td></tr>
      <tr><td>?ssl_session</td><td>0x09</td><td>String</td><td></td></tr>
      <tr><td>?req_attribute</td><td>0x0A</td><td>String</td><td>Nombre (a
      continuación va el nombre del atributo)</td></tr>
      <tr><td>?ssl_key_size</td><td>0x0B</td><td>Integer</td><td></td></tr>
      <tr><td>?secret</td><td>0x0C</td><td>String</td><td>Soportado desde la
      versión 2.4.42</td></tr>
      <tr><td>are_done</td><td>0xFF</td><td>-</td><td>request_terminator</td></tr>
    </table>
    <p>El código C no establece actualmente <code>context</code> ni
    <code>servlet_path</code>, y la mayor parte del código Java ignora por
    completo lo que se envíe en esos campos (y parte de él realmente puede
    fallar si se envía una cadena después de uno de esos códigos). No se
    sabe si se trata de un error, de una funcionalidad sin implementar o
    simplemente de código vestigial, pero falta en ambos extremos de la
    conexión.</p>
    <p><code>remote_user</code> y <code>auth_type</code> hacen
    presumiblemente referencia a la autenticación a nivel de HTTP, y
    comunican el nombre de usuario del usuario remoto y el tipo de
    autenticación usado para establecer su identidad (por ejemplo, Basic,
    Digest).</p>
    <p><code>query_string</code>, <code>ssl_cert</code>,
    <code>ssl_cipher</code>, <code>ssl_session</code> y
    <code>ssl_key_size</code> hacen referencia a los correspondientes
    aspectos de HTTP y HTTPS.</p>
    <p><code>jvm_route</code> se usa para dar soporte a las sesiones
    persistentes ("sticky sessions"), asociando la sesión de un usuario con
    una instancia concreta de Tomcat en presencia de varios servidores con
    balanceo de carga.</p>
    <p><code>secret</code> se envía cuando se usa el parámetro
    <code>secret=secret_keyword</code> en las directivas
    <directive module="mod_proxy">ProxyPass</directive> o
    <directive module="mod_proxy">BalancerMember</directive>.
    El backend debe soportar secret y los valores deben coincidir.
    <code>request.secret</code> o <code>requiredSecret</code> están
    documentados en la configuración AJP de Apache Tomcat.</p>
    <p>Más allá de esta lista de atributos básicos, se puede enviar
    cualquier número de otros atributos mediante el código
    <code>req_attribute</code> <code>0x0A</code>. Inmediatamente después de
    cada instancia de ese código se envía un par de cadenas que representan
    el nombre y el valor del atributo. Los valores de entorno se pasan por
    este método.</p>
    <p>Finalmente, una vez enviados todos los atributos, se envía el
    terminador de atributos, <code>0xFF</code>. Esto señala tanto el fin de
    la lista de atributos como el fin del paquete de petición.</p>
  </section>
</section>

<section id="resppacketstruct"><title>Estructura del paquete de respuesta</title>
    <p>Para los mensajes que el contenedor puede enviar de vuelta al
    servidor.</p>
    <example><pre>
AJP13_SEND_BODY_CHUNK :=
  prefix_code   3
  chunk_length  (integer)
  chunk        *(byte)
  chunk_terminator (byte) Ox00


AJP13_SEND_HEADERS :=
  prefix_code       4
  http_status_code  (integer)
  http_status_msg   (string)
  num_headers       (integer)
  response_headers *(res_header_name header_value)

res_header_name :=
    sc_res_header_name | (string)   [ver más abajo cómo se analiza esto]

sc_res_header_name := 0xA0 (byte)

header_value := (string)

AJP13_END_RESPONSE :=
  prefix_code       5
  reuse             (boolean)


AJP13_GET_BODY_CHUNK :=
  prefix_code       6
  requested_length  (integer)
    </pre></example>
  <section><title>Detalles:</title></section>
  <section><title>Send Body Chunk</title>
    <p>El fragmento ("chunk") es, básicamente, datos binarios, y se envía
    directamente de vuelta al navegador.</p>
  </section>
  <section><title>Send Headers</title>
    <p>El código de estado y el mensaje son los habituales en HTTP (por
    ejemplo, <code>200</code> y <code>OK</code>). Los nombres de las
    cabeceras de respuesta se codifican de la misma forma que los nombres de
    las cabeceras de la petición. Vea header_encoding más arriba para más
    detalles sobre cómo se distinguen los códigos de las cadenas.<br />
    Los códigos para las cabeceras comunes son:</p>
    <table>
      <tr><td>Nombre</td><td>Valor de código</td></tr>
      <tr><td>Content-Type</td><td>0xA001</td></tr>
      <tr><td>Content-Language</td><td>0xA002</td></tr>
      <tr><td>Content-Length</td><td>0xA003</td></tr>
      <tr><td>Date</td><td>0xA004</td></tr>
      <tr><td>Last-Modified</td><td>0xA005</td></tr>
      <tr><td>Location</td><td>0xA006</td></tr>
      <tr><td>Set-Cookie</td><td>0xA007</td></tr>
      <tr><td>Set-Cookie2</td><td>0xA008</td></tr>
      <tr><td>Servlet-Engine</td><td>0xA009</td></tr>
      <tr><td>Status</td><td>0xA00A</td></tr>
      <tr><td>WWW-Authenticate</td><td>0xA00B</td></tr>
    </table>
    <p>Después del código o del nombre de cabecera en forma de cadena, se
    codifica inmediatamente el valor de la cabecera.</p>
  </section>
  <section><title>End Response</title>
    <p>Señala el fin de este ciclo de gestión de la petición. Si el
    indicador <code>reuse</code> es verdadero <code>(cualquier valor
    distinto de 0 en el código C real)</code>, esta conexión TCP ya puede
    usarse para gestionar nuevas peticiones entrantes. Si <code>reuse</code>
    es falso (==0), la conexión debe cerrarse.</p>
  </section>
  <section><title>Get Body Chunk</title>
    <p>El contenedor solicita más datos de la petición (si el cuerpo era
    demasiado grande para caber en el primer paquete enviado, o cuando la
    petición está fragmentada). El servidor enviará un paquete de cuerpo de
    vuelta con una cantidad de datos que es el mínimo entre
    <code>request_length</code>, el tamaño máximo de envío del cuerpo
    <code>(8186 (8 Kbytes - 6))</code>, y el número de bytes que realmente
    quedan por enviar del cuerpo de la petición.<br/>
    Si no hay más datos en el cuerpo (es decir, el contenedor de servlets
    está intentando leer más allá del final del cuerpo), el servidor enviará
    de vuelta un paquete <em>vacío</em>, que es un paquete de cuerpo con una
    longitud de carga útil de 0.
    <code>(0x12,0x34,0x00,0x00)</code></p>
  </section>
</section>


</modulesynopsis>
