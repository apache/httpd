<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933537 -->
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

<modulesynopsis metafile="mod_remoteip.xml.meta">

<name>mod_remoteip</name>
<description>Sustituye la dirección IP original del cliente de la conexión
por la lista de direcciones IP del user-agent presentada por un proxy o un
balanceador de carga a través de las cabeceras de la petición.
</description>

<status>Base</status>
<sourcefile>mod_remoteip.c</sourcefile>
<identifier>remoteip_module</identifier>

<summary>
    <p>Este módulo se usa para tratar al user-agent que inició la petición
    como el user-agent de origen identificado por httpd a efectos de
    autorización y registro, incluso cuando ese user-agent está detrás de un
    balanceador de carga, un servidor frontend o un servidor proxy.</p>

    <p>El módulo sobrescribe la dirección IP del cliente de la conexión con
    la dirección IP del user-agent indicada en la cabecera de la petición
    configurada con la directiva
    <directive module="mod_remoteip">RemoteIPHeader</directive>.</p>

    <p>Además, este módulo implementa el lado de servidor del
    <a href="https://www.haproxy.org/download/3.1/doc/proxy-protocol.txt">PROXY
    Protocol</a> de HAProxy cuando se usa la directiva
    <directive module="mod_remoteip">RemoteIPProxyProtocol</directive>.</p>

    <p>Una vez sustituida según lo indicado, esta dirección IP del user-agent
    sobrescrita se usa para la funcionalidad
    <directive module="mod_authz_core" name="Require">Require ip</directive>
    de <module>mod_authz_host</module>, es comunicada por
    <module>mod_status</module>, y es registrada por las cadenas de formato
    <code>%a</code> de <module>mod_log_config</module> y <code>%a</code> de
    <module>core</module>. La IP de cliente subyacente de la conexión está
    disponible en la cadena de formato <code>%{c}a</code> y a través de la
    variable <code>CONN_REMOTE_ADDR</code> en
    <a href="../expr.html">expresiones</a>.</p>

    <note type="warning">Es fundamental activar este comportamiento
    únicamente para los hosts intermedios (proxies, etc.) en los que este
    servidor confía, ya que es trivial para el user-agent remoto
    suplantar a otro user-agent.</note>
</summary>

<seealso><module>mod_authz_host</module></seealso>
<seealso><module>mod_status</module></seealso>
<seealso><module>mod_log_config</module></seealso>
<seealso><a href="https://www.haproxy.org/download/3.1/doc/proxy-protocol.txt">Especificación de Proxy Protocol</a></seealso>

<section id="processing"><title>Procesamiento de la IP remota</title>

    <p>Por defecto, Apache identifica al user-agent con el valor client_ip de
    la conexión, y los valores remote_host y remote_logname de la conexión se
    derivan de este. Estos campos intervienen en la autenticación, la
    autorización, el registro y otros fines a través de otros módulos
    cargables.</p>

    <p>mod_remoteip sobrescribe la IP de cliente de la conexión con la IP del
    user-agent anunciada por un proxy o un balanceador de carga, durante la
    duración de la petición. Un balanceador de carga puede establecer una
    conexión keepalive de larga duración con el servidor, y cada petición
    tendrá la IP de user-agent correcta, aunque la dirección IP de cliente
    subyacente del balanceador de carga permanezca sin cambios.</p>

    <p>Cuando se indican varias direcciones IP de user-agent separadas por
    comas en el valor de la cabecera, se procesan en orden de derecha a
    izquierda. El procesamiento se detiene cuando una dirección IP de
    user-agent determinada no es de confianza para presentar la dirección IP
    precedente. El campo de cabecera se actualiza a la lista restante de
    direcciones IP no confirmadas, o, si todas las direcciones IP eran de
    confianza, esta cabecera se elimina por completo de la petición.</p>

    <p>Al sobrescribir la IP de cliente, el módulo almacena la lista de hosts
    intermedios en una nota remoteip-proxy-ip-list, que
    <module>mod_log_config</module> puede registrar usando el token de
    formato <code>%{remoteip-proxy-ip-list}n</code>. Si el administrador
    necesita almacenar esto como una cabecera adicional, este mismo valor
    también puede registrarse como cabecera mediante la directiva
    <directive module="mod_remoteip">RemoteIPProxiesHeader</directive>.</p>

    <note><title>Direcciones IPv4 sobre IPv6 mapeadas</title>
    Como ocurre con httpd en general, cualquier dirección IPv4 sobre IPv6
    mapeada se registra en su representación IPv4.</note>

    <note><title>Direcciones internas (privadas)</title>
    Todas las direcciones internas de los bloques 10/8, 172.16/12,
    192.168/16, 169.254/16 y 127/8 (y las direcciones IPv6 fuera del bloque
    público 2000::/3) solo son evaluadas por mod_remoteip cuando hay
    registrados proxies internos (de intranet) mediante la directiva
    <directive module="mod_remoteip">RemoteIPInternalProxy</directive>.</note>

</section>

<directivesynopsis>
<name>RemoteIPHeader</name>
<description>Declara el campo de cabecera que debe analizarse en busca de direcciones IP de user-agent</description>
<syntax>RemoteIPHeader <var>header-field</var></syntax>
<default>none</default>
<contextlist><context>server config</context><context>virtual host</context></contextlist>

<usage>
    <p>La directiva <directive>RemoteIPHeader</directive> hace que
    <module>mod_remoteip</module> trate el valor de la cabecera
    <var>header-field</var> indicada como la dirección IP del user-agent, o
    la lista de direcciones IP de user-agent intermedias, sujeto a la
    configuración adicional de las directivas
    <directive module="mod_remoteip">RemoteIPInternalProxy</directive> y
    <directive module="mod_remoteip">RemoteIPTrustedProxy</directive>. A menos
    que se usen estas otras directivas, <module>mod_remoteip</module>
    confiará en todos los hosts que presenten un valor de IP en la
    directiva <directive module="mod_remoteip">RemoteIPHeader</directive>.</p>

    <example><title>Ejemplo interno (balanceador de carga)</title>
    <highlight language="config">
        RemoteIPHeader X-Client-IP
        </highlight>
    </example>

    <example><title>Ejemplo de proxy</title>
    <highlight language="config">
        RemoteIPHeader X-Forwarded-For
        </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>RemoteIPInternalProxy</name>
<description>Declara las direcciones IP de intranet de cliente de confianza para presentar el valor de RemoteIPHeader</description>
<syntax>RemoteIPInternalProxy <var>proxy-ip</var>|<var>proxy-ip/subnet</var>|<var>hostname</var> ...</syntax>
<contextlist><context>server config</context><context>virtual host</context></contextlist>

<usage>
    <p>La directiva <directive>RemoteIPInternalProxy</directive> añade una o
    más direcciones (o bloques de direcciones) de confianza para presentar un
    valor válido de RemoteIPHeader de la IP del user-agent. A diferencia de la
    directiva <directive module="mod_remoteip">RemoteIPTrustedProxy</directive>,
    cualquier dirección IP presentada en esta cabecera, incluidas las
    direcciones de intranet privadas, es de confianza cuando procede de estos
    proxies.</p>

    <example><title>Ejemplo interno (balanceador de carga)</title>
    <highlight language="config">
RemoteIPHeader X-Client-IP
RemoteIPInternalProxy 10.0.2.0/24
RemoteIPInternalProxy gateway.localdomain
        </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>RemoteIPInternalProxyList</name>
<description>Declara las direcciones IP de intranet de cliente de confianza para presentar el valor de RemoteIPHeader</description>
<syntax>RemoteIPInternalProxyList <var>filename</var></syntax>
<contextlist><context>server config</context><context>virtual host</context></contextlist>

<usage>
    <p>La directiva <directive>RemoteIPInternalProxyList</directive>
    especifica un archivo analizado al arrancar, y construye una lista de
    direcciones (o bloques de direcciones) de confianza para presentar un
    valor válido de RemoteIPHeader de la IP del user-agent.</p>

    <p>El carácter de almohadilla '<code>#</code>' designa una línea de
    comentario; en caso contrario, cada entrada separada por espacios en
    blanco o saltos de línea se procesa de forma idéntica a la directiva
    <directive module="mod_remoteip">RemoteIPInternalProxy</directive>.</p>

    <example><title>Ejemplo interno (balanceador de carga)</title>
        <highlight language="config">
RemoteIPHeader X-Client-IP
RemoteIPInternalProxyList conf/trusted-proxies.lst
        </highlight>
    </example>

    <example><title>Contenido de conf/trusted-proxies.lst</title>
    <pre>
# Nuestros proxies de confianza internos;
10.0.2.0/24         #Todos en el grupo de pruebas
gateway.localdomain #El balanceador frontend
</pre>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>RemoteIPProxiesHeader</name>
<description>Declara el campo de cabecera en el que se registrarán todas las direcciones IP intermedias</description>
<syntax>RemoteIPProxiesHeader <var>HeaderFieldName</var></syntax>
<contextlist><context>server config</context><context>virtual host</context></contextlist>

<usage>
    <p>La directiva <directive>RemoteIPProxiesHeader</directive> especifica
    una cabecera en la que <module>mod_remoteip</module> recopilará una lista
    de todas las direcciones IP de cliente intermedias de confianza para
    resolver la IP del user-agent de la petición. Tenga en cuenta que las
    direcciones intermedias de
    <directive module="mod_remoteip">RemoteIPTrustedProxy</directive> se
    registran en esta cabecera, mientras que cualquier dirección intermedia de
    <directive module="mod_remoteip">RemoteIPInternalProxy</directive> se
    descarta.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
RemoteIPHeader X-Forwarded-For
RemoteIPProxiesHeader X-Forwarded-By
    </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>RemoteIPProxyProtocol</name>
<description>Activa o desactiva la gestión del protocolo PROXY</description>
<syntax>RemoteIPProxyProtocol On|Off</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<compatibility>RemoteIPProxyProtocol solo está disponible en httpd 2.4.31 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>RemoteIPProxyProtocol</directive> activa o
    desactiva la lectura y gestión de la cabecera de conexión del protocolo
    PROXY. Si se activa con el indicador <code>On</code>, el cliente
    upstream <em>debe</em> enviar la cabecera cada vez que abra una conexión,
    o la conexión se abortará, a menos que esté en la lista de hosts
    excluidos facilitada por la directiva
    <directive module="mod_remoteip">RemoteIPProxyProtocolExceptions</directive>.</p>

    <p>Aunque esta directiva puede especificarse en cualquier host virtual,
    es importante entender que, dado que el protocolo PROXY está basado en
    la conexión y es agnóstico del protocolo, la activación y desactivación
    se basa en realidad en la dirección IP y el puerto. Esto significa que
    si tiene varios hosts virtuales basados en nombre para el mismo host y
    puerto, y lo activa en uno de ellos, quedará activado para todos ellos
    (con ese host y puerto). También significa que, si intenta activarlo en
    uno y desactivarlo en otro, eso no funcionará; en tal caso, prevalece el
    último, y se registrará un aviso indicando qué ajuste fue sobrescrito.</p>

    <highlight language="config">
Listen 80
&lt;VirtualHost *:80&gt;
    ServerName www.example.com
    RemoteIPProxyProtocol On

    #Las peticiones a este host virtual deben llevar una cabecera
    # de protocolo PROXY. Si falta, la conexión se abortará
&lt;/VirtualHost&gt;

Listen 8080
&lt;VirtualHost *:8080&gt;
    ServerName www.example.com
    RemoteIPProxyProtocol On
    RemoteIPProxyProtocolExceptions 127.0.0.1 10.0.0.0/8

    #Las peticiones a este host virtual deben llevar una cabecera
    # de protocolo PROXY. Si falta, la conexión se abortará
    # excepto cuando provenga de localhost o del rango
    # RFC1918 10.x.x.x
&lt;/VirtualHost&gt;
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>RemoteIPProxyProtocolExceptions</name>
<description>Desactiva el procesamiento de la cabecera PROXY para determinados hosts o redes</description>
<syntax>RemoteIPProxyProtocolExceptions host|range [host|range] [host|range]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<compatibility>RemoteIPProxyProtocolExceptions solo está disponible en httpd 2.4.31 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>RemoteIPProxyProtocol</directive>
    activa o desactiva la lectura y gestión de la cabecera de conexión del
    protocolo PROXY. En ocasiones es deseable exigir a los clientes que
    proporcionen la cabecera PROXY, pero permitir que otros clientes se
    conecten sin ella. Esta directiva permite a un administrador del servidor
    configurar un único host o rango CIDR de hosts que pueden hacerlo. Esto
    es, en general, útil para el tráfico de monitorización y administración
    hacia un host virtual que va directo al servidor situado detrás del
    balanceador de carga ascendente.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>RemoteIPTrustedProxy</name>
<description>Declara las direcciones IP de intranet de cliente de confianza para presentar el valor de RemoteIPHeader</description>
<syntax>RemoteIPTrustedProxy <var>proxy-ip</var>|<var>proxy-ip/subnet</var>|<var>hostname</var> ...</syntax>
<contextlist><context>server config</context><context>virtual host</context></contextlist>

<usage>
    <p>La directiva <directive module="mod_remoteip">RemoteIPTrustedProxy</directive> añade una
    o más direcciones (o bloques de direcciones) de confianza para presentar un valor válido de
    RemoteIPHeader de la IP del user-agent. A diferencia de la directiva
    <directive module="mod_remoteip">RemoteIPInternalProxy</directive>, cualquier dirección
    IP de intranet o privada comunicada por dichos proxies, incluidos los
    bloques 10/8, 172.16/12, 192.168/16, 169.254/16 y 127/8 (o fuera del
    bloque público IPv6 2000::/3), no es de confianza como IP del
    user-agent, y se deja en el valor de la cabecera
    <directive module="mod_remoteip">RemoteIPHeader</directive>.</p>

    <example><title>Ejemplo de confianza (balanceador de carga)</title>
        <highlight language="config">
RemoteIPHeader X-Forwarded-For
RemoteIPTrustedProxy 10.0.2.16/28
RemoteIPTrustedProxy proxy.example.com
        </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>RemoteIPTrustedProxyList</name>
<description>Declara las direcciones IP de intranet de cliente de confianza para presentar el valor de RemoteIPHeader</description>
<syntax>RemoteIPTrustedProxyList <var>filename</var></syntax>
<contextlist><context>server config</context><context>virtual host</context></contextlist>

<usage>
    <p>La directiva <directive>RemoteIPTrustedProxyList</directive>
    especifica un archivo analizado al arrancar, y construye una lista de
    direcciones (o bloques de direcciones) de confianza para presentar un
    valor válido de RemoteIPHeader de la IP del user-agent.</p>

    <p>El carácter de almohadilla '<code>#</code>' designa una línea de
    comentario; en caso contrario, cada entrada separada por espacios en
    blanco o saltos de línea se procesa de forma idéntica a la directiva
    <directive module="mod_remoteip">RemoteIPTrustedProxy</directive>.</p>

    <example><title>Ejemplo de confianza (balanceador de carga)</title>
    <highlight language="config">
RemoteIPHeader X-Forwarded-For
RemoteIPTrustedProxyList conf/trusted-proxies.lst
        </highlight>
    </example>

    <example><title>Contenido de conf/trusted-proxies.lst</title>
       # Proxies externos identificados;<br/>
       192.0.2.16/28         #grupo de proxies de teléfonos wap<br/>
       proxy.isp.example.com #un ISP conocido
    </example>
</usage>
</directivesynopsis>


</modulesynopsis>
