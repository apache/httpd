<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1939353 -->
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

<modulesynopsis metafile="mod_proxy_hcheck.xml.meta">

<name>mod_proxy_hcheck</name>
<description>Comprobación dinámica del estado de los miembros del balanceador (workers) para
<module>mod_proxy</module></description>
<status>Extension</status>
<sourcefile>mod_proxy_hcheck.c</sourcefile>
<identifier>proxy_hcheck_module</identifier>
<compatibility>Disponible en Apache 2.4.21 y posteriores</compatibility>

<summary>
    <p>Este módulo permite la comprobación dinámica del estado de los miembros
    	del balanceador (workers). Esto puede activarse worker a worker.
    	La comprobación del estado se realiza de forma independiente a las
    	peticiones del proxy inverso en sí.</p>

    <p>Este módulo <em>requiere</em> el servicio de <module>mod_watchdog</module>.</p>

<note><title>Parámetros</title>
  <p>El mecanismo de comprobación del estado se activa usando parámetros
     adicionales de <directive module="mod_proxy">BalancerMember</directive>, que se configuran
     de la forma habitual mediante <directive module="mod_proxy">ProxyPass</directive>:</p>

  <p>Este módulo define un nuevo <a href="mod_proxy.html#status_table">estado</a> (flag)
     de BalancerMember: "<code>C</code>".
     Cuando el worker se pone fuera de línea por fallos detectados por el módulo
     de comprobación del estado, se activa este flag, que puede verse (y modificarse)
     a través de <code>balancer-manager</code>.</p>

    <table>
    <tr><th>Parámetro</th>
        <th>Por defecto</th>
        <th>Descripción</th></tr>
    <tr><td>hcmethod</td>
        <td>None</td>
        <td>No se realiza ninguna comprobación dinámica del estado. Las opciones son:
        	<table>
        		<tr><th>Método</th><th>Descripción</th><th>Nota</th></tr>
        		<tr><td>None</td><td>No se realiza ninguna comprobación dinámica del estado</td><td></td></tr>
        		<tr><td>TCP</td><td>Comprueba que se pueda crear un socket hacia el backend: por ejemplo, "¿estás arriba?"</td><td></td></tr>
        		<tr><td>OPTIONS</td><td>Envía una petición <code>HTTP OPTIONS</code> al backend mediante <code>HTTP/1.0</code></td><td>*</td></tr>
        		<tr><td>HEAD</td><td>Envía una petición <code>HTTP HEAD</code> al backend mediante <code>HTTP/1.0</code></td><td>*</td></tr>
        		<tr><td>GET</td><td>Envía una petición <code>HTTP GET</code> al backend mediante <code>HTTP/1.0</code></td><td>*</td></tr>
        		<tr><td>OPTIONS11</td><td>Envía una petición <code>HTTP OPTIONS</code> al backend mediante <code>HTTP/1.1</code></td><td>*</td></tr>
        		<tr><td>HEAD11</td><td>Envía una petición <code>HTTP HEAD</code> al backend mediante <code>HTTP/1.1</code></td><td>*</td></tr>
        		<tr><td>GET11</td><td>Envía una petición <code>HTTP GET</code> al backend mediante <code>HTTP/1.1</code></td><td>*</td></tr>
<!--
        		<tr><td>CPING</td><td><strong>AJP only</strong> Do <code>CPING/CPONG</code> check</td><td></td></tr>
        		<tr><td>PROVIDER</td><td>Name of <code>provider</code> to be used to check health</td><td></td></tr>
-->
					<tr><td colspan="3"></td></tr>
					<tr><td colspan="3">*: A menos que se use <code>hcexpr</code>, un código de estado HTTP 2xx o 3xx se interpretará como que <em>pasa</em> la comprobación del estado</td></tr>
        	</table>
        </td></tr>
    <tr><td>hcpasses</td>
        <td>1</td>
        <td>Número de comprobaciones del estado correctas antes de que el worker se reactive
        (un número entero, 0 o más)</td></tr>
    <tr><td>hcfails</td>
        <td>1</td>
        <td>Número de comprobaciones del estado fallidas antes de que el worker se desactive
        (un número entero, 0 o más)</td></tr>
    <tr><td>hcinterval</td>
        <td>30</td>
        <td>Periodo de las comprobaciones del estado en segundos (por ejemplo, se realiza cada 30 segundos).
        Usa la sintaxis de directiva <a href="directive-dict.html#Syntax">time-interval</a>.</td></tr>
    <tr><td>hcuri</td>
        <td>&nbsp;</td>
        <td>URI adicional que se añade a la URL del worker para la comprobación del estado.
        Se une a la ruta de la URL del worker, si la tiene, con una única barra,
        de modo que <code>ping</code> y <code>/ping</code> son lo mismo. Un cambio hecho
        en <code>balancer-manager</code> se usa en la siguiente comprobación.</td></tr>
    <tr><td>hctemplate</td>
        <td>&nbsp;</td>
        <td>Nombre de la plantilla, creada mediante <directive module="mod_proxy_hcheck">ProxyHCTemplate</directive>,
            que se usa para establecer los parámetros de comprobación del estado de este worker</td></tr>
    <tr><td>hcexpr</td>
        <td>&nbsp;</td>
        <td>Nombre de la expresión, creada mediante <directive module="mod_proxy_hcheck">ProxyHCExpr</directive>,
            usada para comprobar las cabeceras de la respuesta en busca de estado.<br/>
            <em>Si no se usa, los códigos de estado 2xx a 3xx implican éxito</em></td></tr>
    </table>
</note>

<note><title>Qué acepta una comprobación del estado</title>
  <p>No se confía en que el backend se comporte correctamente. Una comprobación falla si la
     respuesta no está completa (sus cabeceras deben terminar con la línea en blanco, no al
     final de la conexión), tiene más de 100 campos de cabecera o una línea de cabecera
     demasiado larga, o si todo el intercambio tarda más que el <code>timeout</code> del
     worker (el <directive module="core">Timeout</directive> del servidor
     si el worker no tiene uno); un backend que sigue enviando datos no puede mantener
     abierta una comprobación. Para los workers <code>https</code> la comprobación envía
     el nombre del servidor (SNI) y verifica el nombre del certificado igual que lo
     haría una petición proxificada al mismo worker, según las directivas
     <code>SSLProxy*</code> de <module>mod_ssl</module>.</p>
</note>

<note><title>Compatibilidad:</title>
    <p><code>OPTIONS11</code>, <code>HEAD11</code> y <code>GET11</code> están
       disponibles en la versión 2.4.55 y posteriores.</p>
</note>

</summary>
<seealso><module>mod_proxy</module></seealso>

<section id="examples">

	<title>Ejemplos de uso</title>
    <p>El siguiente ejemplo muestra cómo se podría configurar la comprobación del estado
    	para varios servidores backend:</p>

	<!-- This section should probably be extended with more, useful examples -->
	<highlight language="config">
ProxyHCExpr ok234 {%{REQUEST_STATUS} =~ /^[234]/}
ProxyHCExpr gdown {%{REQUEST_STATUS} =~ /^[5]/}
ProxyHCExpr in_maint {hc('body') !~ /Under maintenance/}

&lt;Proxy balancer://foo&gt;
  BalancerMember http://www.example.com/  hcmethod=GET hcexpr=in_maint hcuri=/status.php
  BalancerMember http://www2.example.com/ hcmethod=HEAD hcexpr=ok234 hcinterval=10
  BalancerMember http://www3.example.com/ hcmethod=TCP hcinterval=5 hcpasses=2 hcfails=3
  BalancerMember http://www4.example.com/
&lt;/Proxy&gt;

ProxyPass "/" "balancer://foo"
ProxyPassReverse "/" "balancer://foo"
</highlight>

<p>En este escenario, el estado de <code>http://www.example.com/</code> se comprueba enviando una petición
<code>GET /status.php</code> a ese servidor y comprobando que la página devuelta no incluye la cadena <em>Under maintenance</em>. Si
la incluye, ese servidor se pone en modo de fallo de comprobación del estado, y se desactiva. Esta comprobación dinámica se realiza
cada 30 segundos, que es el valor por defecto.</p>

<p>El estado de <code>http://www2.example.com/</code> se comprueba enviando una simple petición <code>HEAD</code> cada
10 segundos y asegurándose de que el estado de la respuesta es 2xx, 3xx o 4xx. El estado de <code>http://www3.example.com/</code> se comprueba
cada 5 segundos simplemente asegurándose de que el socket hacia ese servidor está activo. Si el backend está marcado como
"caído" y pasa 2 comprobaciones del estado, se reactivará y se añadirá de nuevo al balanceador de carga.
Se necesitan 3 fallos consecutivos de la comprobación del estado para desactivar el servidor y sacarlo
de la rotación. Por último, el estado de <code>http://www4.example.com/</code>
no se comprueba dinámicamente en absoluto.</p>

</section>

<directivesynopsis>
<name>ProxyHCExpr</name>
<description>Crea una expresión de condición con nombre para determinar el estado del backend en función de su respuesta</description>
<syntax>ProxyHCExpr <em>name</em> {<em>ap_expr expression</em>}</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>ProxyHCExpr</directive> permite
       crear una expresión de condición con nombre que comprueba las cabeceras
       de respuesta del servidor backend para determinar su estado. Esta condición
       con nombre se puede asignar después a los miembros del balanceador mediante el
       parámetro <code>hcexpr</code>.</p>

    <example><title>ProxyHCExpr: Permitir 2xx/3xx/4xx como correcto</title>
    <highlight language="config">
ProxyHCExpr ok234 {%{REQUEST_STATUS} =~ /^[234]/}
ProxyPass "/apps"     "balancer://foo"

&lt;Proxy balancer://foo&gt;
  BalancerMember http://www2.example.com/  hcmethod=HEAD hcexpr=ok234 hcinterval=10
&lt;/Proxy&gt;
    </highlight>
    </example>

    <note>
    La <a href="../expr.html">expresión</a> puede usar llaves ("{}") como
    delimitadores de cita además de las comillas normales.
    </note>

    <p>Si se usa un método de comprobación del estado (por ejemplo: <code>GET</code>) que produce un cuerpo
    de respuesta, ese cuerpo se puede comprobar mediante <code>ap_expr</code> usando la función de expresión
    <code>hc()</code>, exclusiva de este módulo. El cuerpo solo se lee en
    memoria para un worker que tenga un <code>hcexpr</code>, y como máximo 1 MB de él: un
    cuerpo mayor hace fallar la comprobación. Sin un <code>hcexpr</code> el cuerpo se lee y
    se descarta.</p>

    <p>En el siguiente ejemplo, enviamos al backend una petición <code>GET</code>
    y si el cuerpo de la respuesta contiene la frase <em>Under maintenance</em>,
    queremos desactivar el backend.</p>

    <example><title>ProxyHCExpr: Comprobación del cuerpo de la respuesta</title>
    <highlight language="config">
ProxyHCExpr in_maint {hc('body') !~ /Under maintenance/}
ProxyPass "/apps"     "balancer://foo"

&lt;Proxy balancer://foo&gt;
  BalancerMember http://www.example.com/ hcexpr=in_maint hcmethod=get hcuri=/status.php
&lt;/Proxy&gt;
    </highlight>
    </example>

    <p><em>NOTA:</em> Dado que el cuerpo de la respuesta puede ser bastante grande, es mejor usarlo con páginas de estado específicas.</p>
</usage>
</directivesynopsis>


<directivesynopsis>
<name>ProxyHCTemplate</name>
<description>Crea una plantilla con nombre para establecer varios parámetros de comprobación del estado</description>
<syntax>ProxyHCTemplate <em>name</em> <em>parameter</em>=<em>setting</em> [...]</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>ProxyHCTemplate</directive> permite
       crear un conjunto con nombre (plantilla) de parámetros de comprobación del estado
       que luego se puede asignar a los miembros del balanceador mediante el
       parámetro <code>hctemplate</code>.</p>

    <example><title>ProxyHCTemplate</title>
    <highlight language="config">
ProxyHCTemplate tcp5 hcmethod=tcp hcinterval=5
ProxyPass "/apps"     "balancer://foo"

&lt;Proxy balancer://foo&gt;
  BalancerMember http://www2.example.com/ hctemplate=tcp5
&lt;/Proxy&gt;
    </highlight>
    </example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyHCTPsize</name>
<description>Establece el tamaño total, a nivel de servidor, del pool de hilos usado por los workers de comprobación del estado</description>
<syntax>ProxyHCTPsize <em>size</em></syntax>
<default>ProxyHCTPsize 16</default>
<contextlist><context>server config</context>
</contextlist>

<usage>
    <p>Si Apache httpd y APR se compilan con soporte de hilos, el módulo de
       comprobación del estado delegará el trabajo de la comprobación real a un pool
       de hilos asociado al proceso Watchdog, lo que permite comprobaciones en paralelo.
       La directiva <directive>ProxyHCTPsize</directive>
       determina el tamaño de este pool de hilos. Si se establece a <code>0</code>, no se usa
       ningún pool de hilos, lo que da lugar a comprobaciones del estado serializadas.</p>

    <example><title>ProxyHCTPsize</title>
    <highlight language="config">
ProxyHCTPsize 32
    </highlight>
    </example>

</usage>
</directivesynopsis>

</modulesynopsis>
