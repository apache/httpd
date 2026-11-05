<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1852270 -->
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

<modulesynopsis metafile="mod_proxy_express.xml.meta">

<name>mod_proxy_express</name>
<description>Extensión de proxy inverso masivo configurado dinámicamente para
<module>mod_proxy</module></description>
<status>Extension</status>
<sourcefile>mod_proxy_express.c</sourcefile>
<identifier>proxy_express_module</identifier>
<compatibility>Disponible en Apache 2.3.13 y posteriores</compatibility>

<summary>
    <p>Este módulo crea proxies inversos masivos configurados dinámicamente,
    mapeando la cabecera <code>Host:</code> de la petición HTTP a
    un nombre de servidor y una URL de backend almacenados en un archivo DBM.
    Esto permite usar fácilmente un gran número de proxies inversos
    sin cambios de configuración. Tiene muchas menos funcionalidades
    que <module>mod_proxy_balancer</module>, que también proporciona
    crecimiento dinámico, pero está pensado para gestionar números de
    backends mucho, mucho mayores. Es ideal como
    conmutador HTTP de front-end y para arquitecturas de
    microservicios.</p>

    <p>Este módulo <em>requiere</em> el servicio de <module
    >mod_proxy</module>.</p>

    <note type="warning"><title>Advertencia</title>
      <p>No active el proxy hasta que haya <a
      href="mod_proxy.html#access">asegurado su servidor</a>. Los servidores proxy
      abiertos son peligrosos tanto para su red como para Internet en
      general.</p>
    </note>

<note><title>Limitaciones</title>
  <ul>
    <li>Este módulo no pretende sustituir la capacidad dinámica de
      <module>mod_proxy_balancer</module>. En su lugar, pretende ser principalmente
      una alternativa ligera y rápida al uso de <module>mod_rewrite</module>
      con <directive module="mod_rewrite">RewriteMap</directive> y el
      indicador <code>[P]</code> para el proxy inverso mapeado.
    </li>
    <li>No admite en absoluto el uso de expresiones regulares ni coincidencia de patrones.
    </li>
    <li>Emula lo siguiente:
      <highlight language="config">
&lt;VirtualHost *:80&gt;
   ServerName front.end.server
   ProxyPass        "/" "back.end.server:port"
   ProxyPassReverse "/" "back.end.server:port"
&lt;/VirtualHost&gt;
      </highlight>
      Es decir, la URL completa se añade a la URL de backend mapeada.
      Esto está en consonancia con la intención de ser un conmutador de
      proxy inverso simple pero rápido.
    </li>
  </ul>
</note>

</summary>
<seealso><module>mod_proxy</module></seealso>
<seealso><directive module="mod_proxy">BalancerMember</directive></seealso>
<seealso><directive module="mod_proxy">BalancerGrowth</directive></seealso>
<seealso><directive module="mod_proxy">BalancerPersist</directive></seealso>
<seealso><directive module="mod_proxy">BalancerInherit</directive></seealso>

<directivesynopsis>
<name>ProxyExpressEnable</name>
<description>Activa la funcionalidad del módulo.</description>
<syntax>ProxyExpressEnable on|off</syntax>
<default>ProxyExpressEnable off</default>
<contextlist><context>server config</context><context>virtual host</context>
  </contextlist>
<override>FileInfo</override>

<usage>
  <p>La directiva <directive>ProxyExpressEnable</directive>
    controla si el módulo estará activo.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyExpressDBMFile</name>
<description>Ruta al archivo DBM.</description>
<syntax>ProxyExpressDBMFile <var>pathname</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
  </contextlist>
<override>FileInfo</override>

<usage>
  <p>La directiva <directive>ProxyExpressDBMFile</directive>
    apunta a la ubicación del archivo DBM del mapa Express. Este
    archivo sirve para mapear el nombre de servidor entrante, obtenido de
    la cabecera <code>Host:</code>, a una URL de backend.</p>

    <note><title>Nota</title>
      <p>El archivo se construye a partir de un formato de archivo de texto plano
        usando la utilidad <code><a href="../programs/httxt2dbm.html">httxt2dbm</a></code>.</p>

      <example><title>Archivo de mapa ProxyExpress</title>
        ##<br />
        ##express-map.txt:<br />
        ##<br />
        <br />
        www1.example.com   http://192.168.211.2:8080<br />
        www2.example.com   http://192.168.211.12:8088<br />
        www3.example.com   http://192.168.212.10<br />
      </example>

      <example><title>Crear el archivo DBM</title>
        httxt2dbm -i express-map.txt -o emap<br />
      </example>

      <example><title>Configuración</title>
      <highlight language="config">
ProxyExpressEnable on
ProxyExpressDBMFile emap
      </highlight>
      </example>
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyExpressDBMType</name>
<description>Tipo DBM del archivo.</description>
<syntax>ProxyExpressDBMType <var>type</var></syntax>
<default>ProxyExpressDBMType default</default>
<contextlist><context>server config</context><context>virtual host</context>
  </contextlist>
<override>FileInfo</override>

<usage>
  <p>La directiva <directive>ProxyExpressDBMType</directive>
    controla el tipo de DBM esperado por el módulo. El valor por defecto
    es el tipo de DBM por defecto creado con <code>
    <a href="../programs/httxt2dbm.html">httxt2dbm</a></code>.</p>
    <p>Los valores posibles son (no todos pueden estar disponibles en tiempo de ejecución):</p>
<table border="1" style="zebra">
    <columnspec><column width=".3"/><column width=".7"/></columnspec>

    <tr><th>Valor</th><th>Descripción</th></tr>
    <tr><td><code>db</code></td><td> Archivos Berkeley DB</td></tr>
    <tr><td><code>gdbm</code></td><td> Archivos GDBM</td></tr>
    <tr><td><code>ndbm</code></td><td> Archivos NDBM</td></tr>
    <tr><td><code>sdbm</code></td><td> Archivos SDBM (siempre disponible)</td></tr>
    <tr><td><code>default</code></td><td> tipo DBM por defecto</td></tr>
    </table>

</usage>
</directivesynopsis>

</modulesynopsis>
