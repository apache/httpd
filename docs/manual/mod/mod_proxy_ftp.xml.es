<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933682 -->
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

<modulesynopsis metafile="mod_proxy_ftp.xml.meta">

<name>mod_proxy_ftp</name>
<description>Módulo de soporte FTP para
<module>mod_proxy</module></description>
<status>Extension</status>
<sourcefile>mod_proxy_ftp.c</sourcefile>
<identifier>proxy_ftp_module</identifier>

<summary>
    <p>Este módulo <em>requiere</em> el servicio de <module
    >mod_proxy</module>. Proporciona soporte para hacer de proxy de
    sitios FTP. Observe que el soporte FTP está actualmente limitado a
    el método GET.</p>

    <p>Así, para obtener la capacidad de gestionar peticiones de proxy FTP,
    <module>mod_proxy</module> y <module>mod_proxy_ftp</module>
    tienen que estar presentes en el servidor.</p>

    <note type="warning"><title>Advertencia</title>
      <p>No active el proxy hasta que haya <a
      href="mod_proxy.html#access">asegurado su servidor</a>. Los servidores
      proxy abiertos son peligrosos tanto para su red como para Internet en
      general.</p>
    </note>
</summary>
<seealso><module>mod_proxy</module></seealso>

    <section id="mimetypes"><title>¿Por qué no se descarga el tipo de archivo
    <var>xxx</var> por FTP?</title>
      <p>Probablemente no tenga ese tipo de archivo en concreto definido como
      <code>application/octet-stream</code> en el archivo de configuración mime.types
      de su proxy. Una línea útil puede ser:</p>

      <example>
<pre>application/octet-stream   bin dms lha lzh exe class tgz taz</pre>
      </example>
      <p>Alternativamente, puede preferir usar la directiva <directive module="core">ForceType</directive>
      para que todo sea binario por defecto:</p>
      <example>
        <highlight language="config">
ForceType application/octet-stream
        </highlight>
      </example>
    </section> <!-- /mimetypes -->

    <section id="type"><title>¿Cómo puedo forzar una descarga FTP en ASCII
    del archivo <var>xxx</var>?</title>
      <p>En la rara situación en la que deba descargar un archivo específico usando el
      método de transferencia FTP <code>ASCII</code> (mientras que la transferencia por defecto es en
      modo <code>binary</code>), puede sobrescribir el valor por defecto de
      <module>mod_proxy</module> añadiendo el sufijo <code>;type=a</code> a la petición para forzar una
      transferencia ASCII. (Sin embargo, los listados de directorios FTP siempre se ejecutan en modo ASCII).</p>
    </section> <!-- /type -->

    <section id="ftpnonget"><title>¿Cómo puedo hacer una subida por FTP?</title>
    <p>Actualmente, solo GET es compatible para FTP en <module>mod_proxy</module>. Por supuesto, puede
    usar subida HTTP (POST o PUT) a través de un proxy Apache.</p>
    </section>

    <section id="percent2fhck"><title>¿Cómo puedo acceder a archivos FTP fuera
    de mi directorio home?</title>
      <p>Una URI FTP se interpreta en relación con el directorio home del usuario
      que inicia sesión. Por desgracia, para alcanzar niveles de directorio superiores no se puede
      usar /../, ya que los puntos son interpretados por el navegador y en realidad no se
      envían al servidor FTP. Para abordar este problema, se implementó el llamado <dfn>truco
      %2f de Squid</dfn> en el proxy FTP de Apache; es una
      solución que también usan otros servidores proxy populares como <a
      href="http://www.squid-cache.org/">Squid Proxy Cache</a>. Añadiendo
      <code>/%2f</code> como prefijo a la ruta de su petición, puede hacer que
      dicho proxy cambie el directorio inicial de FTP a <code>/</code> (en lugar
      del directorio home). Por ejemplo, para recuperar el archivo
      <code>/etc/motd</code>, usaría la URL:</p>

      <example>
        ftp://<var>user</var>@<var>host</var>/%2f/etc/motd
      </example>
    </section> <!-- /percent2fhck -->

    <section id="ftppass"><title>¿Cómo puedo ocultar la contraseña FTP en texto claro
    en la línea de URL de mi navegador?</title>
      <p>Para iniciar sesión en un servidor FTP mediante nombre de usuario y contraseña, Apache usa
      distintas estrategias. En ausencia por completo de un nombre de usuario y contraseña en la URL,
      Apache envía un inicio de sesión anónimo al servidor FTP,
      <em>es decir</em>,</p>

      <example>
        user: anonymous<br />
        password: apache-proxy@
      </example>

      <p>Esto funciona para todos los servidores FTP populares configurados para
      acceso anónimo.</p>

      <p>Para un inicio de sesión personal con un nombre de usuario específico, puede incrustar el
      nombre de usuario en la URL, como en:</p>

      <example>
        ftp://<var>username</var>@<var>host</var>/myfile
      </example>

      <note><title>HttpProtocolOptions</title>
        <p>Por defecto, <directive module="core"
        >HttpProtocolOptions</directive> está establecido en <code>Strict</code>,
        lo que rechaza URLs que contienen userinfo (nombre de usuario o contraseña)
        según RFC 7230. Para usar credenciales en URLs FTP, debe establecer
        <code>HttpProtocolOptions Unsafe</code>.</p>
      </note>

      <p>Si el servidor FTP solicita una contraseña al proporcionarle este nombre de usuario (como
      debería), entonces Apache responderá con una respuesta <code>401</code> (se requiere
      autorización), lo que hace que el navegador muestre el diálogo de
      nombre de usuario/contraseña. Al introducir la contraseña, se reintenta el
      intento de conexión, y si tiene éxito, se presenta el recurso
      solicitado. La ventaja de este procedimiento es que su navegador no
      muestra la contraseña en texto claro (como ocurriría si hubiera usado</p>

      <example>
        ftp://<var>username</var>:<var>password</var>@<var>host</var>/myfile
      </example>

      <p>en primer lugar).</p>

      <note><title>Nota</title>
        <p>La contraseña que se transmite de esta manera no se cifra durante
        su trayecto. Viaja entre su navegador y el servidor proxy Apache en
        una cadena en texto claro codificada en base64, y entre el proxy Apache y el
        servidor FTP como texto claro. Por lo tanto, debería pensárselo dos veces antes de
        acceder a su servidor FTP mediante HTTP (¡o antes de acceder a sus archivos
        personales mediante FTP, en general!). Cuando se usan canales inseguros, un espía
        podría interceptar su contraseña durante su trayecto.</p>
      </note>
    </section> <!-- /ftppass -->

    <section id="wildcard"><title>¿Por qué obtengo un listado de archivos cuando esperaba
        que se descargara un archivo?</title>
      <p>Para permitir tanto navegar por los directorios de un servidor FTP como
        descargar archivos, Apache examina la URL de la petición. Si se parece a
        un directorio, o contiene caracteres comodín ("*?[{~"), entonces
        supone que se desea un listado en lugar de una descarga.</p>
      <p>Puede desactivar el tratamiento especial de nombres con caracteres comodín.
        Consulte la directiva <directive module="mod_proxy_ftp">ProxyFtpListOnWildcard</directive>.
      </p>
    </section> <!-- /wildcard -->

<directivesynopsis>
<name>ProxyFtpListOnWildcard</name>
<description>Indica si los comodines en los nombres de archivo solicitados provocan un listado de archivos</description>
<syntax>ProxyFtpListOnWildcard on|off</syntax>
<default>ProxyFtpListOnWildcard on</default>
<contextlist><context>server config</context><context>virtual host</context>
  <context>directory</context></contextlist>
<compatibility>Disponible en Apache 2.3.3 y posteriores</compatibility>

<usage>
  <p>La directiva <directive>ProxyFtpListOnWildcard</directive>
    controla si los caracteres comodín ("*?[{~") en los nombres de archivo
    solicitados hacen que <module>mod_proxy_ftp</module> devuelva un listado
    de archivos en lugar de descargar un archivo. Por defecto (valor on),
    lo hacen.</p>
    <p>Establézcalo en "off" para permitir descargar archivos aunque
    tengan caracteres comodín en sus nombres.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyFtpEscapeWildcards</name>
<description>Indica si los comodines en los nombres de archivo solicitados se escapan al enviarlos al servidor FTP</description>
<syntax>ProxyFtpEscapeWildcards on|off</syntax>
<default>ProxyFtpEscapeWildcards on</default>
<contextlist><context>server config</context><context>virtual host</context>
  <context>directory</context></contextlist>
<compatibility>Disponible en Apache 2.3.3 y posteriores</compatibility>

<usage>
  <p>La directiva <directive>ProxyFtpEscapeWildcards</directive>
    controla si los caracteres comodín ("*?[{~") en los nombres de archivo
    solicitados se escapan con una barra invertida antes de enviarlos al
    servidor FTP. Ese es el comportamiento por defecto, pero muchos servidores FTP
    no saben nada sobre el escapado e intentan servir los nombres de archivo literales
    que recibieron, incluyendo las barras invertidas en los nombres.</p>
    <p>Establézcalo en "off" para permitir descargar archivos con comodines
    en sus nombres desde servidores FTP que no entienden el escapado
    de comodines.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ProxyFtpDirCharset</name>
<description>Define el juego de caracteres para los listados FTP proxificados</description>
<syntax>ProxyFtpDirCharset <var>character_set</var></syntax>
<default>ProxyFtpDirCharset ISO-8859-1</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>Movida desde <module>mod_proxy</module> en Apache 2.3.5.</compatibility>

<usage>
    <p>La directiva <directive>ProxyFtpDirCharset</directive> define el
    juego de caracteres que se establecerá para los listados de directorios FTP en el HTML generado por
    <module>mod_proxy_ftp</module>.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
