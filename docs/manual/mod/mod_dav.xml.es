<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1934445 -->
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

<modulesynopsis metafile="mod_dav.xml.meta">

<name>mod_dav</name>
<description>Funcionalidad de Distributed Authoring and Versioning
(<a href="http://www.webdav.org/">WebDAV</a>)</description>
<status>Extension</status>
<sourcefile>mod_dav.c</sourcefile>
<identifier>dav_module</identifier>

<summary>
    <p>Este módulo proporciona funcionalidad <a
    href="http://www.webdav.org">WebDAV</a> ('Web-based Distributed
    Authoring and Versioning') de clase 1 y clase 2 para Apache. Esta
    extensión del protocolo HTTP permite crear, mover,
    copiar y eliminar recursos y colecciones en un servidor web
    remoto.</p>
</summary>
<seealso><module>mod_dav_fs</module></seealso>
<seealso><directive module="core">LimitXMLRequestBody</directive></seealso>

<section id="example"><title>Activar WebDAV</title>
    <p>Para activar <module>mod_dav</module>, añada lo siguiente a un
    contenedor de su archivo <code>httpd.conf</code>:</p>

    <highlight language="config">
Dav On
    </highlight>

    <p>Esto activa el proveedor del sistema de archivos DAV, que implementa
    el módulo <module>mod_dav_fs</module>. Por lo tanto, ese módulo
    debe estar compilado en el servidor o cargarse en tiempo de ejecución mediante
    la directiva <directive module="mod_so">LoadModule</directive>.</p>

    <p>En el ejemplo siguiente, se usa <directive module="mod_authz_core"
    type="section">RequireAny</directive> para asegurarse de que los
    métodos específicos de DAV (es decir, métodos distintos de <code>GET</code>,
    <code>POST</code> y <code>OPTIONS</code>) se limiten al usuario
    autenticado.</p>

    <p>Si quiere establecer la cantidad máxima de
    bytes que un cliente DAV puede enviar en una petición, tiene que usar
    la directiva <directive module="core">LimitXMLRequestBody</directive>.
    La directiva "normal" <directive module="core"
    >LimitRequestBody</directive> no tiene efecto en las peticiones
    DAV.</p>

    <example><title>Ejemplo completo</title>
    <highlight language="config">
&lt;Directory "/usr/local/apache2/htdocs/foo"&gt;
    Dav On

    AuthType Basic
    AuthName "DAV"
    AuthUserFile "user.passwd"

    &lt;RequireAny&gt;
        Require method GET POST OPTIONS
        Require user admin
    &lt;/RequireAny&gt;
&lt;/Directory&gt;
      </highlight>
    </example>

</section>

<section id="security"><title>Cuestiones de seguridad</title>

    <p>Dado que los métodos de acceso DAV permiten a los clientes remotos manipular
    archivos en el servidor, debe tener especial cuidado en asegurarse de que
    su servidor sea seguro antes de activar <module>mod_dav</module>.</p>

    <p>Cualquier ubicación del servidor en la que esté activado DAV debería estar
    protegida mediante autenticación. No se recomienda el uso de autenticación
    básica HTTP. Debería usar al menos la autenticación Digest HTTP, que
    proporciona el módulo
    <module>mod_auth_digest</module>. Casi todos los clientes WebDAV
    admiten este método de autenticación. Una alternativa es la autenticación
    Basic sobre una conexión con <a href="../ssl/">SSL</a>
    activado.</p>

    <p>Para que <module>mod_dav</module> pueda gestionar archivos, debe
    poder escribir en los directorios y archivos bajo su control
    usando el <directive module="mod_unixd">User</directive> y
    <directive module="mod_unixd">Group</directive> con los que
    se está ejecutando Apache. Los archivos nuevos creados también pertenecerán a este
    <directive module="mod_unixd">User</directive> y <directive
    module="mod_unixd">Group</directive>. Por esta razón, es
    importante controlar el acceso a esta cuenta. El repositorio DAV
    se considera privado de Apache; no se debería permitir modificar archivos
    fuera de Apache (por ejemplo usando FTP o herramientas a nivel de sistema
    de archivos).</p>

    <p><module>mod_dav</module> puede ser objeto de varios tipos de
    ataques de denegación de servicio. La directiva <directive
    module="core">LimitXMLRequestBody</directive> puede
    usarse para limitar la cantidad de memoria consumida al analizar peticiones
    DAV grandes. La directiva <directive
    module="mod_dav">DavDepthInfinity</directive> puede
    usarse para evitar que las peticiones <code>PROPFIND</code> sobre un
    repositorio muy grande consuman grandes cantidades de memoria. Otro
    posible ataque de denegación de servicio consiste en que un cliente simplemente
    llene todo el espacio disponible en disco con muchos archivos grandes. No hay
    una forma directa de evitar esto en Apache, por lo que debería evitar dar
    acceso DAV a usuarios no confiables.</p>
</section>

<section id="complex"><title>Configuraciones complejas</title>

    <p>Una petición común es usar <module>mod_dav</module> para
    manipular archivos dinámicos (scripts PHP, scripts CGI, etc.). Esto es
    difícil porque una petición <code>GET</code> siempre ejecutará el
    script, en lugar de descargar su contenido. Una forma de evitar
    esto es asignar dos URLs diferentes al contenido, una de las cuales
    ejecutará el script, y otra que permitirá descargarlo
    y manipularlo con DAV.</p>

<highlight language="config">
Alias "/phparea" "/home/gstein/php_files"
Alias "/php-source" "/home/gstein/php_files"
&lt;Location "/php-source"&gt;
    Dav On
    ForceType text/plain
&lt;/Location&gt;
</highlight>

    <p>Con esta configuración, <code>http://example.com/phparea</code> puede
    usarse para acceder a la salida de los scripts PHP, y
    <code>http://example.com/php-source</code> puede usarse con un cliente
    DAV para manipularlos.</p>
</section>

<directivesynopsis>
<name>Dav</name>
<description>Activa los métodos HTTP de WebDAV</description>
<syntax>Dav On|Off|<var>provider-name</var></syntax>
<default>Dav Off</default>
<contextlist><context>directory</context></contextlist>

<usage>
    <p>Use la directiva <directive>Dav</directive> para activar los
    métodos HTTP de WebDAV para el contenedor indicado:</p>

    <highlight language="config">
&lt;Location "/foo"&gt;
    Dav On
&lt;/Location&gt;
    </highlight>

    <p>El valor <code>On</code> es en realidad un alias del proveedor
    por defecto <code>filesystem</code>, que es servido por el módulo <module
    >mod_dav_fs</module>. Tenga en cuenta que, una vez que ha activado DAV
    para una ubicación, <em>no se puede</em> desactivar para sububicaciones.
    Para ver un ejemplo de configuración completo, consulte la <a
    href="#example">sección anterior</a>.</p>

    <note type="warning">
      No active WebDAV hasta que haya protegido su servidor. De otro modo
      cualquiera podrá distribuir archivos en su sistema.
    </note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DavBasePath</name>
<description>Configura la ruta raíz del repositorio</description>
<syntax>DavBasePath <var>root-path</var></syntax>
<default>None</default>
<contextlist><context>directory</context></contextlist>
<compatibility>Disponible en la versión 2.4.58 y posteriores</compatibility>

<usage>
  <p>Si un repositorio DAV se configura usando una coincidencia por
  expresión regular (como <directive module="core">LocationMatch</directive>)
  entonces <module>mod_dav</module> no podrá encontrar la raíz del
  repositorio solo a partir del nombre de ruta. Los proveedores de terceros (por
  ejemplo, <a
  href="https://svnbook.red-bean.com/en/1.7/svn.ref.mod_dav_svn.conf.html">mod_dav_svn</a>
  de Subversion) pueden no gestionar correctamente las peticiones sin la raíz de
  repositorio correcta.</p>

  <p>Para que los proveedores funcionen correctamente en tal configuración,
  debe usarse <directive>DavBasePath</directive>.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
&lt;LocationMatch "^/repos/"&gt;
    Dav svn
    DavBasePath /repos
    SVNParentPath /var/svn
&lt;/LocationMatch&gt;
    </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DavMinTimeout</name>
<description>Cantidad mínima de tiempo que el servidor mantiene un bloqueo
sobre un recurso DAV</description>
<syntax>DavMinTimeout <var>seconds</var></syntax>
<default>DavMinTimeout 0</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>

<usage>
    <p>Cuando un cliente solicita un bloqueo sobre un recurso DAV, también puede
    especificar un momento en el que el servidor eliminará automáticamente
    el bloqueo. Este valor es solo una petición, y el servidor puede
    ignorarlo o informar al cliente de un valor arbitrario.</p>

    <p>Use la directiva <directive>DavMinTimeout</directive> para especificar, en
    segundos, el tiempo de espera mínimo de bloqueo que se devolverá a un cliente.
    Microsoft Web Folders usa por defecto un tiempo de espera de 120 segundos; la
    directiva <directive>DavMinTimeout</directive> puede aumentar este valor
    (por ejemplo, a 600 segundos) para reducir la posibilidad de que el cliente pierda
    el bloqueo debido a la latencia de la red.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
&lt;Location "/MSWord"&gt;
    DavMinTimeout 600
&lt;/Location&gt;
    </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DavDepthInfinity</name>
<description>Permite las peticiones PROPFIND con Depth: Infinity</description>
<syntax>DavDepthInfinity on|off</syntax>
<default>DavDepthInfinity off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>

<usage>
    <p>Use la directiva <directive>DavDepthInfinity</directive> para
    permitir el procesamiento de peticiones <code>PROPFIND</code> que contengan la
    cabecera 'Depth: Infinity'. Como este tipo de petición podría constituir
    un ataque de denegación de servicio, no se permite por defecto.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DavMSext</name>
<description>Activa el soporte para extensiones de Microsoft</description>
<syntax>DavMSext None | [+|-]WDV | All</syntax>
<default>DavMSext None</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>

<usage>
    <p>La directiva <directive>DavMSext</directive> activa el soporte
    para extensiones de Microsoft. Los valores posibles son:</p>
        <ul>
            <li><code>None</code> No se activa ninguna extensión de Microsoft.</li>
            <li><code>WDV</code> Activa el soporte para
            <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wdv">MS-WDV</a>.
            </li>
            <li><code>All</code> Se activan todas las extensiones de Microsoft
            implementadas. Actualmente, esto significa <code>WDV</code>, ya
            que es la única extensión de Microsoft implementada.</li>
        </ul>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>DavHonorMtimeHeader</name>
<description>Permite a los clientes establecer la hora de modificación de los recursos
mediante la cabecera de petición X-OC-Mtime</description>
<syntax>DavHonorMtimeHeader on|off</syntax>
<default>DavHonorMtimeHeader off</default>
<contextlist><context>directory</context></contextlist>

<usage>
    <p>La directiva <directive>DavHonorMtimeHeader</directive> controla
    si <module>mod_dav</module> respetará la cabecera de petición
    <code>X-OC-Mtime</code> al procesar peticiones
    <code>PUT</code> y <code>MKCOL</code>. Esta cabecera
    la usan algunos clientes de sincronización WebDAV para conservar el
    tiempo de modificación original de los archivos subidos.</p>

    <p>Cuando está activada, si un cliente envía una petición <code>PUT</code> o
    <code>MKCOL</code> con una cabecera <code>X-OC-Mtime</code>,
    el servidor establecerá el tiempo de modificación del recurso al
    valor especificado en esa cabecera. El valor de la cabecera debe ser una
    marca de tiempo Unix (segundos desde epoch), expresada como un entero
    decimal.</p>

    <p>Si la cabecera está presente pero mal formada (contiene caracteres que
    no son dígitos), el servidor responderá con un error 400 Bad
    Request.</p>

    <note type="warning">
    <p>Activar esta directiva permite a los clientes manipular los tiempos de
    modificación de los archivos en el servidor. Actívela solo en ubicaciones
    donde los clientes sean de confianza, y proteja siempre el acceso con
    autenticación.</p>
    </note>

    <example><title>Ejemplo</title>
    <highlight language="config">
&lt;Directory "/var/www/dav/sync"&gt;
    Dav On
    DavHonorMtimeHeader on
&lt;/Directory&gt;
    </highlight>
    </example>
</usage>
</directivesynopsis>

</modulesynopsis>

