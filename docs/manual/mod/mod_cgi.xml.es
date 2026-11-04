<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1938712 -->
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

<modulesynopsis metafile="mod_cgi.xml.meta">

<name>mod_cgi</name>
<description>Ejecución de scripts CGI</description>
<status>Base</status>
<sourcefile>mod_cgi.c</sourcefile>
<identifier>cgi_module</identifier>

<summary>
    <p>Cualquier archivo que tenga el manejador
    <code>cgi-script</code> se tratará
    como un script CGI, y será ejecutado por el servidor, devolviéndose
    su salida al cliente. Los archivos adquieren este manejador bien
    teniendo un nombre que contenga una extensión definida por la
    directiva <directive module="mod_mime">AddHandler</directive>, o bien estando
    en un directorio <directive module="mod_alias">ScriptAlias</directive>.</p>

    <p>Para una introducción al uso de scripts CGI con Apache, consulte
    nuestro tutorial sobre <a href="../howto/cgi.html">Contenido dinámico
    con CGI</a>.</p>

    <p>Cuando se use un MPM multihilo en UNIX, debería usarse el módulo
    <module>mod_cgid</module> en lugar de
    este módulo. A nivel de usuario, ambos módulos son esencialmente
    idénticos.</p>

    <p>Por compatibilidad con versiones anteriores, el manejador cgi-script también se
    activará para cualquier archivo con el tipo MIME <code>application/x-httpd-cgi</code>. El
    uso de este tipo MIME mágico está obsoleto.</p>
</summary>

<seealso><directive module="core">AcceptPathInfo</directive></seealso>
<seealso><directive module="core">Options</directive> ExecCGI</seealso>
<seealso><directive module="mod_alias">ScriptAlias</directive></seealso>
<seealso><directive module="mod_mime">AddHandler</directive></seealso>
<seealso><a href="../suexec.html">Ejecutar programas CGI con diferentes
    IDs de usuario</a></seealso>
<seealso>Especificación CGI (<rfc>3875</rfc>)</seealso>

<section id="env"><title>Variables de entorno CGI</title>
    <p>El servidor establecerá las variables de entorno CGI tal como se
    describe en la especificación CGI (<rfc>3875</rfc>),
    con las siguientes particularidades:</p>

    <dl>
      <dt><glossary ref="pathinfo">PATH_INFO</glossary></dt>

      <dd>Esta no estará disponible si la directiva <directive module="core"
      >AcceptPathInfo</directive> se establece explícitamente a
      <code>off</code>. El comportamiento por defecto, si no se indica
      <directive>AcceptPathInfo</directive>, es que <module
      >mod_cgi</module> aceptará información de ruta (un <code>
      /more/path/info</code> final tras el nombre del script en la URI),
      mientras que el servidor core devolverá un error 404 NOT FOUND para peticiones
      con información de ruta adicional. Omitir la directiva
      <directive>AcceptPathInfo</directive> tiene el mismo efecto que
      establecerla a <code>On</code> para las peticiones de <module>mod_cgi</module>.</dd>

      <dt>REMOTE_HOST</dt>

      <dd>Esta solo se establecerá si <directive module="core"
      >HostnameLookups</directive> está establecida a <code>on</code> (está
      desactivada por defecto), y si una búsqueda inversa de DNS de la dirección
      del host que accede encuentra realmente un nombre de host.</dd>

      <dt>REMOTE_IDENT</dt>

      <dd>Esta solo se establecerá si <directive module="mod_ident"
      >IdentityCheck</directive> está establecida a
      <code>on</code> y el host que accede admite el protocolo ident.
      Tenga en cuenta que no se puede confiar en el contenido de esta
      variable porque se puede falsear fácilmente, y si hay un
      proxy entre el cliente y el servidor, suele ser
      totalmente inútil.</dd>

      <dt>REMOTE_USER</dt>

      <dd>Esta solo se establecerá si el script CGI está sujeto a
      autenticación.</dd>

    </dl>
    <p>Este módulo también aprovecha las funciones del core
       <a href="https://ci.apache.org/projects/httpd/trunk/doxygen/group__APACHE__CORE__SCRIPT.html#ga0e81f9571a8a73f5da0e89e1f46d34b1">ap_add_common_vars</a> y
       <a href="https://ci.apache.org/projects/httpd/trunk/doxygen/group__APACHE__CORE__SCRIPT.html#ga6b975cd7ff27a338cb8752381a4cc14f">ap_add_cgi_vars</a>
       para añadir variables de entorno como:</p>
       <dl>
           <dt>DOCUMENT_ROOT</dt>

           <dd>Se establece con el contenido de la directiva <directive module="core">DocumentRoot</directive> relacionada.</dd>

           <dt>SERVER_NAME</dt>

           <dd>El nombre de dominio completamente cualificado relacionado con la petición.</dd>

           <dt>SERVER_ADDR</dt>

           <dd>La dirección IP del Virtual Host que atiende la petición.</dd>

           <dt>SERVER_ADMIN</dt>

           <dd>Se establece con el contenido de la directiva <directive module="core">ServerAdmin</directive> relacionada.</dd>
      </dl>
    <p>Para obtener una lista exhaustiva, se sugiere escribir un script CGI básico
       que vuelque todas las variables de entorno que pasa Apache en un formato cómodo.
    </p>
</section>

<section id="cgi-debug"><title>Depuración de CGI</title>
    <p>Depurar scripts CGI ha sido tradicionalmente difícil, principalmente
    porque no ha sido posible estudiar la salida (estándar
    y de error) de los scripts que no se ejecutan
    correctamente. Estas directivas proporcionan un registro más detallado de los errores
    cuando ocurren.</p>

    <section><title>Formato del archivo de registro de CGI</title>
      <p>Una vez configurado, el log de errores de CGI registra cualquier CGI que no
      se ejecute correctamente. Cada script CGI que falla al ejecutarse hace
      que se registren varias líneas de información. Las dos primeras líneas
      siempre tienen el formato:</p>

      <example>
        %% [<var>time</var>] <var>request-line</var><br />
        %% <var>HTTP-status</var> <var>CGI-script-filename</var>
      </example>

      <p>Si el error es que el script CGI no se puede ejecutar, el archivo de
      registro contendrá dos líneas adicionales:</p>

      <example>
        %%error<br />
        <var>error-message</var>
      </example>

      <p>Alternativamente, si el error es el resultado de que el script
      devuelva información de cabecera incorrecta (a menudo debido a un fallo
      en el script), se registra la siguiente información:</p>

      <example>
        %request<br />
        <var>All HTTP request headers received</var><br />
        <var>POST or PUT entity (if any)</var><br />
        %response<br />
        <var>All headers output by the CGI script</var><br />
        %stdout<br />
        <var>CGI standard output</var><br />
        %stderr<br />
        <var>CGI standard error</var><br />
      </example>

      <p>(Las partes %stdout y %stderr pueden faltar si el script no
      produjo nada en la salida estándar o en la salida de error).</p>
    </section>
</section>

<directivesynopsis>
<name>CGIScriptTimeout</name>
<description>El tiempo de espera para más salida del
programa CGI</description>
<syntax>CGIScriptTimeout <var>time</var>[s|ms]</syntax>
<default>valor de la directiva <directive module="core">Timeout</directive> cuando
no se establece</default>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<compatibility>Disponible en la versión 2.5.1 y posteriores.</compatibility>

<usage>
    <p>Esta directiva limita el tiempo de espera para más salida de
    el programa CGI. Si se supera el tiempo, la petición y el CGI se
    terminan.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      CGIScriptTimeout 20
    </highlight>
    </example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>ScriptLog</name>
<description>Ubicación del archivo de registro de errores de script CGI</description>
<syntax>ScriptLog <var>file-path</var></syntax>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<modulelist><module>mod_cgi</module><module>mod_cgid</module>
</modulelist>

<usage>
    <p>La directiva <directive>ScriptLog</directive> establece el archivo
    de registro de errores de scripts CGI. Si no se indica <directive>ScriptLog</directive>,
    no se crea ningún log de errores. Si se indica, cualquier error de CGI se registra en el
    nombre de archivo indicado como argumento. Si es una ruta o archivo relativo, se
    toma en relación con <directive module="core">ServerRoot</directive>.
    </p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      ScriptLog logs/cgi_log
    </highlight>
    </example>

    <p>Este log se abrirá como el usuario con el que se ejecutan los procesos
    hijos, <em>es decir</em>, el usuario especificado en la directiva principal
    <directive module="mod_unixd">User</directive>. Esto significa que
    el directorio donde está el log del script debe tener permiso de escritura
    para ese usuario, o bien el archivo debe crearse manualmente y
    configurarse con permiso de escritura para ese usuario. Si coloca el log
    del script en su directorio de logs principal, NO <strong>cambie</strong> los
    permisos del directorio para que tenga permiso de escritura por parte del usuario
    con el que se ejecutan los procesos hijos.</p>

    <p>Tenga en cuenta que el registro de scripts está pensado como una función
    de depuración al escribir scripts CGI, y no está pensado para activarse
    de forma continua en servidores en producción. No está optimizado para la velocidad
    ni la eficiencia, y puede tener problemas de seguridad si se usa de una
    manera distinta a aquella para la que fue diseñado.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ScriptLogLength</name>
<description>Límite de tamaño del archivo de registro de scripts CGI</description>
<syntax>ScriptLogLength <var>bytes</var></syntax>
<default>ScriptLogLength 10385760</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<modulelist><module>mod_cgi</module><module>mod_cgid</module>
</modulelist>

<usage>
    <p><directive>ScriptLogLength</directive> se puede usar para limitar el
    tamaño del archivo de registro de scripts CGI. Dado que el archivo de registro
    guarda mucha información por cada error de CGI (todas las cabeceras de la petición,
    toda la salida del script), puede acabar siendo un archivo muy grande. Para evitar
    problemas por un crecimiento sin límite, esta directiva se puede usar para establecer
    un tamaño máximo de archivo para el log de CGI. Si el archivo supera ese tamaño, no se
    escribirá más información en él.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ScriptLogBuffer</name>
<description>Cantidad máxima de peticiones PUT o POST que se registrarán
en el log del script</description>
<syntax>ScriptLogBuffer <var>bytes</var></syntax>
<default>ScriptLogBuffer 1024</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>
<modulelist><module>mod_cgi</module><module>mod_cgid</module>
</modulelist>

<usage>
    <p>El tamaño de cualquier cuerpo de entidad PUT o POST que se registra en
    el archivo está limitado, para evitar que el archivo de log crezca demasiado
    deprisa si se reciben cuerpos grandes. Por defecto, se registran hasta
    1024 bytes, pero esto se puede cambiar con esta
    directiva.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
