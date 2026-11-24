<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1584572 -->
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

<modulesynopsis metafile="mod_isapi.xml.meta">

<name>mod_isapi</name>
<description>Extensiones ISAPI dentro de Apache para Windows</description>
<status>Base</status>
<sourcefile>mod_isapi.c</sourcefile>
<identifier>isapi_module</identifier>
<compatibility>Solo Win32</compatibility>

<summary>
    <p>Este módulo implementa la API de extensión del Internet Server. Permite
    que las extensiones de Internet Server (<em>p. ej.</em> módulos .dll
    ISAPI) sean servidas por Apache para Windows, con las
    restricciones indicadas.</p>

    <p>Los módulos de extensión ISAPI (archivos .dll) están escritos por
    terceros. El Apache Group no es el autor de estos módulos, por lo que no
    ofrecemos soporte para ellos. Póngase en contacto directamente con el autor
    de la ISAPI si tiene problemas al ejecutar su extensión ISAPI.
    <strong>Por favor, <em>no</em> publique este tipo de problemas en
    las listas de Apache ni en las páginas de reporte de errores.</strong></p>
</summary>

<section id="usage"><title>Uso</title>

    <p>En el archivo de configuración del servidor, use
    la directiva <directive module="mod_mime">AddHandler</directive> para
    asociar los archivos ISAPI con el gestor <code>isapi-handler</code>, y
    asígnelo mediante sus extensiones de archivo. Para permitir que cualquier
    archivo .dll se procese como una extensión ISAPI, edite el archivo httpd.conf
    y añada la siguiente línea:</p>
    <highlight language="config">
        AddHandler isapi-handler .dll
    </highlight>

    <note>En versiones antiguas del servidor Apache,
    <code>isapi-isa</code> era el nombre de gestor correcto, en lugar de
    <code>isapi-handler</code>. A partir de las versiones de desarrollo 2.3 del
    servidor Apache, <code>isapi-isa</code> ya no es válido. Deberá
    cambiar su configuración para usar <code>isapi-handler</code>
    en su lugar.</note>

    <p>El servidor Apache no tiene capacidad para dejar cargado un
    módulo solicitado. Sin embargo, puede precargar y mantener cargado un
    módulo concreto usando la siguiente sintaxis en su
    httpd.conf:</p>
    <highlight language="config">
        ISAPICacheFile c:/WebWork/Scripts/ISAPI/mytest.dll
    </highlight>

    <p>Tanto si ha precargado una extensión ISAPI como si no, todas
    las extensiones ISAPI están sujetas a los mismos permisos y
    restricciones que los scripts CGI. Es decir, debe establecerse
    <directive module="core">Options</directive> <code>ExecCGI</code>
    para el directorio que contiene el archivo .dll de ISAPI.</p>

    <p>Consulte las <a href="#notes">Notas adicionales</a> y el <a
    href="#journal">Diario del programador</a> para obtener más detalles
    y aclaraciones sobre el soporte específico de ISAPI que ofrece
    <module>mod_isapi</module>.</p>
</section>

<section id="notes"><title>Notas adicionales</title>

    <p>La implementación de ISAPI de Apache cumple toda la especificación
    ISAPI 2.0, excepto algunas extensiones "específicas de Microsoft"
    relacionadas con E/S asíncrona. El modelo de E/S de Apache no permite
    la lectura y escritura asíncrona de una forma a la que ISAPI pudiera
    acceder. Si una ISA intenta acceder a funciones no admitidas,
    incluyendo E/S asíncrona, se registra un mensaje en el log de errores
    para ayudar a la depuración. Como estos mensajes pueden convertirse en
    una avalancha, existe la directiva <code>ISAPILogNotSupported
    Off</code> para silenciar este ruido.</p>

    <p>Algunos servidores, como Microsoft IIS, cargan la extensión ISAPI
    en el servidor y la mantienen cargada hasta que el uso de memoria es
    demasiado alto, o a menos que se especifiquen opciones de configuración.
    Actualmente, Apache carga y descarga la extensión ISAPI cada vez que se
    solicita, a menos que se especifique la directiva <directive module="mod_isapi"
    >ISAPICacheFile</directive>.
    Esto es ineficiente, pero el modelo de memoria de Apache hace que este sea
    el método más eficaz. Muchos módulos ISAPI son sutilmente
    incompatibles con el servidor Apache, y descargar estos
    módulos ayuda a garantizar la estabilidad del servidor.</p>

    <p>Además, recuerde que, aunque Apache admite extensiones ISAPI,
    <strong>no admite filtros ISAPI</strong>. El soporte para
    filtros podría añadirse en el futuro, pero por el momento no
    está previsto.</p>
</section>

<section id="journal"><title>Diario del programador</title>

    <p>Si está programando módulos <module>mod_isapi</module> para Apache 2.0,
    debe limitar sus llamadas a <code>ServerSupportFunction</code>
    a las siguientes directivas:</p>

    <dl>
      <dt><code>HSE_REQ_SEND_URL_REDIRECT_RESP</code></dt>
      <dd>Redirige al usuario a otra ubicación.<br />
      Debe ser una URL completamente cualificada (<em>p. ej.</em>
      <code>http://server/location</code>).</dd>

      <dt><code>HSE_REQ_SEND_URL</code></dt>
      <dd>Redirige al usuario a otra ubicación.<br />
      No puede ser una URL completamente cualificada; no se permite
      pasar el protocolo o un nombre de servidor (<em>p. ej.</em> simplemente
      <code>/location</code>).<br />
      Esta redirección la gestiona el servidor, no el
      navegador.<br />
      <note type="warning"><title>Advertencia</title>
        <p>En su documentación reciente, Microsoft parece haber
        abandonado la distinción entre las dos
        funciones <code>HSE_REQ_SEND_URL</code>. Apache sigue tratándolas
        como dos funciones distintas con requisitos y comportamientos
        diferentes.</p>
      </note></dd>

      <dt><code>HSE_REQ_SEND_RESPONSE_HEADER</code></dt>
      <dd>Apache acepta un cuerpo de respuesta a continuación de la cabecera
      si sigue a la línea en blanco (dos saltos de línea consecutivos) en el
      argumento de la cadena de cabeceras. Este cuerpo no puede contener NULLs,
      ya que el argumento de cabeceras termina en NULL.</dd>

      <dt><code>HSE_REQ_DONE_WITH_SESSION</code></dt>
      <dd>Apache considera esto una operación nula, ya que la sesión
      finalizará cuando la ISAPI termine de procesar.</dd>

      <dt><code>HSE_REQ_MAP_URL_TO_PATH</code></dt>
      <dd>Apache traducirá un nombre virtual a un nombre
      físico.</dd>

      <dt><code>HSE_APPEND_LOG_PARAMETER</code></dt>
      <dd>
        Este mensaje registrado puede capturarse en cualquiera de los
        siguientes logs:

        <ul>
          <li>en el componente <code>\"%{isapi-parameter}n\"</code> de una
          directiva <directive module="mod_log_config">CustomLog</directive></li>

          <li>en el componente de log <code>%q</code> con la directiva
          <directive module="mod_isapi">ISAPIAppendLogToQuery</directive>
          en <code>On</code></li>

          <li>en el log de errores con la directiva <directive module="mod_isapi"
          >ISAPIAppendLogToErrors</directive> en <code>On</code></li>
        </ul>

        <p>La primera opción, el componente <code>%{isapi-parameter}n</code>,
        siempre está disponible y es la preferida.</p>
      </dd>

      <dt><code>HSE_REQ_IS_KEEP_CONN</code></dt>
      <dd>Devolverá el estado negociado de Keep-Alive.</dd>

      <dt><code>HSE_REQ_SEND_RESPONSE_HEADER_EX</code></dt>
      <dd>Se comportará como está documentado, aunque se ignora el indicador
      <code>fKeepConn</code>.</dd>

      <dt><code>HSE_REQ_IS_CONNECTED</code></dt>
      <dd>Informará de falso si la petición se ha abortado.</dd>
    </dl>

    <p>Apache devuelve <code>FALSE</code> para cualquier llamada no admitida a
    <code>ServerSupportFunction</code>, y establece el valor de
    <code>GetLastError</code> en
    <code>ERROR_INVALID_PARAMETER</code>.</p>

    <p><code>ReadClient</code> recupera el cuerpo de la petición que exceda el
    búfer inicial (definido por <directive module="mod_isapi"
    >ISAPIReadAheadBuffer</directive>). En función del valor de
    <directive>ISAPIReadAheadBuffer</directive> (número de bytes a almacenar
    en búfer antes de invocar al gestor ISAPI), las peticiones más cortas se
    envían completas a la extensión cuando se invoca. Si la petición es
    más larga, la extensión ISAPI debe usar <code>ReadClient</code> para
    recuperar el resto del cuerpo de la petición.</p>

    <p><code>WriteClient</code> está admitido, pero solo con el
    indicador <code>HSE_IO_SYNC</code> o sin ningún indicador de opción (valor
    <code>0</code>). Cualquier otra petición de <code>WriteClient</code>
    se rechazará con un valor de retorno de <code>FALSE</code>, y un
    valor de <code>GetLastError</code> de
    <code>ERROR_INVALID_PARAMETER</code>.</p>

    <p><code>GetServerVariable</code> está admitido, aunque las variables de
    servidor extendidas no existen (tal como las definen otros servidores).
    Todas las variables de entorno CGI habituales de Apache están disponibles a
    través de <code>GetServerVariable</code>, así como los valores <code>ALL_HTTP</code>
    y <code>ALL_RAW</code>.</p>

    <p>Desde httpd 2.0, <module>mod_isapi</module> admite funciones adicionales
    introducidas en versiones posteriores de la especificación ISAPI,
    así como una emulación limitada de E/S asíncrona y de la semántica de
    <code>TransmitFile</code>. Apache httpd también admite la precarga de
    .dlls de ISAPI para mejorar el rendimiento.</p>
</section>

<directivesynopsis>
<name>ISAPICacheFile</name>
<description>Archivos .dll de ISAPI que se cargarán al arrancar</description>
<syntax>ISAPICacheFile <var>file-path</var> [<var>file-path</var>]
...</syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Especifica una lista, separada por espacios, de nombres de archivo que
    se cargarán cuando se arranque el servidor Apache, y permanecerán cargados
    hasta que el servidor se detenga. Esta directiva puede repetirse para cada
    archivo .dll de ISAPI que se desee. Debe especificarse el nombre de ruta
    completo de cada archivo. Si el nombre de ruta no es absoluto, se tratará
    como relativo a <directive module="core">ServerRoot</directive>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ISAPIReadAheadBuffer</name>
<description>Tamaño del búfer de lectura anticipada enviado a las extensiones
ISAPI</description>
<syntax>ISAPIReadAheadBuffer <var>size</var></syntax>
<default>ISAPIReadAheadBuffer 49152</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>Define el tamaño máximo del búfer de lectura anticipada enviado a
    las extensiones ISAPI cuando se invocan inicialmente. Todos los datos
    restantes deben recuperarse usando la llamada de retorno <code>ReadClient</code>;
    algunas extensiones ISAPI puede que no admitan la función <code>ReadClient</code>.
    Consulte sus dudas al autor de la extensión ISAPI.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ISAPILogNotSupported</name>
<description>Registra las peticiones de funciones no admitidas por parte de
las extensiones ISAPI</description>
<syntax>ISAPILogNotSupported on|off</syntax>
<default>ISAPILogNotSupported off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>Registra en el log de errores del servidor todas las peticiones de
    funciones no admitidas realizadas por extensiones ISAPI. Esto puede ayudar
    a los administradores a localizar problemas. Una vez activado y
    comprobado que todos los módulos ISAPI deseados funcionan correctamente,
    debería volver a desactivarse.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ISAPIAppendLogToErrors</name>
<description>Registra en el log de errores las peticiones <code>HSE_APPEND_LOG_PARAMETER</code>
de las extensiones ISAPI</description>
<syntax>ISAPIAppendLogToErrors on|off</syntax>
<default>ISAPIAppendLogToErrors off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>Registra en el log de errores del servidor las peticiones
    <code>HSE_APPEND_LOG_PARAMETER</code> de las extensiones ISAPI.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ISAPIAppendLogToQuery</name>
<description>Registra en el campo de consulta las peticiones <code>HSE_APPEND_LOG_PARAMETER</code>
de las extensiones ISAPI</description>
<syntax>ISAPIAppendLogToQuery on|off</syntax>
<default>ISAPIAppendLogToQuery on</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>Registra las peticiones <code>HSE_APPEND_LOG_PARAMETER</code> de las
    extensiones ISAPI en el campo de consulta (añadido al componente
    <code>%q</code> de <directive
    module="mod_log_config">CustomLog</directive>).</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>ISAPIFakeAsync</name>
<description>Simula soporte asíncrono para las llamadas de retorno de ISAPI</description>
<syntax>ISAPIFakeAsync on|off</syntax>
<default>ISAPIFakeAsync off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>FileInfo</override>

<usage>
    <p>Mientras esté activado, se simula el soporte asíncrono para las
    llamadas de retorno de ISAPI.</p>
</usage>
</directivesynopsis>

</modulesynopsis>

