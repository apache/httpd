<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1793934 -->
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

<modulesynopsis metafile="mod_session_dbd.xml.meta">

<name>mod_session_dbd</name>
<description>Soporte de sesiones basado en DBD/SQL</description>
<status>Extension</status>
<sourcefile>mod_session_dbd.c</sourcefile>
<identifier>session_dbd_module</identifier>
<compatibility>Disponible en Apache 2.3 y posteriores</compatibility>

<summary>
    <note type="warning"><title>Advertencia</title>
      <p>Los módulos de sesión hacen uso de cookies HTTP y, por tanto, pueden ser
      víctimas de ataques de Cross Site Scripting, o exponer información
      potencialmente privada a los clientes. Asegúrese de haber tenido en cuenta
      los riesgos pertinentes antes de activar la funcionalidad de sesiones en
      su servidor.</p>
    </note>

    <p>Este submódulo de <module>mod_session</module> proporciona soporte para el
    almacenamiento de sesiones de usuario en una base de datos SQL usando el
    módulo <module>mod_dbd</module>.</p>

    <p>Las sesiones pueden ser <strong>anónimas</strong>, donde la sesión se
    identifica mediante una cadena UUID única almacenada en el navegador en una
    cookie, o <strong>por usuario</strong>, donde la sesión se identifica con
    el id de usuario del usuario que ha iniciado sesión.</p>

    <p>Las sesiones basadas en SQL permanecen ocultas al navegador, por lo que
    ofrecen cierto nivel de privacidad sin necesidad de cifrado.</p>

    <p>Distintos servidores web dentro de una granja de servidores pueden optar
    por compartir una base de datos, y así compartir sesiones entre ellos.</p>

    <p>Para más detalles sobre la interfaz de sesión, consulte la documentación
    del módulo <module>mod_session</module>.</p>

</summary>
<seealso><module>mod_session</module></seealso>
<seealso><module>mod_session_crypto</module></seealso>
<seealso><module>mod_session_cookie</module></seealso>
<seealso><module>mod_dbd</module></seealso>

    <section id="dbdconfig"><title>Configuración de DBD</title>

      <p>Antes de poder configurar el módulo <module>mod_session_dbd</module>
      para mantener una sesión, el módulo <module>mod_dbd</module> debe estar
      configurado para poner a disposición del servidor las distintas consultas
      a la base de datos.</p>

      <p>Se requieren cuatro consultas para mantener una sesión: una para
      seleccionar una sesión existente, otra para actualizar una sesión
      existente, otra para insertar una nueva sesión y otra para eliminar una
      sesión caducada o vacía. Estas consultas se configuran según el ejemplo
      siguiente.</p>

      <example><title>Ejemplo de configuración de DBD</title>
      <highlight language="config">
DBDriver pgsql
DBDParams "dbname=apachesession user=apache password=xxxxx host=localhost"
DBDPrepareSQL "delete from session where key = %s" deletesession
DBDPrepareSQL "update session set value = %s, expiry = %lld, key = %s where key = %s" updatesession
DBDPrepareSQL "insert into session (value, expiry, key) values (%s, %lld, %s)" insertsession
DBDPrepareSQL "select value from session where key = %s and (expiry = 0 or expiry &gt; %lld)" selectsession
DBDPrepareSQL "delete from session where expiry != 0 and expiry &lt; %lld" cleansession
    </highlight>
      </example>

    </section>

    <section id="anonymous"><title>Sesiones anónimas</title>

      <p>Las sesiones anónimas se identifican mediante un UUID único, y se
      almacenan en el navegador dentro de una cookie HTTP. Este método es
      similar al que usan la mayoría de los servidores de aplicaciones para
      almacenar información de sesión.</p>

      <p>Para crear una sesión anónima sencilla y almacenarla en una tabla de
      una base de datos postgres llamada <var>apachesession</var>, guardando el
      ID de sesión en una cookie llamada <var>session</var>, configure la
      sesión de la siguiente manera:</p>

      <example><title>Sesión anónima basada en SQL</title>
      <highlight language="config">
Session On
SessionDBDCookieName session path=/
        </highlight>
      </example>

      <p>Para más ejemplos sobre cómo puede configurarse la sesión para que una
      aplicación CGI la lea y escriba en ella, consulte la sección de ejemplos
      de <module>mod_session</module>.</p>

      <p>Para documentación sobre cómo puede usarse la sesión para almacenar
      datos de nombre de usuario y contraseña, consulte el módulo
      <module>mod_auth_form</module>.</p>

    </section>

    <section id="peruser"><title>Sesiones por usuario</title>

      <p>Las sesiones por usuario se identifican con el nombre de usuario de un
      usuario autenticado correctamente. Ofrecen la mayor privacidad, ya que no
      existe ningún identificador externo de la sesión fuera del dominio
      autenticado.</p>

      <p>Las sesiones por usuario funcionan dentro de un entorno autenticado
      correctamente configurado, ya sea usando autenticación básica,
      autenticación digest o certificados de cliente SSL. Debido a las
      limitaciones de qué fue primero, el huevo o la gallina, las sesiones por
      usuario no pueden usarse para almacenar credenciales de autenticación
      procedentes de un módulo como <module>mod_auth_form</module>.</p>

      <p>Para crear una sesión por usuario sencilla y almacenarla en una tabla
      de una base de datos postgres llamada <var>apachesession</var>, con la
      sesión identificada por el id de usuario, configure la sesión de la
      siguiente manera:</p>

      <example><title>Sesión por usuario basada en SQL</title>
      <highlight language="config">
Session On
SessionDBDPerUser On
        </highlight>
      </example>

    </section>

    <section id="housekeeping"><title>Mantenimiento de la base de datos</title>
      <p>Con el paso del tiempo, cabe esperar que la base de datos comience a
      acumular sesiones caducadas. Por el momento, el módulo
      <module>mod_session_dbd</module> todavía no es capaz de gestionar la
      caducidad de sesiones de forma automática.</p>

      <note type="warning"><title>Advertencia</title>
      <p>El administrador deberá configurar un proceso externo mediante cron
      para eliminar las sesiones caducadas.</p>
      </note>

    </section>

<directivesynopsis>
<name>SessionDBDCookieName</name>
<description>Nombre y atributos de la cookie RFC2109 que almacena el ID de sesión</description>
<syntax>SessionDBDCookieName <var>name</var> <var>attributes</var></syntax>
<default>none</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>SessionDBDCookieName</directive> especifica el
    nombre y los atributos opcionales de una cookie conforme a RFC2109 en la que
    se almacenará el ID de sesión. Las cookies RFC2109 se establecen mediante la
    cabecera HTTP <code>Set-Cookie</code>.
    </p>

    <p>Se puede especificar una lista opcional de atributos de la cookie, según
    el ejemplo siguiente. Estos atributos se insertan en la cookie tal cual, y
    no son interpretados por Apache. Asegúrese de que sus atributos estén
    definidos correctamente según la especificación de cookies.
    </p>

    <example><title>Cookie con atributos</title>
    <highlight language="config">
Session On
SessionDBDCookieName session path=/private;domain=example.com;httponly;secure;version=1;
      </highlight>
    </example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SessionDBDCookieName2</name>
<description>Nombre y atributos de la cookie RFC2965 que almacena el ID de sesión</description>
<syntax>SessionDBDCookieName2 <var>name</var> <var>attributes</var></syntax>
<default>none</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>SessionDBDCookieName2</directive> especifica el
    nombre y los atributos opcionales de una cookie conforme a RFC2965 en la que
    se almacenará el ID de sesión. Las cookies RFC2965 se establecen mediante la
    cabecera HTTP <code>Set-Cookie2</code>.
    </p>

    <p>Se puede especificar una lista opcional de atributos de la cookie, según
    el ejemplo siguiente. Estos atributos se insertan en la cookie tal cual, y
    no son interpretados por Apache. Asegúrese de que sus atributos estén
    definidos correctamente según la especificación de cookies.
    </p>

    <example><title>Cookie2 con atributos</title>
    <highlight language="config">
Session On
SessionDBDCookieName2 session path=/private;domain=example.com;httponly;secure;version=1;
      </highlight>
    </example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SessionDBDCookieRemove</name>
<description>Control de si las cookies con el ID de sesión deben eliminarse de las cabeceras HTTP entrantes</description>
<syntax>SessionDBDCookieRemove On|Off</syntax>
<default>SessionDBDCookieRemove On</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>El indicador <directive>SessionDBDCookieRemove</directive> controla si
    las cookies que contienen el ID de sesión se eliminarán de las cabeceras
    durante el procesamiento de la petición.</p>

    <p>En una situación de proxy inverso en la que el servidor Apache actúa
    como frontend para un servidor de origen en el backend, revelar el
    contenido de la cookie del ID de sesión al backend podría suponer una
    posible violación de la privacidad. Cuando se establece a on, la cookie
    del ID de sesión se eliminará de las cabeceras HTTP entrantes.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SessionDBDPerUser</name>
<description>Activa una sesión por usuario</description>
<syntax>SessionDBDPerUser On|Off</syntax>
<default>SessionDBDPerUser Off</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>El indicador <directive>SessionDBDPerUser</directive> activa una sesión
    por usuario identificada con el nombre de inicio de sesión del usuario. Si
    el usuario no ha iniciado sesión, esta directiva será ignorada.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SessionDBDSelectLabel</name>
<description>La consulta SQL a usar para seleccionar sesiones de la base de datos</description>
<syntax>SessionDBDSelectLabel <var>label</var></syntax>
<default>SessionDBDSelectLabel selectsession</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>SessionDBDSelectLabel</directive> establece la
    etiqueta de consulta de selección por defecto que se usará para cargar una
    sesión. Esta etiqueta debe haberse definido previamente mediante la
    directiva <directive module="mod_dbd">DBDPrepareSQL</directive>.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SessionDBDInsertLabel</name>
<description>La consulta SQL a usar para insertar sesiones en la base de datos</description>
<syntax>SessionDBDInsertLabel <var>label</var></syntax>
<default>SessionDBDInsertLabel insertsession</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>SessionDBDInsertLabel</directive> establece la
    etiqueta de consulta de inserción por defecto que se usará para cargar una
    sesión. Esta etiqueta debe haberse definido previamente mediante la
    directiva <directive module="mod_dbd">DBDPrepareSQL</directive>.</p>

    <p>Si un intento de actualizar la sesión no afecta a ninguna fila, se
    invocará esta consulta para insertar la sesión en la base de datos.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SessionDBDUpdateLabel</name>
<description>La consulta SQL a usar para actualizar sesiones existentes en la base de datos</description>
<syntax>SessionDBDUpdateLabel <var>label</var></syntax>
<default>SessionDBDUpdateLabel updatesession</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>SessionDBDUpdateLabel</directive> establece la
    etiqueta de consulta de actualización por defecto que se usará para cargar
    una sesión. Esta etiqueta debe haberse definido previamente mediante la
    directiva <directive module="mod_dbd">DBDPrepareSQL</directive>.</p>

    <p>Si un intento de actualizar la sesión no afecta a ninguna fila, se
    invocará la consulta de inserción para insertar la sesión en la base de
    datos. Si la base de datos admite InsertOrUpdate, sobrescriba esta consulta
    para realizar la actualización en una sola consulta en lugar de dos.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SessionDBDDeleteLabel</name>
<description>La consulta SQL a usar para eliminar sesiones de la base de datos</description>
<syntax>SessionDBDDeleteLabel <var>label</var></syntax>
<default>SessionDBDDeleteLabel deletesession</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>SessionDBDDeleteLabel</directive> establece la
    etiqueta de consulta de eliminación por defecto que se usará para eliminar
    una sesión caducada o vacía. Esta etiqueta debe haberse definido previamente
    mediante la directiva <directive module="mod_dbd">DBDPrepareSQL</directive>.</p>

</usage>
</directivesynopsis>

</modulesynopsis>
