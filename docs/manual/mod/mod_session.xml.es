<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933180 -->
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

<modulesynopsis metafile="mod_session.xml.meta">

<name>mod_session</name>
<description>Soporte de sesiones</description>
<status>Extension</status>
<sourcefile>mod_session.c</sourcefile>
<identifier>session_module</identifier>
<compatibility>Disponible en Apache 2.3 y posteriores</compatibility>

<summary>
    <note type="warning"><title>Advertencia</title>
      <p>Los módulos de sesión hacen uso de cookies HTTP, y como tales pueden ser
      víctimas de ataques de tipo Cross Site Scripting, o exponer información
      potencialmente privada a los clientes. Asegúrese de haber tenido en cuenta
      los riesgos pertinentes antes de activar la funcionalidad de sesión en
      su servidor.</p>
    </note>

    <p>Este módulo proporciona soporte para una interfaz de sesión por usuario
    a nivel de todo el servidor. Las sesiones pueden usarse para llevar el
    control de si un usuario ha iniciado sesión, o para otra información por
    usuario que deba mantenerse disponible entre peticiones.</p>

    <p>Las sesiones pueden almacenarse en el servidor, o pueden almacenarse en
    el navegador. Las sesiones también pueden cifrarse opcionalmente para mayor
    seguridad. Estas características se dividen en varios módulos además de
    <module>mod_session</module>; <module>mod_session_crypto</module>,
    <module>mod_session_cookie</module> y <module>mod_session_dbd</module>.
    Según los requisitos del servidor, cargue los módulos apropiados
    en el servidor (ya sea de forma estática en tiempo de compilación o
    dinámicamente mediante la directiva <directive module="mod_so"
    >LoadModule</directive>).</p>

    <p>Las sesiones pueden manipularse desde otros módulos que dependan de la
    sesión, o la sesión puede leerse y escribirse usando variables de entorno
    y cabeceras HTTP, según corresponda.</p>

</summary>
<seealso><module>mod_session_cookie</module></seealso>
<seealso><module>mod_session_crypto</module></seealso>
<seealso><module>mod_session_dbd</module></seealso>

    <section id="whatisasession"><title>¿Qué es una sesión?</title>
      <p>En el núcleo de la interfaz de sesión hay una tabla de pares clave-valor
      que son accesibles entre peticiones del navegador. Estos pares pueden
      establecerse con cualquier cadena válida, según lo necesite la aplicación
      que use la sesión.</p>

      <p>La "sesión" es una cadena <strong>application/x-www-form-urlencoded</strong>
      que contiene estos pares clave-valor, tal como se define en la
      <a href="http://www.w3.org/TR/html4/">especificación HTML</a>.</p>

      <p>La sesión puede opcionalmente cifrarse y codificarse en base64 antes de
      escribirse en el mecanismo de almacenamiento, según lo defina el
      administrador.</p>

    </section>
    <section id="whocanuseasession"><title>¿Quién puede usar una sesión?</title>
      <p>La interfaz de sesión se desarrolla principalmente para su uso por
      otros módulos del servidor, como <module>mod_auth_form</module>, aunque
      a las aplicaciones basadas en CGI se les puede conceder opcionalmente
      acceso al contenido de la sesión a través de la variable de entorno
      HTTP_SESSION. Las sesiones tienen la opción de modificarse y/o
      actualizarse insertando una cabecera de respuesta HTTP que contenga los
      nuevos parámetros de la sesión.</p>

    </section>
    <section id="serversession"><title>Mantener las sesiones en el servidor</title>
      <p>Apache puede configurarse para llevar el control de sesiones por
      usuario almacenadas en un servidor concreto o grupo de servidores. Esta
      funcionalidad es similar a las sesiones disponibles en los servidores de
      aplicaciones habituales.</p>

      <p>Si se configura así, las sesiones se rastrean mediante el uso de un ID
      de sesión que se almacena dentro de una cookie, o que se extrae de los
      parámetros incluidos en la cadena de consulta de la URL, como se
      encuentra en una petición GET típica.</p>

      <p>Dado que el contenido de la sesión se almacena exclusivamente en el
      servidor, existe una expectativa de privacidad sobre el contenido de la
      sesión. Esto tiene implicaciones de rendimiento y recursos si hay un
      gran número de sesiones presentes, o cuando un gran número de
      servidores web deben compartir sesiones entre sí.</p>

      <p>El módulo <module>mod_session_dbd</module> permite almacenar las
      sesiones de usuario en una base de datos SQL a través de
      <module>mod_dbd</module>.</p>

    </section> <!-- /serversession -->

    <section id="browsersession"><title>Mantener las sesiones en el navegador</title>
      <p>En entornos de tráfico alto donde mantener el control de una sesión en
      el servidor resulta demasiado costoso en recursos o incómodo, existe la
      opción de almacenar el contenido de la sesión en una cookie en el
      navegador del cliente.</p>

      <p>Esto tiene la ventaja de que se requieren recursos mínimos en el
      servidor para llevar el control de las sesiones, y de que varios
      servidores dentro de una granja de servidores no necesitan compartir
      información de sesión.</p>

      <p>El contenido de la sesión, sin embargo, queda expuesto al cliente, con
      el consiguiente riesgo de pérdida de privacidad. El módulo
      <module>mod_session_crypto</module> puede configurarse para cifrar el
      contenido de la sesión antes de escribirla en el cliente.</p>

      <p>El módulo <module>mod_session_cookie</module> permite almacenar las
      sesiones de usuario en el navegador dentro de una cookie HTTP.</p>

    </section> <!-- /browsersession -->

    <section id="basicexamples"><title>Ejemplos básicos</title>

      <p>Crear una sesión es tan sencillo como activar la sesión y decidir
      dónde se almacenará. En este ejemplo, la sesión se almacenará en el
      navegador, en una cookie llamada <code>session</code>.</p>

      <example><title>Sesión basada en el navegador</title>
      <highlight language="config">
Session On
SessionCookieName session path=/
        </highlight>
      </example>

      <p>La sesión no es útil a menos que se pueda escribir en ella o leer de
      ella. El siguiente ejemplo muestra cómo se pueden insertar valores en la
      sesión mediante el uso de una cabecera de respuesta HTTP predeterminada
      llamada <code>X-Replace-Session</code>.</p>

      <example><title>Escribir en una sesión</title>
      <highlight language="config">
Session On
SessionCookieName session path=/
SessionHeader X-Replace-Session
        </highlight>
      </example>

      <p>La cabecera debe contener pares de nombre y valor expresados en el
      mismo formato que una cadena de consulta en una URL, como en el ejemplo
      siguiente. Establecer una clave con la cadena vacía tiene el efecto de
      eliminar esa clave de la sesión.</p>

      <example><title>CGI para escribir en una sesión</title>
      <highlight language="sh">
#!/bin/bash
echo "Content-Type: text/plain"
echo "X-Replace-Session: key1=foo&amp;key2=&amp;key3=bar"
echo
env
        </highlight>
      </example>

      <p>Si se configura, la sesión puede leerse de nuevo desde la variable de
      entorno HTTP_SESSION. Por defecto, la sesión se mantiene privada, por lo
      que esto debe activarse explícitamente con la directiva
      <directive module="mod_session">SessionEnv</directive>.</p>

      <example><title>Leer de una sesión</title>
      <highlight language="config">
Session On
SessionEnv On
SessionCookieName session path=/
SessionHeader X-Replace-Session
        </highlight>
      </example>

      <p>Una vez leída, la variable CGI <code>HTTP_SESSION</code> debería
      contener el valor <code>key1=foo&amp;key3=bar</code>.</p>

    </section>
    <section id="sessionprivacy"><title>Privacidad de la sesión</title>

      <p>Usando la función "mostrar cookies" de su navegador, habría visto una
      representación en texto claro de la sesión. Esto podría ser un problema
      si el usuario final necesita mantenerse al margen del contenido de la
      sesión, o cuando un tercero pudiera obtener acceso no autorizado a los
      datos dentro de la sesión.</p>

      <p>El contenido de la sesión puede cifrarse opcionalmente antes de
      colocarse en el navegador usando el módulo
      <module>mod_session_crypto</module>.</p>

      <example><title>Sesión cifrada basada en el navegador</title>
      <highlight language="config">
Session On
SessionCryptoPassphrase secret
SessionCookieName session path=/
        </highlight>
      </example>

      <p>La sesión se descifrará automáticamente al cargarla, y se cifrará al
      guardarla, por parte de Apache; la aplicación subyacente que use la
      sesión no necesita tener conocimiento de que se está produciendo un
      cifrado.</p>

      <p>Las sesiones almacenadas en el servidor en lugar de en el navegador
      también pueden cifrarse según sea necesario, ofreciendo privacidad
      cuando se comparte información potencialmente sensible entre servidores
      web en una granja de servidores mediante el módulo
      <module>mod_session_dbd</module>.</p>

    </section>
    <section id="cookieprivacy"><title>Privacidad de la cookie</title>

      <p>El mecanismo de cookies HTTP también ofrece características de
      privacidad, como la capacidad de restringir el transporte de la cookie
      solo a páginas protegidas por SSL, o de impedir que el javascript del
      navegador acceda al contenido de la cookie.</p>

      <note type="warning"><title>Advertencia</title>
      <p>Algunas de las características de privacidad de las cookies HTTP son
      o bien no estándar, o no se implementan de forma coherente entre
      navegadores. Los módulos de sesión le permiten establecer parámetros de
      la cookie, pero no garantizan que el navegador respete la privacidad. Si
      la seguridad es una preocupación, use <module>mod_session_crypto</module>
      para cifrar el contenido de la sesión, o almacene la sesión en el
      servidor usando el módulo <module>mod_session_dbd</module>.</p>
      </note>

      <p>Los parámetros estándar de la cookie pueden especificarse después del
      nombre de la cookie, como en el ejemplo siguiente.</p>

      <example><title>Establecer parámetros de la cookie</title>
      <highlight language="config">
Session On
SessionCryptoPassphrase secret
SessionCookieName session path=/private;domain=example.com;httponly;secure;
        </highlight>
      </example>

      <p>En los casos en los que el servidor Apache forma el frontend de
      servidores de origen backend, es posible eliminar las cookies de sesión
      de las cabeceras HTTP entrantes usando la directiva
      <directive module="mod_session_cookie">SessionCookieRemove</directive>.
      Esto evita que el contenido de las cookies de sesión sea accesible
      desde el servidor backend.
      </p>

    </section>
    <section id="authentication"><title>Soporte de sesiones para autenticación</title>

      <p>Como es posible en muchos servidores de aplicaciones, los módulos de
      autenticación pueden usar una sesión para almacenar el nombre de usuario
      y la contraseña tras el inicio de sesión. El módulo
      <module>mod_auth_form</module> guarda el nombre de usuario y la
      contraseña de inicio de sesión dentro de la sesión.</p>

      <example><title>Autenticación basada en formularios</title>
      <highlight language="config">
Session On
SessionCryptoPassphrase secret
SessionCookieName session path=/
AuthFormProvider file
AuthUserFile "conf/passwd"
AuthType form
AuthName "realm"
#...
        </highlight>
      </example>

      <p>Consulte el módulo <module>mod_auth_form</module> para la
      documentación y ejemplos completos.</p>

    </section>
    <section id="integration"><title>Integrar sesiones con aplicaciones externas</title>

      <p>Para que las sesiones sean útiles, debe ser posible compartir el
      contenido de una sesión con aplicaciones externas, y debe ser posible
      que una aplicación externa escriba una sesión propia.</p>

      <p> Un ejemplo típico podría ser una aplicación que cambia la contraseña
      de un usuario establecida por <module>mod_auth_form</module>. Esta
      aplicación necesitaría leer el nombre de usuario y la contraseña
      actuales de la sesión, realizar los cambios necesarios en la contraseña
      del usuario, y luego escribir la nueva contraseña en la sesión para
      proporcionar una transición sin interrupciones a la nueva contraseña.</p>

      <p>Un segundo ejemplo podría implicar una aplicación que registra a un
      nuevo usuario por primera vez. Cuando se completa el registro, el
      nombre de usuario y la contraseña se escriben en la sesión,
      proporcionando una transición sin interrupciones hasta quedar
      conectado.</p>

      <dl>
      <dt>Módulos de Apache</dt>
      <dd>Los módulos dentro del servidor que necesitan acceso a la sesión
      pueden usar la API de <strong>mod_session.h</strong> para leer y
      escribir en la sesión. Este mecanismo es usado por módulos como
      <module>mod_auth_form</module>.
      </dd>

      <dt>Programas CGI y lenguajes de script</dt>
      <dd>Las aplicaciones que se ejecutan dentro del servidor web pueden
      opcionalmente recuperar el valor de la sesión desde la variable de
      entorno <strong>HTTP_SESSION</strong>. La sesión debería codificarse
      como una cadena <strong>application/x-www-form-urlencoded</strong>
      según se describe en la
      <a href="http://www.w3.org/TR/html4/">especificación HTML</a>. La
      variable de entorno se controla mediante el ajuste de la directiva
      <directive module="mod_session">SessionEnv</directive>. El script puede
      escribir en la sesión devolviendo una cabecera de respuesta
      <strong>application/x-www-form-urlencoded</strong> con un nombre
      establecido por la directiva
      <directive module="mod_session">SessionHeader</directive>. En ambos
      casos, cualquier cifrado o descifrado, y la lectura de la sesión desde,
      o la escritura de la sesión en, el mecanismo de almacenamiento elegido
      son gestionados por los módulos de <module>mod_session</module> y la
      configuración correspondiente.
      </dd>

      <dt>Aplicaciones detrás de <module>mod_proxy</module></dt>
      <dd>Si se usa la directiva
      <directive module="mod_session">SessionHeader</directive> para definir
      una cabecera de petición HTTP, la sesión, codificada como una cadena
      <strong>application/x-www-form-urlencoded</strong>, se pondrá a
      disposición de la aplicación. Si se proporciona la misma cabecera en la
      respuesta, el valor de esta cabecera de respuesta se usará para
      reemplazar la sesión. Como antes, cualquier cifrado o descifrado, y la
      lectura de la sesión desde, o la escritura de la sesión en, el
      mecanismo de almacenamiento elegido son gestionados por los módulos de
      <module>mod_session</module> y la configuración correspondiente.</dd>

      <dt>Aplicaciones independientes</dt>
      <dd>Las aplicaciones pueden optar por manipular la sesión fuera del
      control del servidor HTTP Apache. En este caso, es responsabilidad de
      la aplicación leer la sesión desde el mecanismo de almacenamiento
      elegido, descifrar la sesión, actualizar la sesión, cifrar la sesión y
      escribir la sesión en el mecanismo de almacenamiento elegido, según
      corresponda.</dd>
      </dl>

    </section>

<directivesynopsis>
<name>Session</name>
<description>Activa una sesión para el directorio o la ubicación actual</description>
<syntax>Session On|Off</syntax>
<default>Session Off</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>Session</directive> activa una sesión para el
    contenedor de directorio o ubicación. Otras directivas controlan dónde se
    almacenará la sesión y cómo se mantiene la privacidad.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SessionMaxAge</name>
<description>Define una edad máxima en segundos para una sesión</description>
<syntax>SessionMaxAge <var>maxage</var></syntax>
<default>SessionMaxAge 0</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>SessionMaxAge</directive> define un límite de
    tiempo durante el cual una sesión permanecerá válida. Cuando se guarda una
    sesión, este límite de tiempo se reinicia y una sesión existente puede
    continuar. Si una sesión supera este límite sin que se haya producido una
    petición al servidor para renovarla, la sesión expirará y será eliminada.
    Cuando una sesión se usa para almacenar los datos de inicio de sesión de
    un usuario, esto tiene el efecto de desconectar al usuario
    automáticamente tras el tiempo indicado.</p>

    <p>Establecer maxage a cero desactiva la expiración de la sesión.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SessionEnv</name>
<description>Controla si el contenido de la sesión se escribe en la variable
de entorno <var>HTTP_SESSION</var></description>
<syntax>SessionEnv On|Off</syntax>
<default>SessionEnv Off</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Si se establece en <var>On</var>, la directiva
    <directive>SessionEnv</directive> hace que el contenido de la sesión se
    escriba en una variable de entorno CGI llamada <var>HTTP_SESSION</var>.</p>

    <p>La cadena se escribe en el formato de cadena de consulta de la URL,
    por ejemplo:</p>

    <example>
      <code>key1=foo&amp;key3=bar</code>
    </example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SessionHeader</name>
<description>Importa actualizaciones de la sesión desde una cabecera de respuesta HTTP dada</description>
<syntax>SessionHeader <var>header</var></syntax>
<default>none</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>SessionHeader</directive> define el nombre de
    una cabecera de respuesta HTTP que, si está presente, se analizará y se
    escribirá en la sesión actual.</p>

    <p>Se espera que el valor de la cabecera esté en el formato de cadena de
    consulta de la URL, por ejemplo:</p>

    <example>
      <code>key1=foo&amp;key2=&amp;key3=bar</code>
    </example>

    <p>Cuando una clave se establece con la cadena vacía, esa clave se
    eliminará de la sesión.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SessionInclude</name>
<description>Define los prefijos de URL para los que una sesión es válida</description>
<syntax>SessionInclude <var>path</var></syntax>
<default>all URLs</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>SessionInclude</directive> permite que las
    sesiones sean válidas solo para determinados prefijos de URL. Esto puede
    usarse para hacer un sitio web más eficiente, dirigiéndose a un espacio
    de URL más preciso para el cual debe mantenerse una sesión. Por defecto,
    todas las URL dentro del directorio o ubicación se incluyen en la
    sesión.</p>

    <note type="warning"><title>Advertencia</title>
    <p>Esta directiva tiene un propósito similar al del atributo
    <var>path</var> en las cookies HTTP, pero no debe confundirse con dicho
    atributo. Esta directiva no establece el atributo <var>path</var>, que
    debe configurarse por separado.</p></note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SessionExclude</name>
<description>Define los prefijos de URL para los que una sesión se ignora</description>
<syntax>SessionExclude <var>path</var></syntax>
<default>none</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>

<usage>
    <p>La directiva <directive>SessionExclude</directive> permite desactivar
    las sesiones en relación con determinados prefijos de URL únicamente.
    Esto puede usarse para hacer un sitio web más eficiente, dirigiéndose a
    un espacio de URL más preciso para el cual debe mantenerse una sesión.
    Por defecto, todas las URL dentro del directorio o ubicación se incluyen
    en la sesión. La directiva
    <directive module="mod_session">SessionExclude</directive> tiene
    precedencia sobre la directiva
    <directive module="mod_session">SessionInclude</directive>.</p>

    <note type="warning"><title>Advertencia</title>
    <p>Esta directiva tiene un propósito similar al del atributo
    <var>path</var> en las cookies HTTP, pero no debe confundirse con dicho
    atributo. Esta directiva no establece el atributo <var>path</var>, que
    debe configurarse por separado.</p></note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>SessionExpiryUpdateInterval</name>
<description>Define el número de segundos que puede variar la expiración de
una sesión sin que la sesión se actualice</description>
<syntax>SessionExpiryUpdateInterval <var>interval</var></syntax>
<default>SessionExpiryUpdateInterval 0 (always update)</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<compatibility>Disponible en Apache 2.4.41 y posteriores</compatibility>

<usage>
    <p>La directiva <directive>SessionExpiryUpdateInterval</directive>
    permite a las sesiones evitar el coste asociado con escribir la sesión en
    cada petición cuando solo ha cambiado el tiempo de expiración. Esto puede
    usarse para hacer un sitio web más eficiente o reducir la carga en una
    base de datos cuando se usa <module>mod_session_dbd</module>. La sesión
    siempre se escribe si los datos almacenados en la sesión han cambiado o
    si la expiración ha cambiado más que el intervalo configurado.</p>

    <p>Establecer el intervalo a cero desactiva esta directiva, y la
    expiración de la sesión se renueva en cada petición.</p>

    <p>Esta directiva solo tiene efecto cuando se combina con
    <directive module="mod_session">SessionMaxAge</directive> para activar la
    expiración de la sesión. Las sesiones sin expiración solo se escriben
    cuando los datos almacenados en la sesión han cambiado.</p>

    <note type="warning"><title>Advertencia</title>
    <p>Debido a que la expiración de la sesión puede no renovarse en cada
    petición, es posible que las sesiones expiren hasta <var>interval</var>
    segundos antes de tiempo. Usar un intervalo pequeño normalmente
    proporciona un ahorro suficiente mientras tiene un efecto mínimo en la
    resolución de la expiración.</p></note>
</usage>
</directivesynopsis>

</modulesynopsis>
