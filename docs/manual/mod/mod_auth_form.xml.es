<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1939369 -->
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

<modulesynopsis metafile="mod_auth_form.xml.meta">

<name>mod_auth_form</name>
<description>Autenticación mediante formulario</description>
<status>Base</status>
<sourcefile>mod_auth_form.c</sourcefile>
<identifier>auth_form_module</identifier>
<compatibility>Disponible en Apache 2.3 y posteriores</compatibility>

<summary>
    <note type="warning"><title>Advertencia</title>
      <p>La autenticación mediante formulario depende del módulo <module>mod_session</module>,
      y estos módulos hacen uso de cookies HTTP, por lo que pueden ser víctimas
      de ataques de Cross Site Scripting, o exponer información potencialmente privada
      a los clientes. Asegúrese de haber tenido en cuenta los riesgos relevantes
      antes de activar la funcionalidad de sesión en su
      servidor.</p>
    </note>

    <p>Este módulo permite usar un formulario de inicio de sesión HTML para restringir el acceso
    buscando a los usuarios en los proveedores indicados. Los formularios HTML requieren
    una configuración significativamente mayor que las alternativas, pero un
    formulario de inicio de sesión HTML puede ofrecer una experiencia mucho más amigable para los usuarios finales.
    </p>

    <p>La autenticación básica HTTP la proporciona
    <module>mod_auth_basic</module>, y la autenticación digest HTTP la
    proporciona <module>mod_auth_digest</module>. Este módulo debe
    combinarse con al menos un módulo de autenticación,
    como <module>mod_authn_file</module>, y uno de autorización,
    como <module>mod_authz_user</module>.</p>

    <p>Una vez que el usuario se ha autenticado correctamente, los datos de inicio de sesión del usuario
    se almacenarán en una sesión proporcionada por <module>mod_session</module>.
    </p>

</summary>
<seealso><module>mod_session</module></seealso>
<seealso><directive module="mod_authn_core">AuthName</directive></seealso>
<seealso><directive module="mod_authn_core">AuthType</directive></seealso>
<seealso><directive module="mod_authz_core">Require</directive></seealso>
<seealso><a href="../howto/auth.html">Cómo hacer autenticación</a></seealso>

    <section id="basicconfig"><title>Configuración básica</title>

      <p>Para proteger una URL concreta con <module>mod_auth_form</module>, necesita
      decidir dónde almacenará su <var>session</var>, y necesitará
      decidir qué método usará para autenticarse. En este ejemplo sencillo, los
      datos de inicio de sesión se almacenarán en una sesión basada en
      <module>mod_session_cookie</module>, y la autenticación se intentará contra
      un archivo usando <module>mod_authn_file</module>. Si la autenticación no tiene éxito,
      el usuario será redirigido a la página del formulario de inicio de sesión.</p>

      <example><title>Ejemplo básico</title>
      <highlight language="config">
&lt;Location "/admin"&gt;
    AuthFormProvider file
    AuthUserFile "conf/passwd"
    AuthType form
    AuthName "/admin"
    AuthFormLoginRequiredLocation "http://example.com/login.html"

    Session On
    SessionCookieName session path=/

    Require valid-user
&lt;/Location&gt;
        </highlight>
      </example>

      <p>La directiva <directive module="mod_authn_core">AuthType</directive> activará
      la autenticación de <module>mod_auth_form</module> cuando se establezca con el valor <var>form</var>.
      Las directivas <directive module="mod_auth_form">AuthFormProvider</directive> y
      <directive module="mod_authn_file">AuthUserFile</directive> especifican que los nombres de usuario
      y las contraseñas deben comprobarse contra el archivo elegido.</p>

      <p>Las directivas <directive module="mod_session">Session</directive> y
      <directive module="mod_session_cookie">SessionCookieName</directive>
      configuran una sesión almacenada en una cookie HTTP en el navegador. Para más información
      sobre las distintas opciones para configurar una sesión, lea la documentación de
      <module>mod_session</module>.</p>

      <p>Opcionalmente puede añadir una
      <directive module="mod_session_crypto">SessionCryptoPassphrase</directive> para
      crear una cookie de sesión cifrada. Esto requiere que esté cargado el
      módulo adicional <module>mod_session_crypto</module>.</p>

      <p>En el ejemplo sencillo anterior, se ha protegido una URL con
      <module>mod_auth_form</module>, pero aún no se le ha dado al usuario la oportunidad de
      introducir su nombre de usuario y contraseña. Las opciones para hacerlo incluyen proporcionar una
      página de inicio de sesión independiente dedicada a este propósito, o bien proporcionar la página
      de inicio de sesión en línea.</p>
    </section>

    <section id="standalone"><title>Inicio de sesión independiente</title>

      <p>El formulario de inicio de sesión puede alojarse como una página independiente, o puede proporcionarse en línea en
      la misma página.</p>

      <p>Al configurar el inicio de sesión como una página independiente, los intentos de autenticación fallidos
      deben redirigirse a un formulario de inicio de sesión creado por el sitio web para este propósito,
      usando la directiva <directive module="mod_auth_form">AuthFormLoginRequiredLocation</directive>.
      Normalmente esta página de inicio de sesión contendrá un formulario HTML que pide al usuario que
      proporcione su nombre de usuario y contraseña.</p>

      <example><title>Ejemplo de formulario de inicio de sesión</title>
        <highlight language="html">
&lt;form method="POST" action="/dologin.html"&gt;
  Username: &lt;input type="text" name="httpd_username" value="" /&gt;
  Password: &lt;input type="password" name="httpd_password" value="" /&gt;
  &lt;input type="submit" name="login" value="Login" /&gt;
&lt;/form&gt;
        </highlight>
      </example>

      <p>La parte que realiza el inicio de sesión real la gestiona el <var>form-login-handler</var>.
      La acción del formulario debe apuntar a este manejador, el cual se configura dentro de
      Apache httpd de la siguiente manera:</p>

      <example><title>Ejemplo de manejador de inicio de sesión de formulario</title>
      <highlight language="config">
&lt;Location "/dologin.html"&gt;
    SetHandler form-login-handler
    AuthFormLoginRequiredLocation "http://example.com/login.html"
    AuthFormLoginSuccessLocation "http://example.com/admin/index.html"
    AuthFormProvider file
    AuthUserFile "conf/passwd"
    AuthType form
    AuthName /admin
    Session On
    SessionCookieName session path=/
&lt;/Location&gt;
        </highlight>
      </example>

      <p>Las URLs especificadas por la directiva
      <directive module="mod_auth_form">AuthFormLoginRequiredLocation</directive> normalmente
      apuntarán a una página que explique al usuario que su intento de inicio de sesión no tuvo éxito, y que
      debería intentarlo de nuevo. La directiva <directive module="mod_auth_form">AuthFormLoginSuccessLocation</directive>
      especifica la URL a la que debe redirigirse al usuario tras un inicio de sesión correcto.</p>

      <p>Alternativamente, la URL a la que redirigir al usuario en caso de éxito puede incrustarse dentro del
      formulario de inicio de sesión, como en el siguiente ejemplo. Como resultado, el mismo <var>form-login-handler</var>
      se puede reutilizar para diferentes áreas de un sitio web.</p>

      <example><title>Ejemplo de formulario de inicio de sesión con ubicación</title>
        <highlight language="html">
&lt;form method="POST" action="/dologin.html"&gt;
  Username: &lt;input type="text" name="httpd_username" value="" /&gt;
  Password: &lt;input type="password" name="httpd_password" value="" /&gt;
  &lt;input type="submit" name="login" value="Login" /&gt;
  &lt;input type="hidden" name="httpd_location" value="http://example.com/success.html" /&gt;
&lt;/form&gt;
        </highlight>
      </example>

    </section>

    <section id="inline"><title>Inicio de sesión en línea</title>

      <note type="warning"><title>Advertencia</title>
        <p>Existe el riesgo de que, bajo ciertas circunstancias, el formulario de inicio de sesión configurado
        con inicio de sesión en línea se envíe más de una vez, revelando las credenciales de inicio de sesión a
        la aplicación subyacente. El administrador debe asegurarse de que la aplicación subyacente
        esté debidamente protegida para evitar abusos. En caso de duda, use la
        configuración de inicio de sesión independiente.</p>
      </note>

      <p>Como alternativa a tener una página de inicio de sesión dedicada para un sitio web, es posible
      configurar <module>mod_auth_form</module> para autenticar a los usuarios en línea, sin ser
      redirigidos a otra página. Esto permite preservar el estado de la página actual
      durante el intento de inicio de sesión. Esto puede ser útil en una situación en la que está vigente una
      sesión con tiempo límite y la sesión expira en medio de la petición del usuario. El
      usuario puede volver a autenticarse in situ, y puede continuar donde lo dejó.</p>

      <p>Si un usuario no autenticado intenta acceder a una página protegida por
      <module>mod_auth_form</module> que no está configurada con una directiva
      <directive module="mod_auth_form">AuthFormLoginRequiredLocation</directive>,
      se devuelve al navegador un código de estado <var>HTTP_UNAUTHORIZED</var> indicando al usuario
      que no está autorizado a ver la página.</p>

      <p>Para configurar la autenticación en línea, el administrador sobrescribe el documento de error
      devuelto por el código de estado <var>HTTP_UNAUTHORIZED</var> con un documento de error personalizado
      que contenga el formulario de inicio de sesión, como sigue:</p>

      <example><title>Ejemplo básico en línea</title>
      <highlight language="config">
AuthFormProvider file
ErrorDocument 401 "/login.shtml"
AuthUserFile "conf/passwd"
AuthType form
AuthName realm
Session On
SessionCookieName session path=/
        </highlight>
      </example>

      <p>La página del documento de error debe contener un formulario de inicio de sesión con una propiedad action vacía,
      como en el siguiente ejemplo. Esto tiene el efecto de enviar el formulario a
      la URL original protegida, sin que la página tenga que saber cuál es esa
      URL.</p>

      <example><title>Ejemplo de formulario de inicio de sesión en línea</title>
<highlight language="html">
&lt;form method="POST" <strong>action=""</strong>&gt;
  Username: &lt;input type="text" name="httpd_username" value="" /&gt;
  Password: &lt;input type="password" name="httpd_password" value="" /&gt;
  &lt;input type="submit" name="login" value="Login" /&gt;
&lt;/form&gt;
</highlight>
      </example>

      <p>Cuando el usuario final ha rellenado sus datos de inicio de sesión, el formulario realizará
      una petición HTTP POST a la URL original protegida por contraseña.
      <module>mod_auth_form</module> interceptará esta petición POST, y si
      se encuentran presentes los campos HTML para el nombre de usuario y la contraseña, el usuario
      iniciará sesión, y la URL original protegida por contraseña se devolverá
      al usuario como una petición GET.</p>

    </section>

    <section id="inlinepreservebody"><title>Inicio de sesión en línea con preservación del cuerpo</title>

      <p>Una limitación de la técnica de inicio de sesión en línea descrita anteriormente es que, si un
      POST de formulario HTML ha dado lugar a la petición de autenticación o
      reautenticación, el
      contenido del formulario original enviado por el navegador se perderá. Dependiendo de
      la función del sitio web, esto podría suponer un inconveniente significativo para el
      usuario final.</p>

      <p><module>mod_auth_form</module> resuelve esto permitiendo que el método y el cuerpo
      de la petición original se incrusten en el formulario de inicio de sesión. Si la autenticación
      tiene éxito, Apache httpd volverá a intentar el método y el cuerpo originales, preservando
      el estado de la petición original.</p>

      <p>Para activar la preservación del cuerpo, añada tres campos adicionales al formulario de inicio de sesión
      como en el siguiente ejemplo.</p>

      <example><title>Ejemplo con preservación del cuerpo</title>
        <highlight language="html">
&lt;form method="POST" action=""&gt;
  Username: &lt;input type="text" name="httpd_username" value="" /&gt;
  Password: &lt;input type="password" name="httpd_password" value="" /&gt;
  &lt;input type="submit" name="login" value="Login" /&gt;
  <br/>  <strong>&lt;input type="hidden" name="httpd_method" value="POST" /&gt;
  &lt;input type="hidden" name="httpd_mimetype" value="application/x-www-form-urlencoded" /&gt;
  &lt;input type="hidden" name="httpd_body" value="name1=value1&amp;name2=value2" /&gt;</strong><br/>
&lt;/form&gt;
        </highlight>
      </example>

      <p>La forma en que se incrustan el método, el tipo MIME y el cuerpo de la petición original dentro del
      formulario de inicio de sesión dependerá de la plataforma y la tecnología utilizadas en el sitio web.
      </p>

      <p>Una opción es usar el módulo <module>mod_include</module> junto con la
      directiva <directive module="mod_request">KeptBodySize</directive>, junto con un
      script CGI adecuado para incrustar las variables en el formulario.</p>

      <p>Otra opción es generar el formulario de inicio de sesión usando un script CGI u otra tecnología
      dinámica.</p>

      <example><title>Ejemplo CGI</title>
      <highlight language="config">
AuthFormProvider file
ErrorDocument 401 "/cgi-bin/login.cgi"
...
        </highlight>
      </example>

    </section>

    <section id="loggingout"><title>Cerrar sesión</title>

      <p>Para permitir que un usuario cierre sesión en una sesión concreta, configure una página para que
      sea gestionada por el <var>form-logout-handler</var>. Cualquier intento de acceder a esta
      URL hará que se elimine el nombre de usuario y la contraseña de la
      sesión actual, cerrando efectivamente la sesión del usuario.</p>

      <p>Estableciendo la directiva
      <directive module="mod_auth_form">AuthFormLogoutLocation</directive>,
      se puede especificar una URL a la que se redirigirá al navegador tras un
      cierre de sesión correcto. Esta URL podría explicar al usuario que se ha cerrado la sesión, y
      ofrecer al usuario la opción de volver a iniciar sesión.</p>

      <example><title>Ejemplo básico de cierre de sesión</title>
      <highlight language="config">
SetHandler form-logout-handler
AuthName realm
AuthFormLogoutLocation "http://example.com/loggedout.html"
Session On
SessionCookieName session path=/
        </highlight>
      </example>

      <p>Tenga en cuenta que cerrar la sesión de un usuario no elimina la sesión; simplemente elimina
      el nombre de usuario y la contraseña de la sesión. Si esto da como resultado una sesión vacía,
      el efecto neto será la eliminación de dicha sesión, pero esto no está
      garantizado. Si desea garantizar la eliminación de una sesión, establezca la
      directiva <directive module="mod_session">SessionMaxAge</directive> con un valor
      pequeño, como 1 (establecer la directiva a cero significaría que no hay límite de edad de sesión).
      </p>

      <example><title>Ejemplo básico de caducidad de sesión</title>
      <highlight language="config">
SetHandler form-logout-handler
AuthFormLogoutLocation "http://example.com/loggedout.html"
Session On
SessionMaxAge 1
SessionCookieName session path=/
        </highlight>
      </example>

    </section>

    <section id="urlencoding"><title>Nombres de usuario y contraseñas</title>
    <p>Tenga en cuenta que el envío de formularios implica codificar como URL los datos del formulario:
    en este caso el nombre de usuario y la contraseña. Por lo tanto, debería
    elegir nombres de usuario y contraseñas que eviten caracteres que se
    codifiquen como URL al enviar el formulario, o podría obtener resultados inesperados.</p>
    </section>

<directivesynopsis>
<name>AuthFormProvider</name>
<description>Establece los proveedores de autenticación para esta ubicación</description>
<syntax>AuthFormProvider <var>provider-name</var>
[<var>provider-name</var>] ...</syntax>
<default>AuthFormProvider file</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>AuthFormProvider</directive> establece
    qué proveedor se usa para autenticar a los usuarios para esta ubicación.
    El proveedor por defecto, <code>file</code>, está implementado
    por el módulo <module>mod_authn_file</module>. Asegúrese de
    que el módulo proveedor elegido esté presente en el servidor.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
&lt;Location "/secure"&gt;
    AuthType form
    AuthName "private area"
    AuthFormProvider  dbm
    AuthDBMType        SDBM
    AuthDBMUserFile    "/www/etc/dbmpasswd"
    Require            valid-user
    #...
&lt;/Location&gt;
      </highlight>
    </example>

    <p>Los proveedores los implementan <module>mod_authn_dbm</module>,
    <module>mod_authn_file</module>, <module>mod_authn_dbd</module>,
    <module>mod_authnz_ldap</module> y <module>mod_authn_socache</module>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthFormAuthoritative</name>
<description>Establece si la autorización y la autenticación se pasan a
módulos de nivel inferior</description>
<syntax>AuthFormAuthoritative On|Off</syntax>
<default>AuthFormAuthoritative On</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Normalmente, cada módulo de autorización listado en <directive
    module="mod_auth_form">AuthFormProvider</directive> intentará
    verificar al usuario, y si el usuario no se encuentra en ningún proveedor,
    se denegará el acceso. Establecer explícitamente la directiva
    <directive>AuthFormAuthoritative</directive> con el valor
    <code>Off</code> permite que tanto la autenticación como la
    autorización se pasen a otros módulos que no están basados en proveedores
    si no hay <strong>ningún userID</strong> o <strong>regla</strong>
    que coincida con el userID proporcionado. Esto solo debería ser necesario cuando se
    combine <module>mod_auth_form</module> con módulos de terceros
    que no están configurados con la directiva
    <directive module="mod_auth_form">AuthFormProvider</directive>.
    Al usar dichos módulos, el orden de procesamiento
    lo determina el código fuente de los módulos y no es configurable.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthFormUsername</name>
<description>El nombre de un campo del formulario que contiene el nombre de usuario de inicio de sesión</description>
<syntax>AuthFormUsername <var>fieldname</var></syntax>
<default>AuthFormUsername httpd_username</default>
<contextlist><context>directory</context>
</contextlist>
<compatibility>Disponible en Apache HTTP Server 2.3.0 y posteriores</compatibility>

<usage>
    <p>La directiva <directive module="mod_auth_form">AuthFormUsername</directive> especifica
    el nombre de un campo HTML que, si está presente, contendrá el nombre de usuario que se usará para
    iniciar sesión.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthFormPassword</name>
<description>El nombre de un campo del formulario que contiene la contraseña de inicio de sesión</description>
<syntax>AuthFormPassword <var>fieldname</var></syntax>
<default>AuthFormPassword httpd_password</default>
<contextlist><context>directory</context>
</contextlist>
<compatibility>Disponible en Apache HTTP Server 2.3.0 y posteriores</compatibility>

<usage>
    <p>La directiva <directive module="mod_auth_form">AuthFormPassword</directive> especifica
    el nombre de un campo HTML que, si está presente, contendrá la contraseña que se usará para
    iniciar sesión.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthFormLocation</name>
<description>El nombre de un campo del formulario que contiene una URL a la que redirigir tras un inicio de sesión correcto</description>
<syntax>AuthFormLocation <var>fieldname</var></syntax>
<default>AuthFormLocation httpd_location</default>
<contextlist><context>directory</context>
</contextlist>
<compatibility>Disponible en Apache HTTP Server 2.3.0 y posteriores</compatibility>

<usage>
    <p>La directiva <directive module="mod_auth_form">AuthFormLocation</directive> especifica
    el nombre de un campo HTML que, si está presente, contendrá una URL a la que redirigir el navegador
    si el inicio de sesión tiene éxito.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthFormMethod</name>
<description>El nombre de un campo del formulario que contiene el método de la petición a intentar tras un inicio de sesión correcto</description>
<syntax>AuthFormMethod <var>fieldname</var></syntax>
<default>AuthFormMethod httpd_method</default>
<contextlist><context>directory</context>
</contextlist>
<compatibility>Disponible en Apache HTTP Server 2.3.0 y posteriores</compatibility>

<usage>
    <p>La directiva <directive module="mod_auth_form">AuthFormMethod</directive> especifica
    el nombre de un campo HTML que, si está presente, contendrá el método de la petición
    a enviar si el inicio de sesión tiene éxito.</p>

    <p>Rellenando el formulario con los campos descritos por
    <directive module="mod_auth_form">AuthFormMethod</directive>,
    <directive module="mod_auth_form">AuthFormMimetype</directive> y
    <directive module="mod_auth_form">AuthFormBody</directive>, un sitio web puede reintentar
    una petición que pudiera haberse interrumpido por la pantalla de inicio de sesión, o por la caducidad
    de una sesión.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthFormMimetype</name>
<description>El nombre de un campo del formulario que contiene el tipo MIME del cuerpo de la petición a intentar tras un inicio de sesión correcto</description>
<syntax>AuthFormMimetype <var>fieldname</var></syntax>
<default>AuthFormMimetype httpd_mimetype</default>
<contextlist><context>directory</context>
</contextlist>
<compatibility>Disponible en Apache HTTP Server 2.3.0 y posteriores</compatibility>

<usage>
    <p>La directiva <directive module="mod_auth_form">AuthFormMimetype</directive> especifica
    el nombre de un campo HTML que, si está presente, contendrá el
    tipo MIME de la petición a enviar si el inicio de sesión tiene éxito.</p>

    <p>Rellenando el formulario con los campos descritos por
    <directive module="mod_auth_form">AuthFormMethod</directive>,
    <directive module="mod_auth_form">AuthFormMimetype</directive> y
    <directive module="mod_auth_form">AuthFormBody</directive>, un sitio web puede reintentar
    una petición que pudiera haberse interrumpido por la pantalla de inicio de sesión, o por la caducidad
    de una sesión.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthFormBody</name>
<description>El nombre de un campo del formulario que contiene el cuerpo de la petición a intentar tras un inicio de sesión correcto</description>
<syntax>AuthFormBody <var>fieldname</var></syntax>
<default>AuthFormBody httpd_body</default>
<contextlist><context>directory</context>
</contextlist>
<compatibility>Disponible en Apache HTTP Server 2.3.0 y posteriores</compatibility>

<usage>
    <p>La directiva <directive module="mod_auth_form">AuthFormBody</directive> especifica
    el nombre de un campo HTML que, si está presente, contendrá el cuerpo de la petición
    a enviar si el inicio de sesión tiene éxito.</p>

    <p>Rellenando el formulario con los campos descritos por
    <directive module="mod_auth_form">AuthFormMethod</directive>,
    <directive module="mod_auth_form">AuthFormMimetype</directive> y
    <directive module="mod_auth_form">AuthFormBody</directive>, un sitio web puede reintentar
    una petición que pudiera haberse interrumpido por la pantalla de inicio de sesión, o por la caducidad
    de una sesión.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthFormSize</name>
<description>El tamaño máximo en bytes del formulario que se analizará para obtener los datos de inicio de sesión</description>
<syntax>AuthFormSize <var>size</var></syntax>
<default>AuthFormSize 8192</default>
<contextlist><context>directory</context>
</contextlist>
<compatibility>Disponible en Apache HTTP Server 2.3.0 y posteriores</compatibility>

<usage>
    <p>La directiva <directive module="mod_auth_form">AuthFormSize</directive> especifica
    el tamaño máximo del cuerpo de la petición que se analizará para encontrar el formulario de inicio de sesión.</p>

    <p>Si llega una petición de inicio de sesión que supera este tamaño, se abortará toda la petición
    con el código de respuesta HTTP <code>HTTP_REQUEST_TOO_LARGE</code>.</p>

    <p>Si ha rellenado el formulario con los campos descritos por
    <directive module="mod_auth_form">AuthFormMethod</directive>,
    <directive module="mod_auth_form">AuthFormMimetype</directive> y
    <directive module="mod_auth_form">AuthFormBody</directive>, probablemente querrá establecer este
    valor con un tamaño similar al de la directiva <directive module="mod_request">KeptBodySize</directive>.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthFormLoginRequiredLocation</name>
<description>La URL de la página a la que redirigir si se requiere iniciar sesión</description>
<syntax>AuthFormLoginRequiredLocation <var>url</var></syntax>
<default>none</default>
<contextlist><context>directory</context>
</contextlist>
<compatibility>Disponible en Apache HTTP Server 2.3.0 y posteriores. El uso del analizador
de expresiones se añadió en la versión 2.4.4.</compatibility>

<usage>
    <p>La directiva <directive module="mod_auth_form">AuthFormLoginRequiredLocation</directive>
    especifica la URL a la que redirigir si el usuario no está autorizado para ver una página. El valor
    se analiza con el analizador <a href="../expr.html">ap_expr</a> antes de enviarse al cliente.
    Por defecto, si un usuario no está autorizado para ver una página, se devolverá el código de respuesta HTTP
    <code>HTTP_UNAUTHORIZED</code> con la página especificada por la
    directiva <directive module="core">ErrorDocument</directive>. Esta directiva sobrescribe ese
    comportamiento por defecto.</p>

    <p>Use esta directiva si tiene una página de inicio de sesión dedicada a la que redirigir a los usuarios.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthFormLoginSuccessLocation</name>
<description>La URL de la página a la que redirigir si el inicio de sesión tiene éxito</description>
<syntax>AuthFormLoginSuccessLocation <var>url</var></syntax>
<default>none</default>
<contextlist><context>directory</context>
</contextlist>
<compatibility>Disponible en Apache HTTP Server 2.3.0 y posteriores. El uso del analizador
de expresiones se añadió en la versión 2.4.4.</compatibility>

<usage>
    <p>La directiva <directive module="mod_auth_form">AuthFormLoginSuccessLocation</directive>
    especifica la URL a la que redirigir si el usuario ha iniciado sesión correctamente. El valor se
    analiza con el analizador <a href="../expr.html">ap_expr</a> antes de enviarse al cliente.
    Esta directiva puede sobrescribirse si se ha definido un campo de formulario que contiene otra URL
    mediante la directiva <directive module="mod_auth_form">AuthFormLocation</directive>.</p>

    <p>Use esta directiva si tiene una URL de inicio de sesión dedicada y no ha incrustado la
    página de destino en el formulario de inicio de sesión.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthFormFakeBasicAuth</name>
<description>Simular una cabecera de autenticación básica</description>
<syntax>AuthFormFakeBasicAuth On|Off</syntax>
<default>AuthFormFakeBasicAuth Off</default>
<contextlist><context>directory</context>
</contextlist>
<compatibility>Disponible en Apache HTTP Server 2.3.0 y posteriores</compatibility>

<usage>
    <p>La bandera <directive module="mod_auth_form">AuthFormFakeBasicAuth</directive>
    determina si se añadirá una cabecera de <code>Basic Authentication</code> a
    las cabeceras de la petición. Esto puede usarse para exponer el nombre de usuario y la contraseña
    a una aplicación subyacente, sin que la aplicación subyacente tenga que saber
    cómo se realizó el inicio de sesión.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthFormLogoutLocation</name>
<description>La URL a la que redirigir después de que un usuario haya cerrado sesión</description>
<syntax>AuthFormLogoutLocation <var>uri</var></syntax>
<default>none</default>
<contextlist><context>directory</context>
</contextlist>
<compatibility>Disponible en Apache HTTP Server 2.3.0 y posteriores. El uso del analizador
de expresiones se añadió en la versión 2.4.4.</compatibility>

<usage>
    <p>La directiva <directive module="mod_auth_form">AuthFormLogoutLocation</directive>
    especifica la URL de una página del servidor a la que redirigir si el usuario intenta cerrar
    sesión. El valor se analiza con el analizador <a href="../expr.html">ap_expr</a> antes de
    enviarse al cliente.</p>

    <p>Cuando se accede a una URI servida por el manejador <code>form-logout-handler</code>,
    se mostrará al usuario final la página especificada por esta directiva. Por ejemplo:</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
&lt;Location "/logout"&gt;
    SetHandler form-logout-handler
    AuthFormLogoutLocation "http://example.com/loggedout.html"
    Session on
    #...
&lt;/Location&gt;
      </highlight>
    </example>

    <p>Un intento de acceder a la URI <var>/logout/</var> hará que se cierre la sesión del usuario,
    y se mostrará la página <var>/loggedout.html</var>. Asegúrese de que la página
    <var>loggedout.html</var> no esté protegida por contraseña, ya que de lo contrario la página no se
    mostrará.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthFormDisableNoStore</name>
<description>Desactiva la cabecera CacheControl no-store en la página de inicio de sesión</description>
<syntax>AuthFormDisableNoStore On|Off</syntax>
<default>AuthFormDisableNoStore Off</default>
<contextlist><context>directory</context>
</contextlist>
<compatibility>Disponible en Apache HTTP Server 2.3.0 y posteriores</compatibility>

<usage>
    <p>La bandera <directive module="mod_auth_form">AuthFormDisableNoStore</directive>
    desactiva el envío de una cabecera <code>Cache-Control no-store</code> con la
    página de error 401 devuelta cuando el usuario aún no ha iniciado sesión. El propósito de la cabecera
    es dificultar que una aplicación <code>ecmascript</code> intente reenviar el
    formulario de inicio de sesión, y revelar el nombre de usuario y la contraseña a la aplicación subyacente. Desactívela
    bajo su propia responsabilidad.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthFormSitePassphrase</name>
<description>Omitir las comprobaciones de autenticación para sitios de alto tráfico</description>
<syntax>AuthFormSitePassphrase <var>secret</var></syntax>
<default>none</default>
<contextlist><context>directory</context>
</contextlist>
<compatibility>Disponible en Apache HTTP Server 2.3.0 y posteriores</compatibility>

<usage>
    <p>La directiva <directive module="mod_auth_form">AuthFormSitePassphrase</directive>
    especifica una frase de paso que, si está presente en la sesión del usuario, hace que Apache httpd
    omita las comprobaciones de autenticación para la URL indicada. Puede usarse
    en sitios web de alto tráfico para reducir la carga inducida en la infraestructura de autenticación.</p>

    <p>La frase de paso puede insertarse en una sesión de usuario añadiendo esta directiva a la
    configuración del <var>form-login-handler</var>. El propio <var>form-login-handler</var>
    siempre ejecutará las comprobaciones de autenticación, independientemente de si se especifica o no
    una frase de paso.</p>

    <note type="warning"><title>Advertencia</title>
      <p>Si la sesión se expone al usuario mediante el uso de
      <module>mod_session_cookie</module>, y la sesión no está protegida con
      <module>mod_session_crypto</module>, la frase de paso queda expuesta a un posible ataque
      de diccionario. Independientemente de cómo esté configurada la sesión,
      asegúrese de que esta directiva no se use en espacios de URL donde se pudieran exponer
      datos privados de usuarios, o donde se puedan realizar transacciones sensibles. Úsela bajo su propia responsabilidad.</p>
    </note>

</usage>
</directivesynopsis>

</modulesynopsis>
