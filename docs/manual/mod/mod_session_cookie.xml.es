<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1874941 -->
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

<modulesynopsis metafile="mod_session_cookie.xml.meta">

<name>mod_session_cookie</name>
<description>Soporte de sesiones basado en cookies</description>
<status>Extension</status>
<sourcefile>mod_session_cookie.c</sourcefile>
<identifier>session_cookie_module</identifier>
<compatibility>Disponible en Apache 2.3 y posteriores</compatibility>

<summary>
    <note type="warning"><title>Advertencia</title>
      <p>Los módulos de sesión hacen uso de cookies HTTP, y como tales pueden ser
      víctimas de ataques de tipo Cross Site Scripting, o exponer información potencialmente
      privada a los clientes. Asegúrese de que se han tenido en cuenta los
      riesgos correspondientes antes de habilitar la funcionalidad de sesión en
      su servidor.</p>
    </note>

    <p>Este submódulo de <module>mod_session</module> proporciona soporte para el
    almacenamiento de sesiones de usuario en el navegador remoto mediante cookies HTTP.</p>

    <p>Usar cookies para almacenar una sesión elimina la necesidad de que el servidor o
    un grupo de servidores almacenen la sesión localmente, o colaboren para compartir
    una sesión, y puede resultar útil en entornos de tráfico elevado donde una
    sesión basada en el servidor podría consumir demasiados recursos.</p>

    <p>Si se requiere privacidad de la sesión, se puede usar el módulo
    <module>mod_session_crypto</module> para cifrar el contenido de la sesión antes de
    escribirla en el cliente.</p>

    <p>Para más detalles sobre la interfaz de sesión, consulte la documentación
    del módulo <module>mod_session</module>.</p>

</summary>
<seealso><module>mod_session</module></seealso>
<seealso><module>mod_session_crypto</module></seealso>
<seealso><module>mod_session_dbd</module></seealso>

    <section id="basicexamples"><title>Ejemplos básicos</title>

      <p>Para crear una sesión sencilla y almacenarla en una cookie llamada
      <var>session</var>, configure la sesión de la siguiente forma:</p>

      <example><title>Sesión basada en el navegador</title>
      <highlight language="config">
Session On
SessionCookieName session path=/
        </highlight>
      </example>

      <p>Para más ejemplos sobre cómo se puede configurar la sesión para que una
      aplicación CGI la lea y escriba, consulte la sección de ejemplos de
      <module>mod_session</module>.</p>

      <p>Para documentación sobre cómo se puede usar la sesión para almacenar los datos de
      nombre de usuario y contraseña, consulte el módulo <module>mod_auth_form</module>.</p>

    </section>

<directivesynopsis>
<name>SessionCookieName</name>
<description>Nombre y atributos de la cookie RFC2109 que almacena la sesión</description>
<syntax>SessionCookieName <var>name</var> <var>attributes</var></syntax>
<default>none</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>SessionCookieName</directive> especifica el nombre y los
    atributos opcionales de una cookie conforme a RFC2109 dentro de la cual se
    almacenará la sesión. Las cookies RFC2109 se establecen usando la cabecera HTTP <code>Set-Cookie</code>.
    </p>

    <p>Se puede especificar una lista opcional de atributos de la cookie, como en el ejemplo siguiente.
    Estos atributos se insertan en la cookie tal cual, y no son interpretados por
    Apache. Asegúrese de que sus atributos están definidos correctamente según la especificación de cookies.
    </p>

    <example><title>Cookie con atributos</title>
    <highlight language="config">
Session On
SessionCookieName session path=/private;domain=example.com;httponly;secure;version=1;
      </highlight>
    </example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SessionCookieName2</name>
<description>Nombre y atributos de la cookie RFC2965 que almacena la sesión</description>
<syntax>SessionCookieName2 <var>name</var> <var>attributes</var></syntax>
<default>none</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>La directiva <directive>SessionCookieName2</directive> especifica el nombre y los
    atributos opcionales de una cookie conforme a RFC2965 dentro de la cual se
    almacenará la sesión. Las cookies RFC2965 se establecen usando la cabecera HTTP <code>Set-Cookie2</code>.
    </p>

    <p>Se puede especificar una lista opcional de atributos de la cookie, como en el ejemplo siguiente.
    Estos atributos se insertan en la cookie tal cual, y no son interpretados por
    Apache. Asegúrese de que sus atributos están definidos correctamente según la especificación de cookies.
    </p>

    <example><title>Cookie2 con atributos</title>
    <highlight language="config">
Session On
SessionCookieName2 session path=/private;domain=example.com;httponly;secure;version=1;
    </highlight>
    </example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SessionCookieRemove</name>
<description>Control de si las cookies de sesión deben eliminarse de las cabeceras HTTP entrantes</description>
<syntax>SessionCookieRemove On|Off</syntax>
<default>SessionCookieRemove Off</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>El indicador <directive>SessionCookieRemove</directive> controla si las cookies
    que contienen la sesión se eliminarán de las cabeceras durante el procesamiento de la petición.</p>

    <p>En una situación de proxy inverso donde el servidor Apache actúa como frontend para
    un servidor de origen backend, revelar el contenido de la cookie de sesión al
    backend podría suponer una posible violación de la privacidad. Cuando se establece a on, la cookie de sesión se
    eliminará de las cabeceras HTTP entrantes.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SessionCookieMaxAge</name>
<description>Controla si las cookies de sesión transmiten Max-Age al cliente</description>
<syntax>SessionCookieMaxAge On|Off</syntax>
<default>SessionCookieMaxAge On</default>
<contextlist><context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>El indicador <directive>SessionCookieMaxAge</directive> controla si
    la expiración de la sesión se especificará en el atributo Max-Age de la
    cookie enviada al cliente. Cuando se establece a 'Off', el atributo no se
    añadirá y los clientes solo devolverán la cookie hasta que "la sesión
    actual termine". Esto suele significar hasta que se cierre el navegador.</p>

    <p>La expiración de la sesión sigue validándose en el servidor mediante
    la directiva <directive module="mod_session">SessionMaxAge</directive>.
    </p>

</usage>
</directivesynopsis>


</modulesynopsis>
