<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1901567 -->
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

<modulesynopsis metafile="mod_authz_dbd.xml.meta">

<name>mod_authz_dbd</name>
<description>Autorización de grupos e inicio de sesión usando SQL</description>
<status>Extension</status>
<sourcefile>mod_authz_dbd.c</sourcefile>
<identifier>authz_dbd_module</identifier>
<compatibility>Disponible en Apache 2.4 y posteriores</compatibility>

<summary>
    <p>Este módulo proporciona capacidades de autorización para que a los
       usuarios autenticados se les pueda permitir o denegar el acceso a partes
       del sitio web según su pertenencia a grupos. <module>mod_authz_groupfile</module> y
       <module>mod_authz_dbm</module> ofrecen una funcionalidad similar,
       con la excepción de que este módulo consulta una base de datos SQL
       para determinar si un usuario pertenece a un grupo.</p>
    <p>Este módulo también puede proporcionar capacidades de inicio/cierre de sesión
       de usuario respaldadas por base de datos. Es probable que sean más útiles
       cuando se usan junto con <module>mod_authn_dbd</module>.</p>
    <p>Este módulo depende de <module>mod_dbd</module> para especificar
       el driver de base de datos del backend y los parámetros de conexión, y
       gestionar las conexiones a la base de datos.</p>
</summary>

<seealso><directive module="mod_authz_core">Require</directive></seealso>
<seealso>
  <directive module="mod_authn_dbd">AuthDBDUserPWQuery</directive>
</seealso>
<seealso><directive module="mod_dbd">DBDriver</directive></seealso>
<seealso><directive module="mod_dbd">DBDParams</directive></seealso>

<section id="requiredirectives"><title>Las directivas Require</title>

    <p>Las directivas <directive module="mod_authz_core">Require</directive>
    de Apache se usan durante la fase de autorización para asegurar que
    un usuario tiene permiso para acceder a un recurso. mod_authz_dbd extiende
    los tipos de autorización con <code>dbd-group</code>, <code>dbd-login</code> y
    <code>dbd-logout</code>.</p>

    <p>Desde la v2.4.8, se admiten <a href="../expr.html">expresiones</a>
    dentro de las directivas Require de DBD.</p>

<section id="reqgroup"><title>Require dbd-group</title>

    <p>Esta directiva especifica la pertenencia a grupo que se requiere para que el
    usuario obtenga acceso.</p>

    <highlight language="config">
Require dbd-group team
AuthzDBDQuery "SELECT user_group FROM authz WHERE user = %s"
    </highlight>

</section>

<section id="reqlogin"><title>Require dbd-login</title>

    <p>Esta directiva especifica una consulta que se ejecutará para indicar que el
    usuario ha iniciado sesión.</p>

    <highlight language="config">
Require dbd-login
AuthzDBDQuery "UPDATE authn SET login = 'true' WHERE user = %s"
    </highlight>

</section>

<section id="reqlogout"><title>Require dbd-logout</title>

    <p>Esta directiva especifica una consulta que se ejecutará para indicar que el
    usuario ha cerrado sesión.</p>

    <highlight language="config">
Require dbd-logout
AuthzDBDQuery "UPDATE authn SET login = 'false' WHERE user = %s"
    </highlight>

</section>

</section>

<section id="login">
<title>Inicio de sesión en base de datos</title>
<p>
Además de la función de autorización estándar de comprobar la pertenencia
a grupos, este módulo también puede ofrecer gestión de sesión de usuario del
lado del servidor mediante capacidades de inicio/cierre de sesión respaldadas por base de datos.
En concreto, puede actualizar el estado de la sesión de un usuario en la base de datos
cada vez que el usuario visita las URLs designadas (sujeto, por supuesto, a que el usuario
proporcione las credenciales necesarias).</p>
<p>Esto funciona definiendo dos tipos especiales de
<directive module="mod_authz_core">Require</directive>:
<code>Require dbd-login</code> y <code>Require dbd-logout</code>.
Para más detalles de uso, vea el ejemplo de configuración siguiente.</p>
</section>

<section id="client">
<title>Integración con el inicio de sesión del cliente</title>
<p>Algunos administradores pueden querer implementar una gestión de sesión del
lado del cliente que funcione junto con las capacidades de inicio/cierre de sesión
del lado del servidor que ofrece este módulo, por ejemplo, estableciendo o eliminando
una cookie HTTP u otro token similar cuando un usuario inicia o cierra sesión.</p>
<p>Para dar soporte a esta integración, <module>mod_authz_dbd</module> exporta un
hook opcional que se ejecutará cada vez que se actualice el estado de un usuario en
la base de datos. Otros módulos de gestión de sesión pueden entonces usar el hook
para implementar funciones que inicien y terminen sesiones del lado del cliente.</p>
</section>

<section id="example">
<title>Ejemplo de configuración</title>
<highlight language="config">
# configuración de mod_dbd
DBDriver pgsql
DBDParams "dbname=apacheauth user=apache pass=xxxxxx"

DBDMin  4
DBDKeep 8
DBDMax  20
DBDExptime 300

&lt;Directory "/usr/www/my.site/team-private/"&gt;
  # configuración de mod_authn_core y mod_auth_basic
  # para mod_authn_dbd
  AuthType Basic
  AuthName Team
  AuthBasicProvider dbd

  # consulta SQL de mod_authn_dbd para autenticar a un usuario que ha iniciado sesión
  AuthDBDUserPWQuery \
    "SELECT password FROM authn WHERE user = %s AND login = 'true'"

  # configuración de mod_authz_core para mod_authz_dbd
  Require dbd-group team

  # configuración de mod_authz_dbd
  AuthzDBDQuery "SELECT group FROM authz WHERE user = %s"

  # cuando un usuario no consigue autenticarse o autorizarse,
  # se le invita a iniciar sesión; esta página debería incluir un enlace
  # a /team-private/login.html
  ErrorDocument 401 "/login-info.html"

  &lt;Files "login.html"&gt;
    # no exigir que el usuario ya haya iniciado sesión
    AuthDBDUserPWQuery "SELECT password FROM authn WHERE user = %s"

    # la acción dbd-login ejecuta una instrucción para iniciar la sesión del usuario
    Require dbd-login
    AuthzDBDQuery "UPDATE authn SET login = 'true' WHERE user = %s"

    # devolver al usuario a la página de referencia (si la hay) tras
    # iniciar sesión correctamente
    AuthzDBDLoginToReferer On
  &lt;/Files&gt;

  &lt;Files "logout.html"&gt;
    # la acción dbd-logout ejecuta una instrucción para cerrar la sesión del usuario
    Require dbd-logout
    AuthzDBDQuery "UPDATE authn SET login = 'false' WHERE user = %s"
  &lt;/Files&gt;
&lt;/Directory&gt;
</highlight>
</section>

<directivesynopsis>
<name>AuthzDBDQuery</name>
<description>Especifica la consulta SQL para la operación requerida</description>
<syntax>AuthzDBDQuery <var>query</var></syntax>
<contextlist><context>directory</context></contextlist>

<usage>
    <p><directive>AuthzDBDQuery</directive> especifica una consulta SQL
    a ejecutar. El propósito de la consulta depende de la
    directiva <directive module="mod_authz_core">Require</directive> en
    vigor.</p>
    <ul>
    <li>Cuando se usa con una directiva <code>Require dbd-group</code>,
    especifica una consulta para buscar los grupos del usuario actual. Esta es
    la funcionalidad estándar de otros módulos de autorización como
    <module>mod_authz_groupfile</module> y <module>mod_authz_dbm</module>.
    El valor de la primera columna de cada fila devuelta por la instrucción de consulta
    debe ser una cadena que contenga un nombre de grupo. Pueden devolverse cero, una
    o más filas.
    <highlight language="config">
Require dbd-group
AuthzDBDQuery "SELECT group FROM groups WHERE user = %s"
</highlight>
    </li>
    <li>Cuando se usa con una directiva <code>Require dbd-login</code> o
    <code>Require dbd-logout</code>, nunca denegará el acceso,
    sino que ejecutará una instrucción SQL diseñada para iniciar o cerrar
    la sesión del usuario. El usuario debe estar ya autenticado con
    <module>mod_authn_dbd</module>.
    <highlight language="config">
Require dbd-login
AuthzDBDQuery "UPDATE authn SET login = 'true' WHERE user = %s"
</highlight>
    </li>
    </ul>
    <p>En todos los casos, el ID del usuario se pasará como único parámetro de tipo cadena
    cuando se ejecute la consulta SQL. Se puede hacer referencia a él dentro de
    la instrucción de consulta usando un especificador de formato <code>%s</code>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthzDBDRedirectQuery</name>
<description>Especifica una consulta para buscar una página de inicio de sesión para el usuario</description>
<syntax>AuthzDBDRedirectQuery <var>query</var></syntax>
<contextlist><context>directory</context></contextlist>

<usage>
    <p>Especifica una consulta SQL opcional que se usa tras un inicio de sesión
    (o cierre de sesión) correcto para redirigir al usuario a una URL, que puede ser
    específica del usuario. El ID del usuario se pasará como único parámetro de tipo cadena
    cuando se ejecute la consulta SQL. Se puede hacer referencia a él dentro de
    la instrucción de consulta usando un especificador de formato <code>%s</code>.</p>
    <highlight language="config">
AuthzDBDRedirectQuery "SELECT userpage FROM userpages WHERE user = %s"
    </highlight>
    <p>El valor de la primera columna de la primera fila devuelta por la instrucción
    de consulta debe ser una cadena que contenga una URL a la que redirigir
    al cliente. Las filas siguientes se ignorarán. Si no se devuelve ninguna fila,
    el cliente no se redirigirá.</p>
    <p>Tenga en cuenta que <directive>AuthzDBDLoginToReferer</directive> tiene
    prioridad si ambas están establecidas.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthzDBDLoginToReferer</name>
<description>Determina si se redirige al cliente a la página de referencia
tras un inicio o cierre de sesión correcto si hay presente una cabecera
de petición <code>Referer</code></description>
<syntax>AuthzDBDLoginToReferer On|Off</syntax>
<default>AuthzDBDLoginToReferer Off</default>
<contextlist><context>directory</context></contextlist>

<usage>
    <p>Junto con <code>Require dbd-login</code> o
    <code>Require dbd-logout</code>, esto ofrece la opción de
    redirigir al cliente de vuelta a la página de referencia (la URL en
    la cabecera de petición HTTP <code>Referer</code>, si está presente).
    Cuando no hay cabecera <code>Referer</code>,
    <code>AuthzDBDLoginToReferer On</code> se ignorará.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
