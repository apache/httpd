<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1673563 -->
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

<modulesynopsis metafile="mod_authn_anon.xml.meta">

<name>mod_authn_anon</name>
<description>Permite el acceso de usuarios "anónimos" a áreas
    autenticadas</description>
<status>Extension</status>
<sourcefile>mod_authn_anon.c</sourcefile>
<identifier>authn_anon_module</identifier>
<compatibility>Disponible en Apache 2.1 y posteriores</compatibility>

<summary>
    <p>Este módulo proporciona a los frontales de autenticación, como
    <module>mod_auth_basic</module>, la capacidad de autenticar usuarios de
    forma similar a los sitios ftp anónimos, <em>es decir</em>, usar un id
    de usuario 'mágico' 'anonymous' y la dirección de correo electrónico
    como contraseña. Estas direcciones de correo pueden registrarse en el
    log.</p>

    <p>Combinado con otros métodos de control de acceso (basados en bases
    de datos), esto permite un seguimiento eficaz de los usuarios y una
    personalización según el perfil del usuario, manteniendo a la vez el
    sitio abierto para usuarios 'no registrados'. Una ventaja de usar el
    seguimiento de usuarios basado en Auth es que, a diferencia de las
    cookies mágicas y de los prefijos/sufijos extraños en las URL, es
    completamente independiente del navegador y permite a los usuarios
    compartir URL.</p>

    <p>Cuando se usa <module>mod_auth_basic</module>, este módulo se invoca
    mediante la directiva <directive module="mod_auth_basic"
    >AuthBasicProvider</directive> con el valor <code>anon</code>.</p>
</summary>

<section id="example"><title>Ejemplo</title>
    <p>El siguiente ejemplo se combina con la autenticación "normal"
    basada en archivo htpasswd y permite además la entrada de usuarios como
    'invitados' con las siguientes propiedades:</p>

    <ul>
      <li>Exige que el usuario introduzca un userID.
      (<directive module="mod_authn_anon"
      >Anonymous_NoUserID</directive>)</li>

      <li>Exige que el usuario introduzca una contraseña.
      (<directive module="mod_authn_anon"
      >Anonymous_MustGiveEmail</directive>)</li>

      <li>La contraseña introducida debe ser una dirección de correo
      electrónico válida, <em>es decir</em>, contener al menos un '@' y un
      '.'.
      (<directive module="mod_authn_anon"
      >Anonymous_VerifyEmail</directive>)</li>

      <li>El userID debe ser uno de <code>anonymous guest www test
      welcome</code> y la comparación <strong>no</strong> distingue entre
      mayúsculas y minúsculas. (<directive module="mod_authn_anon"
      >Anonymous</directive>)</li>

      <li>Y las direcciones de correo introducidas en el campo passwd se
      registran en el archivo de log de errores.
      (<directive module="mod_authn_anon"
      >Anonymous_LogEmail</directive>)</li>
    </ul>

    <example><title>Ejemplo</title>
    <highlight language="config">
&lt;Directory "/var/www/html/private"&gt;
    AuthName "Use 'anonymous' &amp; Email address for guest entry"
    AuthType Basic
    AuthBasicProvider file anon
    AuthUserFile "/path/to/your/.htpasswd"

    Anonymous_NoUserID off
    Anonymous_MustGiveEmail on
    Anonymous_VerifyEmail on
    Anonymous_LogEmail on
    Anonymous anonymous guest www test welcome

    Require valid-user
&lt;/Directory&gt;
      </highlight>
    </example>
</section>

<directivesynopsis>
<name>Anonymous</name>
<description>Especifica los userIDs a los que se les permite el acceso sin
verificación de contraseña</description>
<syntax>Anonymous <var>user</var> [<var>user</var>] ...</syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Una lista de uno o más userIDs 'mágicos' a los que se les permite el
    acceso sin verificación de contraseña. Los userIDs se separan con
    espacios. Es posible usar las comillas ' y " para permitir un espacio
    en un userID, así como el carácter de escape \.</p>

    <p>Tenga en cuenta que la comparación
    <strong>NO distingue</strong> entre mayúsculas y minúsculas.<br />
    Se recomienda encarecidamente que el nombre de usuario mágico
    '<code>anonymous</code>' esté siempre entre los userIDs
    permitidos.</p>

    <example><title>Ejemplo:</title>
    <highlight language="config">
      Anonymous anonymous "Not Registered" "I don't know"
    </highlight>
    </example>

    <p>Esto permitiría al usuario entrar sin verificación de contraseña
    usando los userIDs "anonymous", "AnonyMous", "Not Registered" e
    "I Don't Know".</p>

    <p>Desde Apache 2.1 es posible especificar el userID como
    "<code>*</code>". Eso permite aceptar <em>cualquier</em> userID
    proporcionado.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>Anonymous_LogEmail</name>
<description>Establece si la contraseña introducida se registrará en el
log de errores</description>
<syntax>Anonymous_LogEmail On|Off</syntax>
<default>Anonymous_LogEmail On</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Cuando se establece a <code>On</code>, el valor por defecto, la
    'contraseña' introducida (que se espera que contenga una dirección de
    correo electrónico razonable) se registra en el log de errores.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>Anonymous_MustGiveEmail</name>
<description>Especifica si se permiten contraseñas en blanco</description>
<syntax>Anonymous_MustGiveEmail On|Off</syntax>
<default>Anonymous_MustGiveEmail On</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Especifica si el usuario debe indicar una dirección de correo
    electrónico como contraseña. Esto prohíbe las contraseñas en
    blanco.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>Anonymous_NoUserID</name>
<description>Establece si el campo userID puede estar vacío</description>
<syntax>Anonymous_NoUserID On|Off</syntax>
<default>Anonymous_NoUserID Off</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Cuando se establece a <code>On</code>, los usuarios pueden dejar el
    userID (y quizá también el campo de la contraseña) vacío. Esto puede
    resultar muy conveniente para los usuarios de MS-Explorer, que
    simplemente pueden pulsar intro o hacer clic directamente en el botón
    Aceptar, lo cual parece una reacción natural.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>Anonymous_VerifyEmail</name>
<description>Establece si se debe comprobar que el campo de la contraseña
contiene una dirección de correo electrónico con el formato correcto</description>
<syntax>Anonymous_VerifyEmail On|Off</syntax>
<default>Anonymous_VerifyEmail Off</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Cuando se establece a <code>On</code>, se comprueba que la
    'contraseña' introducida contenga al menos un '@' y un '.', para
    animar a los usuarios a introducir direcciones de correo electrónico
    válidas (véase la directiva anterior <directive
    module="mod_authn_anon">Anonymous_LogEmail</directive>).</p>
</usage>
</directivesynopsis>

</modulesynopsis>
