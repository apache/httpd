<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933751 -->
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

<modulesynopsis metafile="mod_authn_core.xml.meta">

<name>mod_authn_core</name>
<description>Autenticación básica del núcleo</description>
<status>Base</status>
<sourcefile>mod_authn_core.c</sourcefile>
<identifier>authn_core_module</identifier>
<compatibility>Disponible en Apache 2.3 y posteriores</compatibility>

<summary>
    <p>Este módulo proporciona capacidades básicas de autenticación para
    permitir o denegar el acceso a partes del sitio web.
    <module>mod_authn_core</module> proporciona directivas que son
    comunes a todos los proveedores de autenticación.</p>
</summary>

<section id="authnalias"><title>Creación de alias de proveedores de autenticación</title>

    <p>Es posible crear proveedores de autenticación extendidos
    dentro del archivo de configuración y asignarles un nombre de alias. Estos
    proveedores de alias pueden referenciarse después mediante las directivas
    <directive module="mod_auth_basic">AuthBasicProvider</directive> o
    <directive module="mod_auth_digest">AuthDigestProvider</directive> de
    la misma forma que un proveedor de autenticación base. Además de la capacidad
    de crear y poner alias a un proveedor extendido, también permite que el mismo
    proveedor de autenticación extendido sea referenciado por varias
    ubicaciones.</p>

    <section id="example"><title>Ejemplos</title>

        <p>Este ejemplo comprueba las contraseñas en dos archivos
        de texto diferentes.</p>

        <example><title>Comprobar varios archivos de texto de contraseñas</title>
        <highlight language="config">
# Comprobar aquí primero
&lt;AuthnProviderAlias file file1&gt;
    AuthUserFile "/www/conf/passwords1"
&lt;/AuthnProviderAlias&gt;

# Después comprobar aquí
&lt;AuthnProviderAlias file file2&gt;
    AuthUserFile "/www/conf/passwords2"
&lt;/AuthnProviderAlias&gt;

&lt;Directory "/var/web/pages/secure"&gt;
    AuthBasicProvider file1 file2

    AuthType Basic
    AuthName "Protected Area"
    Require valid-user
&lt;/Directory&gt;
        </highlight>
        </example>

        <p>El ejemplo siguiente crea dos alias de proveedores de autenticación
        ldap diferentes basados en el proveedor ldap. Esto permite
        que una única ubicación autenticada sea atendida por varios
        servidores ldap:</p>

        <example><title>Comprobar varios servidores LDAP</title>
        <highlight language="config">
&lt;AuthnProviderAlias ldap ldap-alias1&gt;
    AuthLDAPBindDN "cn=youruser,o=ctx"
    AuthLDAPBindPassword yourpassword
    AuthLDAPURL "ldap://ldap.host/o=ctx"
&lt;/AuthnProviderAlias&gt;
&lt;AuthnProviderAlias ldap ldap-other-alias&gt;
    AuthLDAPBindDN "cn=yourotheruser,o=dev"
    AuthLDAPBindPassword yourotherpassword
    AuthLDAPURL "ldap://other.ldap.host/o=dev?cn"
&lt;/AuthnProviderAlias&gt;

Alias "/secure" "/webpages/secure"
&lt;Directory "/webpages/secure"&gt;
    AuthBasicProvider ldap-other-alias  ldap-alias1

    AuthType Basic
    AuthName "LDAP Protected Place"
    Require valid-user
    # Tenga en cuenta que Require ldap-* no funcionaría aquí, ya que
    # AuthnProviderAlias no proporciona la configuración a los proveedores de autorización
    # que están implementados en el mismo módulo que el proveedor de autenticación.
&lt;/Directory&gt;
          </highlight>
        </example>
    </section>

</section>


<directivesynopsis>
<name>AuthName</name>
<description>Dominio de autorización que se usará en la autenticación
HTTP</description>
<syntax>AuthName <var>auth-domain</var></syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Esta directiva establece el nombre del dominio de autorización de un
    directorio. Este dominio se proporciona al cliente para que el usuario
    sepa qué nombre de usuario y contraseña enviar.
    <directive>AuthName</directive> toma un único argumento; si el
    nombre del dominio contiene espacios, debe ir entre comillas.
    Debe ir acompañado de las directivas <directive
    module="mod_authn_core">AuthType</directive> y <directive
    module="mod_authz_core">Require</directive>, y de directivas como
    <directive module="mod_authn_file">AuthUserFile</directive> y
    <directive module="mod_authz_groupfile">AuthGroupFile</directive> para
    funcionar.</p>

   <p>Por ejemplo:</p>

   <highlight language="config">
     AuthName "Top Secret"
   </highlight>

    <p>La cadena proporcionada en <code>AuthName</code> se mostraba
    históricamente en el diálogo de contraseña que ofrecían los
    navegadores. La mayoría de los navegadores modernos ya no muestran la cadena
    del dominio, ya que podía usarse de forma abusiva para suplantación de identidad
    (phishing). La directiva sigue siendo necesaria para que funcione la autenticación
    HTTP, y el valor del dominio todavía se usa para acotar las
    credenciales.</p>

    <p>Desde la versión 2.5.0, puede usarse la <a href="../expr.html">sintaxis de
    expresiones</a> dentro de la directiva para generar el nombre de forma dinámica.</p>

   <p>Por ejemplo:</p>

   <highlight language="config">
     AuthName "%{HTTP_HOST}"
   </highlight>

</usage>
<seealso><a
    href="../howto/auth.html">Autenticación, autorización y
    control de acceso</a></seealso>
<seealso><module>mod_authz_core</module></seealso>
</directivesynopsis>

<directivesynopsis>
<name>AuthType</name>
<description>Tipo de autenticación de usuario</description>
<syntax>AuthType None|Basic|Digest|Form</syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Esta directiva selecciona el tipo de autenticación de usuario de un
    directorio. Los tipos de autenticación disponibles son <code>None</code>,
    <code>Basic</code> (implementado por
    <module>mod_auth_basic</module>), <code>Digest</code>
    (implementado por <module>mod_auth_digest</module>) y
    <code>Form</code> (implementado por <module>mod_auth_form</module>).</p>

    <p>Para implementar la autenticación, también debe usar las directivas <directive
    module="mod_authn_core">AuthName</directive> y <directive
    module="mod_authz_core">Require</directive>. Además, el
    servidor debe contar con un módulo proveedor de autenticación como
    <module>mod_authn_file</module> y un módulo de autorización como
    <module>mod_authz_user</module>.</p>

    <p>El tipo de autenticación <code>None</code> desactiva la autenticación.
    Cuando la autenticación está activada, normalmente se hereda en cada
    <a href="../sections.html#merging">sección de configuración</a> posterior,
    a menos que se especifique un tipo de autenticación distinto. Si no se
    desea autenticación para una subsección de una sección autenticada,
    puede usarse el tipo de autenticación <code>None</code>;
    en el siguiente ejemplo, los clientes pueden acceder al
    directorio <code>/www/docs/public</code> sin autenticarse:</p>

    <highlight language="config">
&lt;Directory "/www/docs"&gt;
    AuthType Basic
    AuthName Documents
    AuthBasicProvider file
    AuthUserFile "/usr/local/apache/passwd/passwords"
    Require valid-user
&lt;/Directory&gt;

&lt;Directory "/www/docs/public"&gt;
    AuthType None
    Require all granted
&lt;/Directory&gt;
    </highlight>

    <p>Desde la versión 2.5.0, puede usarse la <a href="../expr.html">sintaxis de
    expresiones</a> dentro de la directiva para especificar el tipo de forma dinámica.</p>

    <note>Al desactivar la autenticación, tenga en cuenta que los clientes que ya se
    hayan autenticado contra otra parte del árbol de documentos del servidor
    normalmente seguirán enviando cabeceras HTTP de autenticación
    o cookies con cada petición, independientemente de si el servidor
    realmente requiere autenticación para cada recurso.</note>
</usage>

<seealso><a href="../howto/auth.html">Autenticación, autorización
    y control de acceso</a></seealso>
</directivesynopsis>

<directivesynopsis type="section">
<name>AuthnProviderAlias</name>
<description>Encierra un grupo de directivas que representan una
extensión de un proveedor de autenticación base y que se referencian
mediante el alias indicado</description>
<syntax>&lt;AuthnProviderAlias <var>baseProvider Alias</var>&gt;
... &lt;/AuthnProviderAlias&gt;</syntax>
<contextlist><context>server config</context>
</contextlist>

<usage>
    <p><code>&lt;AuthnProviderAlias&gt;</code> y
    <code>&lt;/AuthnProviderAlias&gt;</code> se usan para encerrar un grupo de
    directivas de autenticación que pueden referenciarse por el nombre de alias
    usando una de las directivas <directive module="mod_auth_basic">
    AuthBasicProvider</directive> o <directive module="mod_auth_digest">
    AuthDigestProvider</directive>.</p>

    <note>Esta directiva no afecta a la autorización, incluso en los módulos que
    proporcionan tanto autenticación como autorización.</note>
</usage>
</directivesynopsis>

</modulesynopsis>
