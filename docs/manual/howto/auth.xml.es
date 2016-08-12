<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- $LastChangedRevision: 1738333 $ -->
<!-- Translated by: Luis Gil de Bernabé Pfeiffer lgilbernabe [AT] apache.org-->
<!-- Reviewed by: Sergio Ramos -->
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

<manualpage metafile="auth.xml.meta">
<parentdocument href="./">How-To / Tutoriales</parentdocument>

<title>Autenticación y Autorización</title>

<summary>
    <p>Autenticación es cualquier proceso por el cuál se verifica que uno es 
    quien dice ser. Autorización es cualquier proceso en el cuál cualquiera
    está permitido a estar donde se quiera, o tener información la cuál se
    quiera tener.
    </p>

    <p>Para información de control de acceso de forma genérica visite<a href="access.html">How to de Control de Acceso</a>.</p>
</summary>

<section id="related"><title>Módulos y Directivas Relacionados</title>

<p>Hay tres tipos de módulos involucrados en los procesos de la autenticación 
	y autorización. Normalmente deberás escoger al menos un módulo de cada grupo.</p>

<ul>
  <li>Modos de Autenticación (consulte la directiva
      <directive module="mod_authn_core">AuthType</directive> )
    <ul>
      <li><module>mod_auth_basic</module></li>
      <li><module>mod_auth_digest</module></li>
    </ul>
  </li>
  <li>Proveedor de Autenticación (consulte la directiva
  <directive module="mod_auth_basic">AuthBasicProvider</directive> y
  <directive module="mod_auth_digest">AuthDigestProvider</directive>)

    <ul>
      <li><module>mod_authn_anon</module></li>
      <li><module>mod_authn_dbd</module></li>
      <li><module>mod_authn_dbm</module></li>
      <li><module>mod_authn_file</module></li>
      <li><module>mod_authnz_ldap</module></li>
      <li><module>mod_authn_socache</module></li>
    </ul>
  </li>
  <li>Autorización (consulte la directiva
      <directive module="mod_authz_core">Require</directive>)
    <ul>
      <li><module>mod_authnz_ldap</module></li>
      <li><module>mod_authz_dbd</module></li>
      <li><module>mod_authz_dbm</module></li>
      <li><module>mod_authz_groupfile</module></li>
      <li><module>mod_authz_host</module></li>
      <li><module>mod_authz_owner</module></li>
      <li><module>mod_authz_user</module></li>
    </ul>
  </li>
</ul>

  <p>A parte de éstos módulos, también están
  <module>mod_authn_core</module> y
  <module>mod_authz_core</module>. Éstos módulos implementan las directivas 
  esenciales que son el centro de todos los módulos de autenticación.</p>

  <p>El módulo <module>mod_authnz_ldap</module> es tanto un proveedor de 
  autenticación como de autorización. El módulo
  <module>mod_authz_host</module> proporciona autorización y control de acceso
  basado en el nombre del Host, la dirección IP o características de la propia
  petición, pero no es parte del sistema proveedor de 
  autenticación. Para tener compatibilidad inversa con el mod_access, 
  hay un nuevo modulo llamado <module>mod_access_compat</module>.</p>

  <p>También puedes mirar el how-to de <a
  href="access.html">Control de Acceso </a>, donde se plantean varias formas del control de acceso al servidor.</p>

</section>

<section id="introduction"><title>Introducción</title>
    <p>Si se tiene información en nuestra página web que sea información 
    	sensible o pensada para un grupo reducido de usuarios/personas,
    	las técnicas que se describen en este manual, le servirán  
    	de ayuda para asegurarse de que las personas que ven esas páginas sean 
    	las personas que uno quiere.</p>

    <p>Este artículo cubre la parte "estándar" de cómo proteger partes de un 
    	sitio web que muchos usarán.</p>

    <note><title>Nota:</title>
    <p>Si de verdad es necesario que tus datos estén en un sitio seguro, 
    	considera usar <module>mod_ssl</module>  como método de autenticación adicional a cualquier forma de autenticación.</p>
    </note>
</section>

<section id="theprerequisites"><title>Los Prerequisitos</title>
    <p>Las directivas que se usan en este artículo necesitaran ponerse ya sea 
    	en el fichero de configuración principal del servidor ( típicamente en 
    	la sección 
    <directive module="core" type="section">Directory</directive> de httpd.conf ), o
    en cada uno de los ficheros de configuraciones del propio directorio
    (los archivos <code>.htaccess</code>).</p>

    <p>Si planea usar los ficheros <code>.htaccess</code> , necesitarás
    tener en la configuración global del servidor, una configuración que permita
    poner directivas de autenticación en estos ficheros. Esto se hace con la
    directiva <directive module="core">AllowOverride</directive>, la cual especifica
    que directivas, en su caso, pueden ser puestas en cada fichero de configuración
    por directorio.</p>

    <p>Ya que estamos hablando aquí de autenticación, necesitarás una directiva 
    	<directive module="core">AllowOverride</directive> como la siguiente:
    	</p>

    <highlight language="config">
AllowOverride AuthConfig
    </highlight>

    <p>O, si solo se van a poner las directivas directamente en la configuración
    	principal del servidor, deberás tener, claro está, permisos de escritura
    	en el archivo. </p>

    <p>Y necesitarás saber un poco de como está estructurado el árbol de 
    	directorios de tu servidor, para poder saber donde se encuentran algunos 
    	archivos. Esto no debería ser una tarea difícil, aún así intentaremos 
    	dejarlo claro llegado el momento de comentar dicho aspecto.</p>

    <p>También deberás de asegurarte de que los módulos 
    <module>mod_authn_core</module> y <module>mod_authz_core</module>
    han sido incorporados, o añadidos a la hora de compilar en tu binario httpd o
    cargados mediante el archivo de configuración <code>httpd.conf</code>. Estos 
    dos módulos proporcionan directivas básicas y funcionalidades que son críticas
    para la configuración y uso de autenticación y autorización en el servidor web.</p>
</section>

<section id="gettingitworking"><title>Conseguir que funcione</title>
    <p>Aquí está lo básico de cómo proteger con contraseña un directorio en tu
     servidor.</p>

    <p>Primero, necesitarás crear un fichero de contraseña. Dependiendo de que 
    	proveedor de autenticación se haya elegido, se hará de una forma u otra. Para empezar, 
    	usaremos un fichero de contraseña de tipo texto.</p>

    <p>Este fichero deberá estar en un sitio que no se pueda tener acceso desde
     la web. Esto también implica que nadie pueda descargarse el fichero de 
     contraseñas. Por ejemplo, si tus documentos están guardados fuera de
     <code>/usr/local/apache/htdocs</code>, querrás poner tu archivo de contraseñas en 
     <code>/usr/local/apache/passwd</code>.</p>

    <p>Para crear el fichero de contraseñas, usa la utilidad 
    	<program>htpasswd</program> que viene con Apache. Esta herramienta se 
    	encuentra en el directorio <code>/bin</code> en donde sea que se ha 
    	instalado el Apache. Si ha instalado Apache desde un paquete de terceros, 
    	puede ser que se encuentre en su ruta de ejecución.</p>

    <p>Para crear el fichero, escribiremos:</p>

    <example>
      htpasswd -c /usr/local/apache/passwd/passwords rbowen
    </example>

    <p><program>htpasswd</program> te preguntará por una contraseña, y después 
    te pedirá que la vuelvas a escribir para confirmarla:</p>

    <example>
      $ htpasswd -c /usr/local/apache/passwd/passwords rbowen<br />
      New password: mypassword<br />
      Re-type new password: mypassword<br />
      Adding password for user rbowen
    </example>

    <p>Si <program>htpasswd</program> no está en tu variable de entorno "path" del 
    sistema, por supuesto deberás escribir la ruta absoluta del ejecutable para 
    poder hacer que se ejecute. En una instalación por defecto, está en:
    <code>/usr/local/apache2/bin/htpasswd</code></p>

    <p>Lo próximo que necesitas, será configurar el servidor para que pida una 
    	contraseña y así decirle al servidor que usuarios están autorizados a acceder.
    	Puedes hacer esto ya sea editando el fichero <code>httpd.conf</code>
    de configuración  o usando in fichero <code>.htaccess</code>. Por ejemplo, 
    si quieres proteger el directorio
    <code>/usr/local/apache/htdocs/secret</code>, puedes usar las siguientes 
    directivas, ya sea en el fichero <code>.htaccess</code> localizado en
    following directives, either placed in the file
    <code>/usr/local/apache/htdocs/secret/.htaccess</code>, o
    en la configuración global del servidor <code>httpd.conf</code> dentro de la
    sección &lt;Directory  
    "/usr/local/apache/htdocs/secret"&gt; section. como se muesta a continuacion:</p>

    <highlight language="config">
&lt;Directory "/usr/local/apache/htdocs/secret"&gt;
AuthType Basic
AuthName "Restricted Files"
# (Following line optional)
AuthBasicProvider file
AuthUserFile "/usr/local/apache/passwd/passwords"
Require user rbowen
&lt;/Directory&gt;
    </highlight>

    <p>Let's examine each of those directives individually. The <directive
    module="mod_authn_core">AuthType</directive> directive selects
    that method that is used to authenticate the user. The most
    common method is <code>Basic</code>, and this is the method
    implemented by <module>mod_auth_basic</module>. It is important to be aware,
    however, that Basic authentication sends the password from the client to
    the server unencrypted. This method should therefore not be used for
    highly sensitive data, unless accompanied by <module>mod_ssl</module>.
    Apache supports one other authentication method:
    <code>AuthType Digest</code>. This method is implemented by <module
    >mod_auth_digest</module> and was intended to be more secure. This is no
    longer the case and the connection should be encrypted with <module
    >mod_ssl</module> instead.</p>

    <p>The <directive module="mod_authn_core">AuthName</directive> directive sets
    the <dfn>Realm</dfn> to be used in the authentication. The realm serves
    two major functions. First, the client often presents this information to
    the user as part of the password dialog box. Second, it is used by the
    client to determine what password to send for a given authenticated
    area.</p>

    <p>So, for example, once a client has authenticated in the
    <code>"Restricted Files"</code> area, it will automatically
    retry the same password for any area on the same server that is
    marked with the <code>"Restricted Files"</code> Realm.
    Therefore, you can prevent a user from being prompted more than
    once for a password by letting multiple restricted areas share
    the same realm. Of course, for security reasons, the client
    will always need to ask again for the password whenever the
    hostname of the server changes.</p>

    <p>The <directive
    module="mod_auth_basic">AuthBasicProvider</directive> is,
    in this case, optional, since <code>file</code> is the default value
    for this directive. You'll need to use this directive if you are
    choosing a different source for authentication, such as
    <module>mod_authn_dbm</module> or <module>mod_authn_dbd</module>.</p>

    <p>The <directive module="mod_authn_file">AuthUserFile</directive>
    directive sets the path to the password file that we just
    created with <program>htpasswd</program>. If you have a large number
    of users, it can be quite slow to search through a plain text
    file to authenticate the user on each request. Apache also has
    the ability to store user information in fast database files.
    The <module>mod_authn_dbm</module> module provides the <directive
    module="mod_authn_dbm">AuthDBMUserFile</directive> directive. These
    files can be created and manipulated with the <program>
    dbmmanage</program> and <program>htdbm</program> programs. Many
    other types of authentication options are available from third
    party modules in the <a
    href="http://modules.apache.org/">Apache Modules
    Database</a>.</p>

    <p>Finally, the <directive module="mod_authz_core">Require</directive>
    directive provides the authorization part of the process by
    setting the user that is allowed to access this region of the
    server. In the next section, we discuss various ways to use the
    <directive module="mod_authz_core">Require</directive> directive.</p>
</section>

<section id="lettingmorethanonepersonin"><title>Letting more than one
person in</title>
    <p>The directives above only let one person (specifically
    someone with a username of <code>rbowen</code>) into the
    directory. In most cases, you'll want to let more than one
    person in. This is where the <directive module="mod_authz_groupfile"
    >AuthGroupFile</directive> comes in.</p>

    <p>If you want to let more than one person in, you'll need to
    create a group file that associates group names with a list of
    users in that group. The format of this file is pretty simple,
    and you can create it with your favorite editor. The contents
    of the file will look like this:</p>

   <example>
     GroupName: rbowen dpitts sungo rshersey
   </example>

    <p>That's just a list of the members of the group in a long
    line separated by spaces.</p>

    <p>To add a user to your already existing password file,
    type:</p>

    <example>
      htpasswd /usr/local/apache/passwd/passwords dpitts
    </example>

    <p>You'll get the same response as before, but it will be
    appended to the existing file, rather than creating a new file.
    (It's the <code>-c</code> that makes it create a new password
    file).</p>

    <p>Now, you need to modify your <code>.htaccess</code> file to
    look like the following:</p>

    <highlight language="config">
AuthType Basic
AuthName "By Invitation Only"
# Optional line:
AuthBasicProvider file
AuthUserFile "/usr/local/apache/passwd/passwords"
AuthGroupFile "/usr/local/apache/passwd/groups"
Require group GroupName
    </highlight>

    <p>Now, anyone that is listed in the group <code>GroupName</code>,
    and has an entry in the <code>password</code> file, will be let in, if
    they type the correct password.</p>

    <p>There's another way to let multiple users in that is less
    specific. Rather than creating a group file, you can just use
    the following directive:</p>

    <highlight language="config">
Require valid-user
    </highlight>

    <p>Using that rather than the <code>Require user rbowen</code>
    line will allow anyone in that is listed in the password file,
    and who correctly enters their password. You can even emulate
    the group behavior here, by just keeping a separate password
    file for each group. The advantage of this approach is that
    Apache only has to check one file, rather than two. The
    disadvantage is that you have to maintain a bunch of password
    files, and remember to reference the right one in the
    <directive module="mod_authn_file">AuthUserFile</directive> directive.</p>
</section>

<section id="possibleproblems"><title>Possible problems</title>
    <p>Because of the way that Basic authentication is specified,
    your username and password must be verified every time you
    request a document from the server. This is even if you're
    reloading the same page, and for every image on the page (if
    they come from a protected directory). As you can imagine, this
    slows things down a little. The amount that it slows things
    down is proportional to the size of the password file, because
    it has to open up that file, and go down the list of users
    until it gets to your name. And it has to do this every time a
    page is loaded.</p>

    <p>A consequence of this is that there's a practical limit to
    how many users you can put in one password file. This limit
    will vary depending on the performance of your particular
    server machine, but you can expect to see slowdowns once you
    get above a few hundred entries, and may wish to consider a
    different authentication method at that time.</p>
</section>

<section id="dbmdbd"><title>Alternate password storage</title>

    <p>Because storing passwords in plain text files has the above
    problems, you may wish to store your passwords somewhere else, such
    as in a database.</p>

    <p><module>mod_authn_dbm</module> and <module>mod_authn_dbd</module> are two
    modules which make this possible. Rather than selecting <code><directive
    module="mod_auth_basic">AuthBasicProvider</directive> file</code>, instead
    you can choose <code>dbm</code> or <code>dbd</code> as your storage
    format.</p>

    <p>To select a dbm file rather than a text file, for example:</p>

    <highlight language="config">
&lt;Directory "/www/docs/private"&gt;
    AuthName "Private"
    AuthType Basic
    AuthBasicProvider dbm
    AuthDBMUserFile "/www/passwords/passwd.dbm"
    Require valid-user
&lt;/Directory&gt;
    </highlight>

    <p>Other options are available. Consult the
    <module>mod_authn_dbm</module> documentation for more details.</p>
</section>

<section id="multprovider"><title>Using multiple providers</title>

    <p>With the introduction of the new provider based authentication and
    authorization architecture, you are no longer locked into a single
    authentication or authorization method. In fact any number of the
    providers can be mixed and matched to provide you with exactly the
    scheme that meets your needs. In the following example, both the
    file and LDAP based authentication providers are being used.</p>

    <highlight language="config">
&lt;Directory "/www/docs/private"&gt;
    AuthName "Private"
    AuthType Basic
    AuthBasicProvider file ldap
    AuthUserFile "/usr/local/apache/passwd/passwords"
    AuthLDAPURL ldap://ldaphost/o=yourorg
    Require valid-user
&lt;/Directory&gt;
    </highlight>

    <p>In this example the file provider will attempt to authenticate
    the user first. If it is unable to authenticate the user, the LDAP
    provider will be called. This allows the scope of authentication
    to be broadened if your organization implements more than
    one type of authentication store. Other authentication and authorization
    scenarios may include mixing one type of authentication with a
    different type of authorization. For example, authenticating against
    a password file yet authorizing against an LDAP directory.</p>

    <p>Just as multiple authentication providers can be implemented, multiple
    authorization methods can also be used. In this example both file group
    authorization as well as LDAP group authorization is being used.</p>

    <highlight language="config">
&lt;Directory "/www/docs/private"&gt;
    AuthName "Private"
    AuthType Basic
    AuthBasicProvider file
    AuthUserFile "/usr/local/apache/passwd/passwords"
    AuthLDAPURL ldap://ldaphost/o=yourorg
    AuthGroupFile "/usr/local/apache/passwd/groups"
    Require group GroupName
    Require ldap-group cn=mygroup,o=yourorg
&lt;/Directory&gt;
    </highlight>

    <p>To take authorization a little further, authorization container
    directives such as
    <directive module="mod_authz_core" type="section">RequireAll</directive>
    and
    <directive module="mod_authz_core" type="section">RequireAny</directive>
    allow logic to be applied so that the order in which authorization
    is handled can be completely controlled through the configuration.
    See <a href="../mod/mod_authz_core.html#logic">Authorization
    Containers</a> for an example of how they may be applied.</p>

</section>

<section id="beyond"><title>Beyond just authorization</title>

    <p>The way that authorization can be applied is now much more flexible
    than just a single check against a single data store. Ordering, logic
    and choosing how authorization will be done is now possible.</p>

    <section id="authandororder"><title>Applying logic and ordering</title>
        <p>Controlling how and in what order authorization will be applied
        has been a bit of a mystery in the past. In Apache 2.2 a provider-based
        authentication mechanism was introduced to decouple the actual
        authentication process from authorization and supporting functionality.
        One of the side benefits was that authentication providers could be
        configured and called in a specific order which didn't depend on the
        load order of the auth module itself. This same provider based mechanism
        has been brought forward into authorization as well. What this means is
        that the <directive module="mod_authz_core">Require</directive> directive
        not only specifies which authorization methods should be used, it also
        specifies the order in which they are called. Multiple authorization
        methods are called in the same order in which the
        <directive module="mod_authz_core">Require</directive> directives
        appear in the configuration.</p>

        <p>With the introduction of authorization container directives
        such as
        <directive module="mod_authz_core" type="section">RequireAll</directive>
        and
        <directive module="mod_authz_core" type="section">RequireAny</directive>,
        the configuration also has control over when the
        authorization methods are called and what criteria determines when
        access is granted.  See
        <a href="../mod/mod_authz_core.html#logic">Authorization Containers</a>
        for an example of how they may be used to express complex
        authorization logic.</p>

        <p>By default all
        <directive module="mod_authz_core">Require</directive>
        directives are handled as though contained within a
        <directive module="mod_authz_core" type="section">RequireAny</directive>
        container directive.  In other words, if
        any of the specified authorization methods succeed, then authorization
        is granted.</p>

    </section>

    <section id="reqaccessctrl"><title>Using authorization providers for access control</title>
        <p>Authentication by username and password is only part of the
        story. Frequently you want to let people in based on something
        other than who they are. Something such as where they are
        coming from.</p>

        <p>The authorization providers <code>all</code>,
        <code>env</code>, <code>host</code> and <code>ip</code> let you
        allow or deny access based on other host based criteria such as
        host name or ip address of the machine requesting a
        document.</p>

        <p>The usage of these providers is specified through the
        <directive module="mod_authz_core">Require</directive> directive.
        This directive registers the authorization providers
        that will be called during the authorization stage of the request
        processing. For example:</p>

        <highlight language="config">
Require ip <var>address</var>
        </highlight>

        <p>where <var>address</var> is an IP address (or a partial IP
        address) or:</p>

        <highlight language="config">
Require host <var>domain_name</var>
        </highlight>

        <p>where <var>domain_name</var> is a fully qualified domain name
        (or a partial domain name); you may provide multiple addresses or
        domain names, if desired.</p>

        <p>For example, if you have someone spamming your message
        board, and you want to keep them out, you could do the
        following:</p>

        <highlight language="config">
&lt;RequireAll&gt;
    Require all granted
    Require not ip 10.252.46.165
&lt;/RequireAll&gt;
        </highlight>

        <p>Visitors coming from that address will not be able to see
        the content covered by this directive. If, instead, you have a
        machine name, rather than an IP address, you can use that.</p>

        <highlight language="config">
&lt;RequireAll&gt;
    Require all granted
    Require not host host.example.com
&lt;/RequireAll&gt;
        </highlight>

        <p>And, if you'd like to block access from an entire domain,
        you can specify just part of an address or domain name:</p>

        <highlight language="config">
&lt;RequireAll&gt;
    Require all granted
    Require not ip 192.168.205
    Require not host phishers.example.com moreidiots.example
    Require not host ke
&lt;/RequireAll&gt;
        </highlight>

        <p>Using <directive module="mod_authz_core" type="section">RequireAll</directive>
        with multiple <directive module="mod_authz_core"
        type="section">Require</directive> directives, each negated with <code>not</code>,
        will only allow access, if all of negated conditions are true. In other words,
        access will be blocked, if any of the negated conditions fails.</p>

    </section>

    <section id="filesystem"><title>Access Control backwards compatibility</title>
        <p>One of the side effects of adopting a provider based mechanism for
        authentication is that the previous access control directives
        <directive module="mod_access_compat">Order</directive>,
        <directive module="mod_access_compat">Allow</directive>,
        <directive module="mod_access_compat">Deny</directive> and
        <directive module="mod_access_compat">Satisfy</directive> are no longer needed.
        However to provide backwards compatibility for older configurations, these
        directives have been moved to the <module>mod_access_compat</module> module.</p>

        <note type="warning"><title>Note</title>
        <p>The directives provided by <module>mod_access_compat</module> have
        been deprecated by <module>mod_authz_host</module>.
        Mixing old directives like <directive
        module="mod_access_compat">Order</directive>, <directive
        module="mod_access_compat">Allow</directive> or <directive
        module="mod_access_compat">Deny</directive> with new ones like
        <directive module="mod_authz_core">Require</directive> is technically possible
        but discouraged. The <module>mod_access_compat</module> module was created to support
        configurations containing only old directives to facilitate the 2.4 upgrade.
        Please check the <a href="../upgrading.html">upgrading</a> guide for more
        information.
        </p>
        </note>
    </section>

</section>

<section id="socache"><title>Authentication Caching</title>
    <p>There may be times when authentication puts an unacceptable load
    on a provider or on your network.  This is most likely to affect users
    of <module>mod_authn_dbd</module> (or third-party/custom providers).
    To deal with this, HTTPD 2.3/2.4 introduces a new caching provider
    <module>mod_authn_socache</module> to cache credentials and reduce
    the load on the origin provider(s).</p>
    <p>This may offer a substantial performance boost to some users.</p>
</section>

<section id="moreinformation"><title>More information</title>
    <p>You should also read the documentation for
    <module>mod_auth_basic</module> and <module>mod_authz_host</module>
    which contain some more information about how this all works.  The
    directive <directive type="section"
    module="mod_authn_core">AuthnProviderAlias</directive> can also help
    in simplifying certain authentication configurations.</p>

    <p>The various ciphers supported by Apache for authentication data are
    explained in <a href="../misc/password_encryptions.html">Password
    Encryptions</a>.</p>

    <p>And you may want to look at the <a href="access.html">Access
    Control</a> howto, which discusses a number of related topics.</p>

</section>

</manualpage>
