<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1738333 $ -->
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
    "/usr/local/apache/htdocs/secret"&gt; , como se muestra a continuación:</p>

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

    <p>Vamos a explicar cada una de las directivas individualmente.
    	La directiva <directive
    module="mod_authn_core">AuthType</directive> selecciona el método
    que se usa para autenticar al usuario. El método más común es 
    <code>Basic</code>, y éste es el método que implementa 
    <module>mod_auth_basic</module>. Es muy importante ser consciente,
    de que la autenticación básica, envía las contraseñas desde el cliente 
    al servidor sin cifrar.
    Este método por tanto, no debe ser utilizado para proteger datos muy sensibles,
    a no ser que, este método de autenticación básica, sea acompañado del módulo
    <module>mod_ssl</module>.
    Apache soporta otro método más de autenticación  que es del tipo 
    <code>AuthType Digest</code>. Este método, es implementado por el módulo <module
    >mod_auth_digest</module> y con el se pretendía crear una autenticación más
    segura. Este ya no es el caso, ya que la conexión deberá realizarse con  <module
    >mod_ssl</module> en su lugar.
    </p>

    <p>La directiva <directive module="mod_authn_core">AuthName</directive> 
    establece el <dfn>Realm</dfn> para ser usado en la autenticación. El 
    <dfn>Realm</dfn> tiene dos funciones principales.
    La primera, el cliente presenta a menudo esta información al usuario como 
    parte del cuadro de diálogo de contraseña. La segunda, que es utilizado por 
    el cliente para determinar qué contraseña enviar a para una determinada zona 
    de autenticación.</p>

    <p>Así que, por ejemple, una vez que el cliente se ha autenticado en el área de
    los <code>"Ficheros Restringidos"</code>, entonces re-intentará automáticamente
    la misma contraseña para cualquier área en el mismo servidor que es marcado 
    con el Realm de <code>"Ficheros Restringidos"</code>
    Por lo tanto, puedes prevenir que a un usuario se le pida mas de una vez por su
    contraseña, compartiendo así varias áreas restringidas el mismo Realm
    Por supuesto, por razones de seguridad, el cliente pedirá siempre por una contraseña, 
    siempre y cuando el nombre del servidor cambie.
    </p>

    <p>La directiva <directive
    module="mod_auth_basic">AuthBasicProvider</directive> es,
    en este caso, opcional, ya que <code>file</code> es el valor por defecto
    para esta directiva. Deberás usar esta directiva si estas usando otro medio
    diferente para la autenticación, como por ejemplo
    <module>mod_authn_dbm</module> o <module>mod_authn_dbd</module>.</p>

    <p>La directiva <directive module="mod_authn_file">AuthUserFile</directive>
    establece el path al fichero de contraseñas que acabamos de crear con el 
    comando <program>htpasswd</program>. Si tiene un número muy grande de usuarios, 
    puede ser realmente lento el buscar el usuario en ese fichero de texto plano 
    para autenticar a los usuarios en cada petición.
    Apache también tiene la habilidad de almacenar información de usuarios en 
    unos ficheros de rápido acceso a modo de base de datos.
    El módulo <module>mod_authn_dbm</module> proporciona la directiva <directive
    module="mod_authn_dbm">AuthDBMUserFile</directive>. Estos ficheros pueden ser creados y
    manipulados con el programa <program>dbmmanage</program> y <program>htdbm</program>. 
    Muchos otros métodos de autenticación así como otras opciones, están disponibles en 
    módulos de terceros 
    <a href="http://modules.apache.org/">Base de datos de Módulos disponibles</a>.</p>

    <p>Finalmente, la directiva <directive module="mod_authz_core">Require</directive>
    proporciona la parte del proceso de autorización estableciendo el o los
    usuarios que se les está permitido acceder a una región del servidor.
    En la próxima sección, discutiremos las diferentes vías de utilizar la 
    directiva <directive module="mod_authz_core">Require</directive>.</p>
</section>

<section id="lettingmorethanonepersonin"><title>Dejar que más de una persona 
	entre</title>
    <p>Las directivas mencionadas arriba sólo permiten a una persona 
    (especialmente con un usuario que en ej ejemplo es <code>rbowen</code>) 
    en el directorio. En la mayoría de los casos, se querrá permitir el acceso
    a más de una persona. Aquí es donde la directiva 
    <directive module="mod_authz_groupfile">AuthGroupFile</directive> entra en juego.</p>

    <p>Si lo que se desea es permitir a más de una persona el acceso, necesitarás
     crear un archivo de grupo que asocie los nombres de grupos con el de personas
     para permitirles el acceso. El formato de este fichero es bastante sencillo, 
     y puedes crearlo con tu editor de texto favorito. El contenido del fichero 
     se parecerá a:</p>

   <example>
     GroupName: rbowen dpitts sungo rshersey
   </example>

    <p>Básicamente eso es la lista de miembros los cuales están en un mismo fichero
     de grupo en una sola linea separados por espacios.</p>

    <p>Para añadir un usuario a tu fichero de contraseñas existente teclee:</p>

    <example>
      htpasswd /usr/local/apache/passwd/passwords dpitts
    </example>

    <p>Te responderá lo mismo que anteriormente, pero se añadirá al fichero 
    	existente en vez de crear uno nuevo. (Es decir el flag <code>-c</code> será 
    	el que haga que se genere un nuevo 
    fichero de contraseñas).</p>

    <p>Ahora, tendrá que modificar su fichero <code>.htaccess</code> para que sea 
    parecido a lo siguiente:</p>

    <highlight language="config">
AuthType Basic
AuthName "By Invitation Only"
# Optional line:
AuthBasicProvider file
AuthUserFile "/usr/local/apache/passwd/passwords"
AuthGroupFile "/usr/local/apache/passwd/groups"
Require group GroupName
    </highlight>

    <p>Ahora, cualquiera que esté listado en el grupo <code>GroupName</code>,
    y tiene una entrada en el fichero de <code>contraseñas</code>, se les 
    permitirá el acceso, si introducen su contraseña correctamente.</p>

    <p>Hay otra manera de dejar entrar a varios usuarios, que es menos específica.
    En lugar de crear un archivo de grupo, sólo puede utilizar la siguiente 
    directiva:</p>

    <highlight language="config">
Require valid-user
    </highlight>

    <p>Usando ésto en vez de la línea <code>Require user rbowen</code>
     permitirá a cualquier persona acceder, la cuál aparece en el archivo de 
     contraseñas, y que introduzca correctamente su contraseña. Incluso puede 
     emular el comportamiento del grupo aquí, sólo manteniendo un fichero de 
     contraseñas independiente para cada grupo. La ventaja de este enfoque es 
     que Apache sólo tiene que comprobar un archivo, en lugar de dos. La desventaja 
     es que se tiene que mantener un montón de ficheros de contraseña de grupo, y 
     recuerde hacer referencia al fichero correcto en la directiva
    <directive module="mod_authn_file">AuthUserFile</directive>.</p>
</section>

<section id="possibleproblems"><title>Posibles Problemas</title>
    <p>Debido a la forma en que se especifica la autenticación básica,
    su nombre de usuario y la contraseña deben ser verificados cada vez 
    que se solicita un documento desde el servidor. Esto es, incluso si 
    se  vuelve a cargar la misma página, y para cada imagen de la página (si
    provienen de un directorio protegido). Como se puede imaginar, esto
    ralentiza las cosas un poco. La cantidad que ralentiza las cosas es 
    proporcional al tamaño del archivo de contraseñas, porque tiene que 
    abrir ese archivo, recorrer lista de usuarios hasta que llega a su nombre.
    Y tiene que hacer esto cada vez que se carga una página.</p>

    <p>Una consecuencia de esto, es que hay un limite práctico de cuantos 
    usuarios puedes introducir en el fichero de contraseñas. Este límite
    variará dependiendo de la máquina en la que tengas el servidor,
    pero puedes notar ralentizaciones en cuanto se metan cientos de entradas,
    y por lo tanto consideraremos entonces otro método de autenticación
    en ese momento.
	</p>
</section>

<section id="dbmdbd"><title>Método alternativo de almacenamiento de las 
	contraseñas</title>

    <p>Debido a que el almacenamiento de las contraseñas en texto plano tiene 
    	el problema mencionado anteriormente, puede que se prefiera guardar 
    	las contraseñas en otro lugar como por ejemplo una base de datos.
    	</p>

    <p>Los módulos <module>mod_authn_dbm</module> y <module>mod_authn_dbd</module> son
    dos módulos que hacen esto posible. En vez de seleccionar la directiva de fichero
    <code><directive module="mod_auth_basic">AuthBasicProvider</directive> </code>, en su lugar
    se puede elegir <code>dbm</code> o <code>dbd</code> como formato de almacenamiento.</p>

    <p>Para seleccionar los ficheros de tipo dbm en vez de texto plano, podremos hacer algo parecido a lo siguiente:</p>

    <highlight language="config">
&lt;Directory "/www/docs/private"&gt;
    AuthName "Private"
    AuthType Basic
    AuthBasicProvider dbm
    AuthDBMUserFile "/www/passwords/passwd.dbm"
    Require valid-user
&lt;/Directory&gt;
    </highlight>

    <p>Hay otras opciones disponibles. Consulta la documentación de
    <module>mod_authn_dbm</module> para más detalles.</p>
</section>

<section id="multprovider"><title>Uso de múltiples proveedores</title>

    <p>Con la introducción de la nueva autenticación basada en un proveedor y
     una arquitectura de autorización, ya no estaremos restringidos a un único
     método de autenticación o autorización. De hecho, cualquier número de 
     los proveedores pueden ser mezclados y emparejados para ofrecerle 
     exactamente el esquema que se adapte a sus necesidades. 
     En el siguiente ejemplo, veremos como ambos proveedores tanto el fichero 
     como el LDAP son usados en la autenticación:
     </p>

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

    <p>En este ejemplo el fichero, que actúa como proveedor, intentará autenticar 
    	primero al usuario. Si no puede autenticar al usuario, el proveedor del LDAP
    	será llamado para que realice la autenticación.
    	Esto permite al ámbito de autenticación ser amplio, si su organización 
    	implementa más de un tipo de almacén de autenticación. 
    	Otros escenarios de autenticación y autorización pueden incluir la 
    	mezcla de un tipo de autenticación con un tipo diferente de autorización.
    	Por ejemplo, autenticar contra un fichero de contraseñas pero autorizando
    	dicho acceso mediante el directorio del LDAP.</p>

    <p>Así como múltiples métodos y proveedores de autenticación pueden 
    	ser implementados, también pueden usarse múltiples formas de 
    	autorización.
    	En este ejemplo ambos ficheros de autorización de grupo así como 
    	autorización de grupo mediante LDAP va a ser usado:
    </p>

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

    <p>Para llevar la autorización un poco más lejos, las directivas 
    	de autorización de contenedores tales como
    <directive module="mod_authz_core" type="section">RequireAll</directive>
    and
    <directive module="mod_authz_core" type="section">RequireAny</directive>
    nos permiten aplicar una lógica de en qué orden se manejará la autorización dependiendo
    de la configuración y controlada a través de ella.
    Mire también <a href="../mod/mod_authz_core.html#logic">Contenedores de
    Autorización</a> para ejemplos de cómo pueden ser aplicados.</p>

</section>

<section id="beyond"><title>Más allá de la Autorización</title>

    <p>El modo en que la autorización puede ser aplicada es ahora mucho más flexible
    	que us solo chequeo contra un almacén de datos (contraseñas). Ordenando la 
    	lógica y escoger la forma en que la autorización es realizada, ahora es posible 
    </p>

    <section id="authandororder"><title>Aplicando la lógica y ordenación</title>
        <p>Controlar el cómo y en qué orden se va a aplicar la autorización ha 
        	sido un misterio en el pasado. En Apache 2.2 un proveedior de autenticación
        	C

        	 In Apache 2.2 a provider-based
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
