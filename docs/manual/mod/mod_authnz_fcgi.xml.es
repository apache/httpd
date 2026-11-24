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

<modulesynopsis metafile="mod_authnz_fcgi.xml.meta">

<name>mod_authnz_fcgi</name>
<description>Permite que una aplicación autorizadora FastCGI gestione
la autenticación y autorización de Apache httpd</description>
<status>Extension</status>
<sourcefile>mod_authnz_fcgi.c</sourcefile>
<identifier>authnz_fcgi_module</identifier>
<compatibility>Disponible en la versión 2.4.10 y posteriores</compatibility>

<summary>
    <p>Este módulo permite que las aplicaciones autorizadoras FastCGI
    autentiquen usuarios y autoricen el acceso a recursos. Admite
    autorizadores FastCGI genéricos que participan en una única fase
    de autenticación y autorización, así como autenticadores y autorizadores
    específicos de Apache httpd que participan en una o ambas
    fases.</p>

    <p>Los autorizadores FastCGI pueden autenticar usando un id de usuario y una contraseña,
    como ocurre con la autenticación básica, o pueden autenticar usando mecanismos
    arbitrarios.</p>
</summary>

<seealso><a href="../howto/auth.html">Autenticación, autorización
y control de acceso</a></seealso>
<seealso><module>mod_auth_basic</module></seealso>
<seealso><program>fcgistarter</program></seealso>
<seealso><module>mod_proxy_fcgi</module></seealso>

<section id="invocations"><title>Modos de invocación</title>

    <p>Los modos de invocación de los autorizadores FastCGI admitidos por este
    módulo se distinguen por dos características, el <em>tipo</em> y el
    <em>mecanismo</em> de autenticación.</p>

    <p>El <em>tipo</em> es simplemente <code>authn</code> para autenticación,
    <code>authz</code> para autorización, o <code>authnz</code> para
    autenticación y autorización combinadas.</p>

    <p>El <em>mecanismo</em> de autenticación se refiere a los mecanismos de
    configuración de Apache httpd y a las fases de procesamiento, y puede ser
    <code>AuthBasicProvider</code>, <code>Require</code>, o
    <code>check_user_id</code>. Los dos primeros
    corresponden a las directivas usadas para activar la participación en la
    fase de procesamiento correspondiente.</p>

    <p>Descripciones de cada modo:</p>

    <dl>
      <dt><em>Tipo</em> <code>authn</code>, <em>mecanismo</em>
      <code>AuthBasicProvider</code></dt>

      <dd>En este modo,
      <code>FCGI_ROLE</code> se establece como <code>AUTHORIZER</code> y
      <code>FCGI_APACHE_ROLE</code> se establece como <code>AUTHENTICATOR</code>.
      La aplicación debe definirse como proveedor de tipo <em>authn</em>
      usando <directive module="mod_authnz_fcgi">
      AuthnzFcgiDefineProvider</directive> y activarse con
      <directive module="mod_auth_basic">AuthBasicProvider</directive>.
      Al invocarse, se espera que la aplicación
      autentique al cliente usando el id de usuario y la contraseña proporcionados.
      Ejemplo de aplicación:

<highlight language="perl">
#!/usr/bin/perl
use FCGI;
my $request = FCGI::Request();
while ($request->Accept() >= 0) {
    die if $ENV{'FCGI_APACHE_ROLE'} ne "AUTHENTICATOR";
    die if $ENV{'FCGI_ROLE'}        ne "AUTHORIZER";
    die if !$ENV{'REMOTE_PASSWD'};
    die if !$ENV{'REMOTE_USER'};

    print STDERR "This text is written to the web server error log.\n";

    if ( ($ENV{'REMOTE_USER' } eq "foo" || $ENV{'REMOTE_USER'} eq "foo1") &amp;&amp;
        $ENV{'REMOTE_PASSWD'} eq "bar" ) {
        print "Status: 200\n";
        print "Variable-AUTHN_1: authn_01\n";
        print "Variable-AUTHN_2: authn_02\n";
        print "\n";
    }
    else {
        print "Status: 401\n\n";
    }
}
</highlight>

      Ejemplo de configuración:
<highlight language="config">
AuthnzFcgiDefineProvider authn FooAuthn fcgi://localhost:10102/
&lt;Location "/protected/"&gt;
  AuthType Basic
  AuthName "Restricted"
  AuthBasicProvider FooAuthn
  Require ...
&lt;/Location&gt;
</highlight>
      </dd>

      <dt><em>Tipo</em> <code>authz</code>, <em>mecanismo</em>
      <code>Require</code></dt>
      <dd>En este modo, <code>FCGI_ROLE</code> se establece como
      <code>AUTHORIZER</code> y <code>FCGI_APACHE_ROLE</code> se establece como
      <code>AUTHORIZER</code>. La aplicación debe definirse como
      proveedor de tipo <em>authz</em> usando <directive module="mod_authnz_fcgi">
      AuthnzFcgiDefineProvider</directive>. Al invocarse, se espera que la aplicación
      autorice al cliente usando el id de usuario proporcionado y otros
      datos de la petición. Ejemplo de aplicación:
<highlight language="perl">
#!/usr/bin/perl
use FCGI;
my $request = FCGI::Request();
while ($request->Accept() >= 0) {
    die if $ENV{'FCGI_APACHE_ROLE'} ne "AUTHORIZER";
    die if $ENV{'FCGI_ROLE'}        ne "AUTHORIZER";
    die if $ENV{'REMOTE_PASSWD'};

    print STDERR "This text is written to the web server error log.\n";

    if ($ENV{'REMOTE_USER'} eq "foo1") {
        print "Status: 200\n";
        print "Variable-AUTHZ_1: authz_01\n";
        print "Variable-AUTHZ_2: authz_02\n";
        print "\n";
    }
    else {
        print "Status: 403\n\n";
    }
}
</highlight>

      Ejemplo de configuración:
<highlight language="config">
AuthnzFcgiDefineProvider authz FooAuthz fcgi://localhost:10103/
&lt;Location "/protected/"&gt;
  AuthType ...
  AuthName ...
  AuthBasicProvider ...
  Require FooAuthz
&lt;/Location&gt;
</highlight>
      </dd>

      <dt><em>Tipo</em> <code>authnz</code>, <em>mecanismo</em>
      <code>AuthBasicProvider</code> <em>+</em> <code>Require</code></dt>

      <dd>En este modo, que admite el protocolo FastCGI
      <code>AUTHORIZER</code>, independiente del servidor web, <code>FCGI_ROLE</code> se establece como
      <code>AUTHORIZER</code> y <code>FCGI_APACHE_ROLE</code> no se establece.
      La aplicación debe definirse como proveedor de tipo <em>authnz</em>
      usando <directive module="mod_authnz_fcgi">
      AuthnzFcgiDefineProvider</directive>. Se espera que la aplicación
      gestione tanto la autenticación como la autorización en la misma invocación
      usando el id de usuario, la contraseña y otros datos de la petición. La invocación
      ocurre durante la fase de autenticación de la API de Apache httpd. Si la
      aplicación devuelve 200 y el mismo proveedor se invoca durante la fase de
      autorización (mediante <directive>Require</directive>), mod_authnz_fcgi
      devolverá éxito para la fase de autorización sin invocar la
      aplicación. Ejemplo de aplicación:
<highlight language="perl">
#!/usr/bin/perl
use FCGI;
my $request = FCGI::Request();
while ($request->Accept() >= 0) {
    die if $ENV{'FCGI_APACHE_ROLE'};
    die if $ENV{'FCGI_ROLE'} ne "AUTHORIZER";
    die if !$ENV{'REMOTE_PASSWD'};
    die if !$ENV{'REMOTE_USER'};

    print STDERR "This text is written to the web server error log.\n";

    if ( ($ENV{'REMOTE_USER' } eq "foo" || $ENV{'REMOTE_USER'} eq "foo1") &amp;&amp;
        $ENV{'REMOTE_PASSWD'} eq "bar" &amp;&amp;
        $ENV{'REQUEST_URI'} =~ m%/bar/.*%) {
        print "Status: 200\n";
        print "Variable-AUTHNZ_1: authnz_01\n";
        print "Variable-AUTHNZ_2: authnz_02\n";
        print "\n";
    }
    else {
        print "Status: 401\n\n";
    }
}
</highlight>

      Ejemplo de configuración:
<highlight language="config">
AuthnzFcgiDefineProvider authnz FooAuthnz fcgi://localhost:10103/
&lt;Location "/protected/"&gt;
  AuthType Basic
  AuthName "Restricted"
  AuthBasicProvider FooAuthnz
  Require FooAuthnz
&lt;/Location&gt;
</highlight>
      </dd>

      <dt><em>Tipo</em> <code>authn</code>, <em>mecanismo</em>
      <code>check_user_id</code></dt>

      <dd>En este modo, <code>FCGI_ROLE</code> se establece como
      <code>AUTHORIZER</code> y <code>FCGI_APACHE_ROLE</code> se establece como
      <code>AUTHENTICATOR</code>. La aplicación debe definirse como
      proveedor de tipo <em>authn</em> usando <directive module="mod_authnz_fcgi">
      AuthnzFcgiDefineProvider</directive>. <directive
      module="mod_authnz_fcgi">AuthnzFcgiCheckAuthnProvider</directive>
      especifica cuándo se invoca. Ejemplo de aplicación:
<highlight language="perl">
#!/usr/bin/perl
use FCGI;
my $request = FCGI::Request();
while ($request->Accept() >= 0) {
    die if $ENV{'FCGI_APACHE_ROLE'} ne "AUTHENTICATOR";
    die if $ENV{'FCGI_ROLE'} ne "AUTHORIZER";

    # This authorizer assumes that the RequireBasicAuth option of
    # AuthnzFcgiCheckAuthnProvider is On:
    die if !$ENV{'REMOTE_PASSWD'};
    die if !$ENV{'REMOTE_USER'};

    print STDERR "This text is written to the web server error log.\n";

    if ( ($ENV{'REMOTE_USER' } eq "foo" || $ENV{'REMOTE_USER'} eq "foo1") &amp;&amp;
        $ENV{'REMOTE_PASSWD'} eq "bar" ) {
        print "Status: 200\n";
        print "Variable-AUTHNZ_1: authnz_01\n";
        print "Variable-AUTHNZ_2: authnz_02\n";
        print "\n";
    }
    else {
        print "Status: 401\n\n";
        # If a response body is written here, it will be returned to
        # the client.
    }
}
</highlight>

      Ejemplo de configuración:
<highlight language="config">
AuthnzFcgiDefineProvider authn FooAuthn fcgi://localhost:10103/
&lt;Location "/protected/"&gt;
  AuthType ...
  AuthName ...
  AuthnzFcgiCheckAuthnProvider FooAuthn \
                               Authoritative On \
                               RequireBasicAuth Off \
                               UserExpr "%{reqenv:REMOTE_USER}"
  Require ...
&lt;/Location&gt;
</highlight>
      </dd>

    </dl>

</section>

<section id="examples"><title>Ejemplos adicionales</title>

  <ol>
    <li>Si su aplicación admite los roles de autenticación y
    autorización por separado (<code>AUTHENTICATOR</code> y <code>AUTHORIZER</code>), defina
    proveedores separados como sigue, aunque se correspondan con la misma
    aplicación:

<highlight language="config">
AuthnzFcgiDefineProvider authn  FooAuthn  fcgi://localhost:10102/
AuthnzFcgiDefineProvider authz  FooAuthz  fcgi://localhost:10102/
</highlight>

    Especifique el proveedor authn en
    <directive module="mod_auth_basic">AuthBasicProvider</directive>
    y el proveedor authz en
    <directive module="mod_authz_core">Require</directive>:

<highlight language="config">
AuthType Basic
AuthName "Restricted"
AuthBasicProvider FooAuthn
Require FooAuthz
</highlight>
    </li>

    <li>Si su aplicación admite el rol genérico <code>AUTHORIZER</code>
    (autenticación y autorización en una sola invocación), defina un
    único proveedor como sigue:

<highlight language="config">
AuthnzFcgiDefineProvider authnz FooAuthnz fcgi://localhost:10103/
</highlight>

    Especifique el proveedor authnz tanto en <directive>AuthBasicProvider</directive>
    como en <directive>Require</directive>:

<highlight language="config">
AuthType Basic
AuthName "Restricted"
AuthBasicProvider FooAuthnz
Require FooAuthnz
</highlight>
    </li>
</ol>
</section>

<section id="limitations"><title>Limitaciones</title>

    <p>Las siguientes son posibles funcionalidades que actualmente no están
    implementadas:</p>

    <dl>
      <dt>Verificador de acceso de Apache httpd</dt>
      <dd>La fase de <em>comprobación de acceso</em> de la API de Apache httpd es una fase
      separada de la autenticación y la autorización. Algunas otras implementaciones de FastCGI
      implementan esta fase, denotada por el establecimiento de
      <code>FCGI_APACHE_ROLE</code> con el valor <code>ACCESS_CHECKER</code>.</dd>

      <dt>Sockets o pipes locales (Unix)</dt>
      <dd>Actualmente solo se admiten sockets TCP.</dd>

      <dt>Compatibilidad con mod_authn_socache</dt>
      <dd>La interacción con mod_authn_socache debería implementarse para
      las aplicaciones que participan en la autenticación al estilo de
      Apache httpd.</dd>

      <dt>Compatibilidad con autenticación digest usando AuthDigestProvider</dt>
      <dd>Se espera que esta sea una limitación permanente, ya que no existe
      un flujo de autorizador para recuperar un hash.</dd>

      <dt>Gestión de procesos de la aplicación</dt>
      <dd>Se espera que esto quede permanentemente fuera del alcance de
      este módulo. Los procesos de la aplicación deben controlarse por
      otros medios. Por ejemplo, se puede usar <program>fcgistarter</program> para
      iniciarlos.</dd>

      <dt>AP_AUTH_INTERNAL_PER_URI</dt>
      <dd>Actualmente todos los proveedores se registran como
      AP_AUTH_INTERNAL_PER_CONF, lo que significa que las comprobaciones no
      se vuelven a realizar para las subpeticiones internas con la misma
      configuración de control de acceso que la petición inicial.</dd>

      <dt>Conversión del juego de caracteres de los datos del protocolo</dt>
      <dd>Si mod_authnz_fcgi se ejecuta en un entorno de compilación
      EBCDIC, todos los datos del protocolo FastCGI se escriben en EBCDIC
      y se espera que se reciban en EBCDIC.</dd>

      <dt>Múltiples peticiones por conexión</dt>
      <dd>Actualmente la conexión con el autorizador FastCGI se
      cierra después de cada fase de procesamiento. Por ejemplo, si el
      autorizador gestiona las fases <em>authn</em> y <em>authz</em>
      por separado, se usarán dos conexiones.</dd>

      <dt>Correspondencia de URIs</dt>
      <dd>Las URIs de los clientes no se pueden asignar, como ocurre con la directiva
      <directive>ProxyPass</directive> usada con los respondedores FastCGI.</dd>

    </dl>

</section>

<section id="logging"><title>Registro</title>

    <ol>
        <li>Los errores de procesamiento se registran en el nivel de registro <code>error</code>
        y superiores.</li>
        <li>Los mensajes escritos por la aplicación se registran en el nivel de registro
        <code>warn</code>.</li>
        <li>Los mensajes generales de depuración se registran en el nivel de registro
        <code>debug</code>.</li>
        <li>Las variables de entorno pasadas a la aplicación se
        registran en el nivel de registro <code>trace2</code>. El valor de la
        variable <code>REMOTE_PASSWD</code> se ocultará,
        pero <strong>cualquier otro dato sensible será visible en el
        registro</strong>.</li>
        <li>Toda la E/S entre el módulo y la aplicación FastCGI,
        incluidas todas las variables de entorno, se registrará en formato imprimible
        y hexadecimal en el nivel de registro <code>trace5</code>. <strong>Todos
        los datos sensibles serán visibles en el registro.</strong></li>
    </ol>

    <p>La directiva <directive module="core">LogLevel</directive> puede usarse
    para configurar un nivel de registro específico para mod_authnz_fcgi. Por
    ejemplo:</p>

<highlight language="config">
LogLevel info authnz_fcgi:trace8
</highlight>

</section>

<directivesynopsis>
<name>AuthnzFcgiDefineProvider</name>
<description>Define una aplicación FastCGI como proveedor de
autenticación y/o autorización</description>
<syntax>AuthnzFcgiDefineProvider <em>type</em> <em>provider-name</em>
<em>backend-address</em></syntax>
<default>none</default>
<contextlist><context>server config</context></contextlist>
<usage>
    <p>Esta directiva se usa para definir una aplicación FastCGI como
    proveedor para una fase concreta de autenticación o
    autorización.</p>

    <dl>
      <dt><em>type</em></dt>
      <dd>Debe establecerse como <em>authn</em> para autenticación,
      <em>authz</em> para autorización, o <em>authnz</em> para
      un autorizador FastCGI genérico que realiza ambas comprobaciones.</dd>

      <dt><em>provider-name</em></dt>
      <dd>Se usa para asignar un nombre al proveedor que se
      usa en otras directivas como
      <directive module="mod_auth_basic">AuthBasicProvider</directive>
      y
      <directive module="mod_authz_core">Require</directive>.</dd>

      <dt><em>backend-address</em></dt>
      <dd>Especifica la dirección de la aplicación, con la forma
      <em>fcgi://hostname:port/</em>. Los procesos de la aplicación
      deben gestionarse de forma independiente, por ejemplo con
      <program>fcgistarter</program>.</dd>
    </dl>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthnzFcgiCheckAuthnProvider</name>
<description>Permite que una aplicación FastCGI gestione el hook de
autenticación check_authn.</description>
<syntax>AuthnzFcgiCheckAuthnProvider <em>provider-name</em>|<code>None</code>
<em>option</em> ...</syntax>
<default>none</default>
<contextlist><context>directory</context></contextlist>
<override>FileInfo</override>
<usage>
    <p>Esta directiva se usa para permitir que un autorizador FastCGI
    gestione una fase de procesamiento concreta de autenticación o
    autorización.</p>

    <p>Algunas capacidades de los autorizadores FastCGI requieren activarse
    usando esta directiva en lugar de
    <directive>AuthBasicProvider</directive>:</p>

    <ul>
      <li>Autenticación no básica; en general, determinar el id de usuario
      del cliente y devolverlo desde el autorizador; vea la opción
      <code>UserExpr</code> más abajo</li>
      <li>Seleccionar un código de respuesta personalizado; para una respuesta
      distinta de 200 del autorizador, el código del autorizador será el
      estado de la respuesta</li>
      <li>Establecer el cuerpo de una respuesta distinta de 200; si el autorizador
      proporciona un cuerpo de respuesta con una respuesta distinta de 200, dicho cuerpo
      se devolverá al cliente; se admiten hasta 8192 bytes de texto</li>
    </ul>

    <dl>
      <dt><em>provider-name</em></dt>
      <dd>Es el nombre de un proveedor definido con <directive>
      AuthnzFcgiDefineProvider</directive>.</dd>

      <dt><code>None</code></dt>
      <dd>Especifique <code>None</code> para desactivar un proveedor activado
      con esta directiva en un ámbito externo, como un directorio
      padre.</dd>

      <dt><em>option</em></dt>
      <dd>Se admiten las siguientes opciones:

      <dl>
         <dt>Authoritative On|Off (por defecto On)</dt>
         <dd>Controla si se permite o no que se ejecuten otros módulos
         cuando este módulo tiene configurado un autorizador FastCGI
         y la petición falla.</dd>

         <dt>DefaultUser <em>userid</em></dt>
         <dd>Cuando el autorizador devuelve éxito y <code>UserExpr</code>
         está configurado y se evalúa como una cadena vacía (p. ej., el autorizador
         no devolvió una variable), este valor se usará como el id de
         usuario. Esto se usa normalmente cuando el autorizador tiene un concepto de
         usuarios invitados o no autenticados, y los usuarios invitados se asignan a
         un id de usuario concreto a efectos de registro y otros fines.</dd>

         <dt>RequireBasicAuth On|Off (por defecto Off)</dt>
         <dd>Controla si se requiere o no autenticación básica
         antes de pasar la petición al autorizador. Si se requiere,
         no se invocará al autorizador sin un id de usuario y una
         contraseña; se devolverá 401 para una petición sin eso.</dd>

         <dt>UserExpr <em>expr</em> (sin valor por defecto)</dt>
         <dd>Cuando el cliente no proporciona autenticación básica
         y el autorizador determina el usuario, esta expresión,
         evaluada después de llamar al autorizador, determina el
         usuario. La expresión sigue la sintaxis
         <a href="../expr.html">ap_expr</a> y debe resolverse en una cadena. Un uso
         típico es referenciar un ajuste <code>Variable-<em>XXX</em></code>
         devuelto por el autorizador usando una opción como
         <code>UserExpr "%{reqenv:<em>XXX</em>}"</code>. Si
         se especifica esta opción y no se puede obtener el id de usuario
         usando la expresión tras una autenticación correcta, la
         petición se rechazará con un error 500.</dd>

       </dl>
      </dd>
     </dl>
</usage>
</directivesynopsis>

</modulesynopsis>
