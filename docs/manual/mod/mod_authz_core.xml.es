<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933739 -->
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

<modulesynopsis metafile="mod_authz_core.xml.meta">

<name>mod_authz_core</name>
<description>Autorización Básica</description>
<status>Base</status>
<sourcefile>mod_authz_core.c</sourcefile>
<identifier>authz_core_module</identifier>
<compatibility>Disponible en Apache HTTPD 2.3 y posteriores</compatibility>

<summary>
    <p>Este módulo proporciona las capacidades básicas de autorización
    para que los usuarios autenticados puedan ser admitidos o rechazados
    en el acceso a partes del sitio web. <module>mod_authz_core</module>
    proporciona la funcionalidad para registrar varios proveedores de
    autorización. Se usa habitualmente junto con un módulo proveedor
    de autenticación, como <module>mod_authn_file</module>, y un módulo
    de autorización, como <module>mod_authz_user</module>. También
    permite aplicar lógica avanzada al procesamiento de la
    autorización.</p>
</summary>

<section id="logic"><title>Contenedores de autorización</title>

    <p>Las directivas contenedoras de autorización
    <directive module="mod_authz_core" type="section">RequireAll</directive>,
    <directive module="mod_authz_core" type="section">RequireAny</directive>
    y
    <directive module="mod_authz_core" type="section">RequireNone</directive>
    pueden combinarse entre sí y con la directiva
    <directive module="mod_authz_core">Require</directive>
    para expresar una lógica de autorización compleja.</p>

    <p>El ejemplo siguiente expresa la siguiente lógica de autorización.
    Para acceder al recurso, el usuario debe ser el usuario
    <code>superadmin</code>, o bien pertenecer tanto al grupo
    <code>admins</code> como al grupo LDAP <code>Administrators</code>, y
    además pertenecer al grupo <code>sales</code> o tener el atributo
    LDAP <code>dept</code> con el valor <code>sales</code>.
    Además, para acceder al recurso, el usuario no debe pertenecer
    ni al grupo <code>temps</code> ni al grupo LDAP
    <code>Temporary Employees</code>.</p>

    <highlight language="config">
&lt;Directory "/www/mydocs"&gt;
    &lt;RequireAll&gt;
        &lt;RequireAny&gt;
            Require user superadmin
            &lt;RequireAll&gt;
                Require group admins
                Require ldap-group "cn=Administrators,o=Airius"
                &lt;RequireAny&gt;
                    Require group sales
                    Require ldap-attribute dept="sales"
                &lt;/RequireAny&gt;
            &lt;/RequireAll&gt;
        &lt;/RequireAny&gt;
        &lt;RequireNone&gt;
            Require group temps
            Require ldap-group "cn=Temporary Employees,o=Airius"
        &lt;/RequireNone&gt;
    &lt;/RequireAll&gt;
&lt;/Directory&gt;
    </highlight>
</section>

<section id="authzresults"><title>Estados del resultado de autorización</title>

    <p>Cada proveedor de autorización devuelve uno de tres posibles
    resultados al evaluar una directiva
    <directive module="mod_authz_core">Require</directive>:</p>

    <dl>
      <dt><strong>Concedido</strong></dt>
      <dd>El proveedor ha verificado que la petición cumple
      sus requisitos.</dd>

      <dt><strong>Denegado</strong></dt>
      <dd>El proveedor ha determinado que la petición no
      cumple sus requisitos.</dd>

      <dt><strong>Neutral</strong></dt>
      <dd>El proveedor no tiene opinión sobre la petición. Esto
      puede ocurrir cuando un proveedor no es relevante para la petición
      (por ejemplo, una comprobación de pertenencia a un grupo cuando la
      petición no implica autorización basada en grupos).</dd>
    </dl>

    <p>Las directivas contenedoras de autorización interpretan estos tres
    resultados de la siguiente manera:</p>

    <table border="1" style="zebra">
    <columnspec><column width=".25"/><column width=".25"/><column width=".25"/><column width=".25"/></columnspec>
    <tr><th>Contenedor</th><th>Concedido si...</th><th>Denegado si...</th><th>Neutral se trata como...</th></tr>
    <tr><td><directive module="mod_authz_core" type="section">RequireAny</directive></td>
        <td>al menos un proveedor concede</td>
        <td>todos los proveedores deniegan</td>
        <td>denegado (no satisface el requisito)</td></tr>
    <tr><td><directive module="mod_authz_core" type="section">RequireAll</directive></td>
        <td>ningún proveedor deniega (y al menos uno concede)</td>
        <td>algún proveedor deniega</td>
        <td>concedido (no bloquea el requisito)</td></tr>
    <tr><td><directive module="mod_authz_core" type="section">RequireNone</directive></td>
        <td>ningún proveedor concede</td>
        <td>algún proveedor concede</td>
        <td>concedido (no bloquea)</td></tr>
    </table>

    <p>Cuando una directiva <directive>Require</directive> se niega con
    <code>not</code> (por ejemplo, <code>Require not group temps</code>),
    un resultado concedido se invierte a denegado y viceversa, pero un
    resultado neutral permanece neutral. Por tanto, una directiva negada
    nunca puede autorizar una petición de manera independiente.</p>

</section>

<section id="requiredirectives"><title>Las directivas Require</title>

  <p><module>mod_authz_core</module> proporciona algunos proveedores de
  autorización genéricos que pueden usarse con la directiva
  <directive module="mod_authz_core">Require</directive>.</p>

  <section id="reqenv"><title>Require env</title>

    <p>El proveedor <code>env</code> permite controlar el acceso al
    servidor en función de la existencia de una <a
    href="../env.html">variable de entorno</a>. Cuando se especifica
    <code>Require env <var>env-variable</var></code>, se concede acceso a
    la petición si la variable de entorno <var>env-variable</var>
    existe. El servidor ofrece la posibilidad de establecer variables de
    entorno de forma flexible en función de las características de la
    petición del cliente mediante las directivas proporcionadas por
    <module>mod_setenvif</module>. Por tanto, esta directiva puede
    usarse para permitir el acceso en función de factores como el
    <code>User-Agent</code> del cliente (tipo de navegador), el
    <code>Referer</code>, u otros campos de cabecera de la petición
    HTTP.</p>

    <highlight language="config">
SetEnvIf User-Agent "^KnockKnock/2\.0" let_me_in
&lt;Directory "/docroot"&gt;
    Require env let_me_in
&lt;/Directory&gt;
    </highlight>

    <p>En este caso, se permitirá el acceso a los navegadores cuya
    cadena user-agent comience con <code>KnockKnock/2.0</code>, y se
    denegará a todos los demás.</p>

    <p>Cuando el servidor busca una ruta mediante una
    <glossary ref="subrequest">subpetición</glossary> interna, como al
    buscar un <directive module="mod_dir" >DirectoryIndex</directive>
    o al generar un listado de directorio con
    <module>mod_autoindex</module>, las variables de entorno de la
    petición <em>no</em> se heredan en la subpetición. Además, las
    directivas <directive module="mod_setenvif">SetEnvIf</directive>
    no se evalúan por separado en la subpetición debido a las fases de
    la API en las que actúa <module>mod_setenvif</module>.</p>

  </section>

  <section id="reqall"><title>Require all</title>

    <p>El proveedor <code>all</code> imita la funcionalidad que
    antes proporcionaban las directivas 'Allow from all' y 'Deny from
    all'. Este proveedor puede tomar uno de dos argumentos, 'granted'
    o 'denied'. Los siguientes ejemplos concederán o denegarán el
    acceso a todas las peticiones.</p>

    <highlight language="config">
    Require all granted
    </highlight>

    <highlight language="config">
    Require all denied
    </highlight>

  </section>

  <section id="reqmethod"><title>Require method</title>

    <p>El proveedor <code>method</code> permite usar el método HTTP en
    las decisiones de autorización. Los métodos GET y HEAD se tratan
    como equivalentes. El método TRACE no está disponible para este
    proveedor; use <directive module="core">TraceEnable</directive> en
    su lugar.</p>

    <p>El siguiente ejemplo solo permitirá peticiones GET, HEAD, POST y
    OPTIONS:</p>

    <highlight language="config">
        Require method GET POST OPTIONS
    </highlight>

    <p>El siguiente ejemplo permitirá peticiones GET, HEAD, POST y
    OPTIONS sin autenticación, y exigirá un usuario válido para
    cualquier otro método:</p>

    <highlight language="config">
&lt;RequireAny&gt;
    &nbsp;Require method GET POST OPTIONS
    &nbsp;Require valid-user
&lt;/RequireAny&gt;
    </highlight>

  </section>

  <section id="reqexpr"><title>Require expr</title>

  <p>El proveedor <code>expr</code> permite basar las decisiones de
  autorización en expresiones arbitrarias.</p>

    <highlight language="config">
        Require expr "%{TIME_HOUR} -ge 9 &amp;&amp; %{TIME_HOUR} -le 17"
    </highlight>

    <highlight language="config">
&lt;RequireAll&gt;
    Require expr "!(%{QUERY_STRING} =~ /secret/)"
    Require expr "%{REQUEST_URI} in { '/example.cgi', '/other.cgi' }"
&lt;/RequireAll&gt;
    </highlight>

    <highlight language="config">
        Require expr "!(%{QUERY_STRING} =~ /secret/) &amp;&amp; %{REQUEST_URI} in { '/example.cgi', '/other.cgi' }"
    </highlight>

  <p>La sintaxis se describe en la documentación de <a href="../expr.html">ap_expr</a>.
  Antes de httpd 2.4.16, las comillas dobles que rodean la expresión
  DEBEN omitirse.</p>

  <p>Normalmente, la expresión se evalúa antes de la autenticación. Sin
  embargo, si la expresión devuelve falso y hace referencia a la
  variable <code>%{REMOTE_USER}</code>, se realizará la autenticación y
  la expresión se volverá a evaluar.</p>

  </section>


</section>



<section id="authzalias"><title>Creación de alias de proveedores de autorización</title>

    <p>Se pueden crear proveedores de autorización ampliados dentro del
    archivo de configuración y asignarles un nombre de alias. Los
    proveedores con alias pueden entonces referenciarse a través de la
    directiva <directive module="mod_authz_core">Require</directive>
    igual que un proveedor de autorización base. Además de permitir
    crear y asignar un alias a un proveedor ampliado, también permite
    que el mismo proveedor de autorización ampliado sea referenciado
    desde varias ubicaciones.
    </p>

    <section id="example"><title>Ejemplo</title>
        <p>El ejemplo siguiente crea dos alias de proveedores de
        autorización ldap distintos basados en el proveedor de
        autorización ldap-group. Este ejemplo permite que una única
        ubicación de autorización compruebe la pertenencia a grupos en
        varios servidores ldap:
        </p>

        <highlight language="config">
&lt;AuthzProviderAlias ldap-group ldap-group-alias1 "cn=my-group,o=ctx"&gt;
    AuthLDAPBindDN "cn=youruser,o=ctx"
    AuthLDAPBindPassword yourpassword
    AuthLDAPUrl "ldap://ldap.host/o=ctx"
&lt;/AuthzProviderAlias&gt;

&lt;AuthzProviderAlias ldap-group ldap-group-alias2 "cn=my-other-group,o=dev"&gt;
    AuthLDAPBindDN "cn=yourotheruser,o=dev"
    AuthLDAPBindPassword yourotherpassword
    AuthLDAPUrl "ldap://other.ldap.host/o=dev?cn"
&lt;/AuthzProviderAlias&gt;

Alias "/secure" "/webpages/secure"
&lt;Directory "/webpages/secure"&gt;
    AuthType Basic
    AuthName "LDAP Protected"
    AuthBasicProvider ldap
    AuthLDAPUrl "ldap://ldap.host/o=ctx"

    #operación OR implícita
    Require ldap-group-alias1
    Require ldap-group-alias2
&lt;/Directory&gt;
        </highlight>
    </section>

</section>




<directivesynopsis>
<name>Require</name>
<description>Comprueba si un usuario autenticado está autorizado por
un proveedor de autorización.</description>
<syntax>Require [not] <var>entity-name</var>
    [<var>entity-name</var>] ...</syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Esta directiva comprueba si un usuario autenticado está
    autorizado de acuerdo con un proveedor de autorización concreto y
    las restricciones especificadas. <module>mod_authz_core</module>
    proporciona los siguientes proveedores de autorización
    genéricos:</p>

    <dl>
      <dt><code>Require all granted</code></dt>
      <dd>Se permite el acceso incondicionalmente.</dd>

      <dt><code>Require all denied</code></dt>
      <dd>Se deniega el acceso incondicionalmente.</dd>

      <dt><code>Require env <var>env-var</var> [<var>env-var</var>]
      ...</code></dt>
      <dd>Se permite el acceso solo si alguna de las variables de
          entorno indicadas está definida.</dd>

      <dt><code>Require method <var>http-method</var> [<var>http-method</var>]
      ...</code></dt>
      <dd>Se permite el acceso solo para los métodos HTTP indicados.</dd>

      <dt><code>Require expr <var>expression</var> </code></dt>
      <dd>Se permite el acceso si <var>expression</var> evalúa a
      verdadero.</dd>
    </dl>

    <p>Algunas de las sintaxis permitidas que proporcionan
       <module>mod_authz_user</module>,
       <module>mod_authz_host</module>,
       y <module>mod_authz_groupfile</module> son:</p>

    <dl>
      <dt><code>Require user <var>userid</var> [<var>userid</var>]
      ...</code></dt>
      <dd>Solo los usuarios indicados pueden acceder al recurso.</dd>

      <dt><code>Require group <var>group-name</var> [<var>group-name</var>]
      ...</code></dt>
      <dd>Solo los usuarios de los grupos indicados pueden acceder al
      recurso.</dd>

      <dt><code>Require valid-user</code></dt>
      <dd>Todos los usuarios válidos pueden acceder al recurso.</dd>

      <dt><code>Require ip 10 172.20 192.168.2</code></dt>
      <dd>Los clientes dentro de los rangos de direcciones IP
      indicados pueden acceder al recurso.</dd>

      <dt><code>Require forward-dns dynamic.example.org</code></dt>
      <dd>A un cliente cuya IP se resuelva a partir del nombre
      dynamic.example.org se le concederá acceso.
      </dd>

    </dl>

    <p>Otros módulos de autorización que implementan opciones require
    son <module>mod_authnz_ldap</module>,
    <module>mod_authz_dbm</module>, <module>mod_authz_dbd</module>,
    <module>mod_authz_owner</module> y <module>mod_ssl</module>.</p>

    <p>En la mayoría de los casos, para una configuración completa de
    autenticación y autorización, <directive>Require</directive> debe
    ir acompañada de las directivas <directive
    module="mod_authn_core">AuthName</directive>, <directive
    module="mod_authn_core">AuthType</directive> y
    <directive module="mod_auth_basic">AuthBasicProvider</directive> o
    <directive module="mod_auth_digest">AuthDigestProvider</directive>,
    y de directivas como
    <directive module="mod_authn_file">AuthUserFile</directive>
    y <directive module="mod_authz_groupfile">AuthGroupFile</directive>
    (para definir usuarios y grupos) para funcionar correctamente.
    Ejemplo:</p>

    <highlight language="config">
AuthType Basic
AuthName "Restricted Resource"
AuthBasicProvider file
AuthUserFile "/web/users"
AuthGroupFile "/web/groups"
Require group admin
    </highlight>

    <p>Los controles de acceso aplicados de esta manera son efectivos
    para <strong>todos</strong> los métodos. <strong>Esto es lo que
    normalmente se desea.</strong> Si desea aplicar controles de
    acceso solo a métodos concretos, dejando el resto de métodos sin
    proteger, coloque la instrucción <directive>Require</directive>
    dentro de una sección
    <directive module="core" type="section">Limit</directive>.</p>

    <p>El resultado de la directiva <directive>Require</directive>
    puede negarse mediante la opción
    <code>not</code>. Igual que con la otra directiva de autorización
    negada <directive type="section">RequireNone</directive>,
    cuando se niega la directiva <directive>Require</directive> solo
    puede fallar o devolver un resultado neutral, por lo que nunca
    puede autorizar una petición de manera independiente.</p>

    <p>En el siguiente ejemplo, todos los usuarios de los grupos
    <code>alpha</code> y <code>beta</code> están autorizados, excepto
    los que también pertenecen al grupo <code>reject</code>.</p>

    <highlight language="config">
&lt;Directory "/www/docs"&gt;
    &lt;RequireAll&gt;
        Require group alpha beta
        Require not group reject
    &lt;/RequireAll&gt;
&lt;/Directory&gt;
    </highlight>

    <p>Cuando se usan varias directivas <directive>Require</directive>
    en una misma
    <a href="../sections.html#merging">sección de configuración</a>
    y no están contenidas en otra directiva de autorización como
    <directive module="mod_authz_core" type="section">RequireAll</directive>,
    quedan contenidas implícitamente en una directiva
    <directive module="mod_authz_core" type="section">RequireAny</directive>.
    Así, la primera que autorice a un usuario autoriza toda la
    petición, y las directivas <directive>Require</directive>
    posteriores se ignoran.</p>

    <note type="warning"><title>Advertencia de seguridad</title>
    <p>Tenga cuidado al establecer directivas de autorización en
    secciones <directive module="core">Location</directive>
    que se superpongan con contenido servido desde el sistema de
    archivos. Por defecto, estas <a href="../sections.html#merging"
    >secciones de configuración</a> sobrescriben la configuración de
    autorización en las secciones <directive module="core">Directory</directive>
    y <directive module="core">Files</directive>.</p>
    <p>La directiva <directive module="mod_authz_core">AuthMerging</directive>
    puede usarse para controlar cómo se combinan las secciones de
    configuración de autorización.</p>
    </note>
</usage>

<seealso><a href="../howto/access.html">Howto de control de acceso</a></seealso>
<seealso><a href="#logic">Contenedores de autorización</a></seealso>
<seealso><a href="#authzresults">Estados del resultado de autorización</a></seealso>
<seealso><module>mod_authn_core</module></seealso>
<seealso><module>mod_authz_host</module></seealso>
</directivesynopsis>

<directivesynopsis type="section">
<name>RequireAll</name>
<description>Encierra un grupo de directivas de autorización, de las
cuales ninguna debe fallar y al menos una debe tener éxito para que la
directiva contenedora tenga éxito.</description>
<syntax>&lt;RequireAll&gt; ... &lt;/RequireAll&gt;</syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p><directive type="section">RequireAll</directive> y
    <code>&lt;/RequireAll&gt;</code> se usan para encerrar un grupo de
    directivas de autorización, de las cuales ninguna debe fallar y al
    menos una debe tener éxito para que la directiva
    <directive type="section">RequireAll</directive> tenga éxito.</p>

    <p>Si ninguna de las directivas contenidas dentro de la directiva
    <directive type="section">RequireAll</directive> falla, y al menos
    una tiene éxito, entonces la directiva
    <directive type="section">RequireAll</directive> tiene éxito. Si
    ninguna tiene éxito y ninguna falla, devuelve un resultado neutral.
    En cualquier otro caso, falla.</p>
</usage>

<seealso><a href="#logic">Contenedores de autorización</a></seealso>
<seealso><a href="#authzresults">Estados del resultado de autorización</a></seealso>
<seealso><a href="../howto/auth.html">Autenticación, autorización
    y control de acceso</a></seealso>

</directivesynopsis>

<directivesynopsis type="section">
<name>RequireAny</name>
<description>Encierra un grupo de directivas de autorización, de las
cuales una debe tener éxito para que la directiva contenedora tenga
éxito.</description>
<syntax>&lt;RequireAny&gt; ... &lt;/RequireAny&gt;</syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p><directive type="section">RequireAny</directive> y
    <code>&lt;/RequireAny&gt;</code> se usan para encerrar un grupo de
    directivas de autorización, de las cuales una debe tener éxito para
    que la directiva <directive type="section">RequireAny</directive>
    tenga éxito.</p>

    <p>Si una o más de las directivas contenidas dentro de la directiva
    <directive type="section">RequireAny</directive> tienen éxito,
    entonces la directiva <directive type="section">RequireAny</directive>
    tiene éxito. Si ninguna tiene éxito y ninguna falla, devuelve un
    resultado neutral. En cualquier otro caso, falla.</p>

    <note>Dado que las directivas de autorización negadas no pueden
    devolver un resultado de éxito, no pueden influir de forma
    significativa en el resultado de una directiva
    <directive type="section">RequireAny</directive>. (Como mucho
    podrían hacer que la directiva fallara en el caso de que fallasen y
    todas las demás directivas devolvieran un valor neutral.) Por
    tanto, las directivas de autorización negadas no están permitidas
    dentro de una directiva <directive type="section">RequireAny</directive>.</note>
</usage>

<seealso><a href="#logic">Contenedores de autorización</a></seealso>
<seealso><a href="#authzresults">Estados del resultado de autorización</a></seealso>
<seealso><a href="../howto/auth.html">Autenticación, autorización
    y control de acceso</a></seealso>

</directivesynopsis>

<directivesynopsis type="section">
<name>RequireNone</name>
<description>Encierra un grupo de directivas de autorización, de las
cuales ninguna debe tener éxito para que la directiva contenedora no
falle.</description>
<syntax>&lt;RequireNone&gt; ... &lt;/RequireNone&gt;</syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p><directive type="section">RequireNone</directive> y
    <code>&lt;/RequireNone&gt;</code> se usan para encerrar un grupo de
    directivas de autorización, de las cuales ninguna debe tener éxito
    para que la directiva
    <directive type="section">RequireNone</directive> no falle.</p>

    <p>Si una o más de las directivas contenidas dentro de la directiva
    <directive type="section">RequireNone</directive> tienen éxito,
    entonces la directiva <directive type="section">RequireNone</directive>
    falla. En cualquier otro caso, devuelve un resultado neutral. Así,
    igual que con la otra directiva de autorización negada
    <code>Require not</code>, nunca puede autorizar una petición de
    manera independiente, porque nunca puede devolver un resultado de
    éxito. Sin embargo, puede usarse para restringir el conjunto de
    usuarios autorizados a acceder a un recurso.</p>

    <note>Dado que las directivas de autorización negadas no pueden
    devolver un resultado de éxito, no pueden influir de forma
    significativa en el resultado de una directiva
    <directive type="section">RequireNone</directive>. Por tanto, las
    directivas de autorización negadas no están permitidas dentro de
    una directiva
    <directive type="section">RequireNone</directive>.</note>
</usage>

<seealso><a href="#logic">Contenedores de autorización</a></seealso>
<seealso><a href="#authzresults">Estados del resultado de autorización</a></seealso>
<seealso><a href="../howto/auth.html">Autenticación, autorización
    y control de acceso</a></seealso>

</directivesynopsis>

<directivesynopsis>
<name>AuthMerging</name>
<description>Controla la manera en que la lógica de autorización de
cada sección de configuración se combina con la de las secciones de
configuración precedentes.</description>
<syntax>AuthMerging Off | And | Or</syntax>
<default>AuthMerging Off</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Cuando la autorización está activada, normalmente se hereda en
    cada <a href="../sections.html#merging">sección de configuración</a>
    siguiente, a menos que se especifique un conjunto diferente de
    directivas de autorización. Esta es la acción por defecto, que
    corresponde a establecer explícitamente
    <code>AuthMerging Off</code>.</p>

    <p>Sin embargo, puede haber circunstancias en las que sea deseable
    que la autorización de una sección de configuración se combine con
    la de su predecesora mientras se fusionan las secciones de
    configuración. Hay dos opciones disponibles para este caso,
    <code>And</code> y <code>Or</code>.</p>

    <p>Cuando una sección de configuración contiene
    <code>AuthMerging And</code> o <code>AuthMerging Or</code>, su
    lógica de autorización se combina con la de la predecesora más
    cercana (según el orden general de las secciones de configuración)
    que también contenga lógica de autorización, como si ambas
    secciones estuvieran contenidas conjuntamente dentro de una
    directiva
    <directive module="mod_authz_core" type="section">RequireAll</directive>
    o
    <directive module="mod_authz_core" type="section">RequireAny</directive>,
    respectivamente.</p>

    <note>El valor de <directive>AuthMerging</directive> no se hereda
    fuera de la sección de configuración en la que aparece. En el
    siguiente ejemplo, solo los usuarios que pertenecen al grupo
    <code>alpha</code> pueden acceder a <code>/www/docs</code>. Los
    usuarios que pertenecen a los grupos <code>alpha</code> o
    <code>beta</code> pueden acceder a <code>/www/docs/ab</code>. Sin
    embargo, el valor por defecto <code>Off</code> de
    <directive>AuthMerging</directive> se aplica a la sección de
    configuración <directive type="section" module="core">Directory</directive>
    para <code>/www/docs/ab/gamma</code>, por lo que las directivas de
    autorización de esa sección sobrescriben las de las secciones
    precedentes. Así, solo los usuarios que pertenecen al grupo
    <code>gamma</code> pueden acceder a
    <code>/www/docs/ab/gamma</code>.</note>

    <highlight language="config">
&lt;Directory "/www/docs"&gt;
    AuthType Basic
    AuthName Documents
    AuthBasicProvider file
    AuthUserFile "/usr/local/apache/passwd/passwords"
    Require group alpha
&lt;/Directory&gt;

&lt;Directory "/www/docs/ab"&gt;
    AuthMerging Or
    Require group beta
&lt;/Directory&gt;

&lt;Directory "/www/docs/ab/gamma"&gt;
    Require group gamma
&lt;/Directory&gt;
    </highlight>
</usage>

</directivesynopsis>

<directivesynopsis type="section">
<name>AuthzProviderAlias</name>
<description>Encierra un grupo de directivas que representan una
extensión de un proveedor de autorización base y que se referencia
mediante el alias indicado</description>
<syntax>&lt;AuthzProviderAlias <var>baseProvider Alias Require-Parameters</var>&gt;
... &lt;/AuthzProviderAlias&gt;
</syntax>
<contextlist><context>server config</context>
</contextlist>

<usage>
    <p><directive type="section">AuthzProviderAlias</directive> y
    <code>&lt;/AuthzProviderAlias&gt;</code> se usan para encerrar un
    grupo de directivas de autorización que pueden referenciarse por
    el nombre del alias mediante la directiva
    <directive module="mod_authz_core">Require</directive>.</p>

    <p>Si se necesitan varios parámetros en <var>Require-Parameters</var>,
    deben encerrarse entre comillas. De lo contrario, solo se tendrá
    en cuenta el primero.</p>

    <highlight language="config">
# En este ejemplo, para que se tengan en cuenta ambas direcciones, DEBEN
# encerrarse entre comillas
&lt;AuthzProviderAlias ip reject-ips "XXX.XXX.XXX.XXX YYY.YYY.YYY.YYY"&gt;
&lt;/AuthzProviderAlias&gt;

&lt;Directory "/path/to/dir"&gt;
    &lt;RequireAll&gt;
        Require not reject-ips
        Require all granted
    &lt;/RequireAll&gt;
&lt;/Directory&gt;
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthzSendForbiddenOnFailure</name>
<description>Envía '403 FORBIDDEN' en lugar de '401 UNAUTHORIZED' si la
autenticación tiene éxito pero la autorización falla
</description>
<syntax>AuthzSendForbiddenOnFailure On|Off</syntax>
<default>AuthzSendForbiddenOnFailure Off</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>
<compatibility>Disponible en Apache HTTPD 2.3.11 y posteriores</compatibility>

<usage>
    <p>Si la autenticación tiene éxito pero la autorización falla,
    Apache HTTPD responderá por defecto con un código de respuesta
    HTTP '401 UNAUTHORIZED'. Esto normalmente hace que los navegadores
    vuelvan a mostrar al usuario el cuadro de diálogo de contraseña,
    lo cual no se desea en todas las situaciones.
    <directive>AuthzSendForbiddenOnFailure</directive> permite cambiar
    el código de respuesta a '403 FORBIDDEN'.</p>

    <note type="warning"><title>Advertencia de seguridad</title>
    <p>Modificar la respuesta en caso de falta de autorización debilita
    la seguridad de la contraseña, porque revela a un posible atacante
    que la contraseña que intentó adivinar era correcta.</p>
    </note>
</usage>
</directivesynopsis>


</modulesynopsis>
