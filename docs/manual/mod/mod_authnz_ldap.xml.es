<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- $LastChangedRevision$ -->
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

<modulesynopsis metafile="mod_authnz_ldap.xml.meta">

<name>mod_authnz_ldap</name>
<description>Permite usar un directorio LDAP para almacenar la base de datos
para la autenticación HTTP Basic.</description>
<status>Extension</status>
<sourcefile>mod_authnz_ldap.c</sourcefile>
<identifier>authnz_ldap_module</identifier>

<summary>
    <p>Este módulo permite que front-ends de autenticación como
    <module>mod_auth_basic</module> autentiquen usuarios a través de
    un directorio ldap.</p>

    <p><module>mod_authnz_ldap</module> soporta las siguientes
    características:</p>

    <ul>
      <li>Se sabe que soporta el <a
      href="http://www.openldap.org/">SDK de OpenLDAP</a> (tanto 1.x
      como 2.x).</li>

      <li>Se pueden implementar políticas de autorización complejas
      representando la política con filtros LDAP.</li>

      <li>Usa un amplio sistema de caché de las operaciones LDAP a través
      de <a href="mod_ldap.html">mod_ldap</a>.</li>

      <li>Soporte para LDAP sobre SSL/TLS (requiere el SDK de OpenLDAP
      2.x).</li>
    </ul>

    <p>Cuando se usa <module>mod_auth_basic</module>, este módulo se invoca
    mediante la directiva <directive module="mod_auth_basic"
    >AuthBasicProvider</directive> con el valor <code>ldap</code>.</p>
</summary>

<seealso><module>mod_ldap</module></seealso>
<seealso><module>mod_auth_basic</module></seealso>
<seealso><module>mod_authz_user</module></seealso>
<seealso><module>mod_authz_groupfile</module></seealso>

<section id="contents"><title>Contenidos</title>

    <ul>
      <li> <a href="#gcaveats">Advertencias generales</a> </li>
      <li> <a href="#operation">Funcionamiento</a>

        <ul>
          <li><a href="#authenphase">La Fase de
          Autenticación</a></li>

          <li><a href="#authorphase">La Fase de
          Autorización</a></li>
        </ul>
      </li>

      <li>
        <a href="#requiredirectives">Las Directivas Require</a>

        <ul>
          <li><a href="#requser">Require ldap-user</a></li>
          <li><a href="#reqgroup">Require ldap-group</a></li>
          <li><a href="#reqdn">Require ldap-dn</a></li>
          <li><a href="#reqattribute">Require ldap-attribute</a></li>
          <li><a href="#reqfilter">Require ldap-filter</a></li>
          <li><a href="#reqsearch">Require ldap-search</a></li>
        </ul>
      </li>

      <li><a href="#examples">Ejemplos</a></li>
      <li><a href="#usingtls">Usar TLS</a></li>
      <li><a href="#usingssl">Usar SSL</a></li>
      <li><a href="#exposed">Exponer Información de Inicio de Sesión</a></li>
      <li><a href="#activedirectory">Usar Active Directory</a></li>
      <li>
        <a href="#frontpage">Usar Microsoft FrontPage con
        <module>mod_authnz_ldap</module></a>

        <ul>
          <li><a href="#howitworks">Cómo Funciona</a></li>
          <li><a href="#fpcaveats">Advertencias</a></li>
        </ul>
      </li>
    </ul>
</section>

<section id="gcaveats"><title>Advertencias generales</title>
<p> Este módulo cachea los resultados de autenticación y autorización en
base a la configuración de <module>mod_ldap</module>. Los cambios
realizados en el servidor LDAP de backend no se reflejarán inmediatamente en
el servidor HTTP, incluyendo entre otros los bloqueos/revocaciones de
usuarios, los cambios de contraseña o los cambios en la pertenencia a
grupos. Consulte las directivas de <module>mod_ldap</module> para más
detalles sobre los parámetros ajustables de la caché.
</p>
</section>

<section id="operation"><title>Funcionamiento</title>

    <p>Hay dos fases a la hora de conceder acceso a un usuario. La primera
    fase es la autenticación, en la que el proveedor de autenticación de
    <module>mod_authnz_ldap</module> verifica que las credenciales del
    usuario son válidas. También se la denomina fase de
    <em>búsqueda/vinculación</em>. La segunda fase es la autorización, en la
    que <module>mod_authnz_ldap</module> determina si al usuario autenticado
    se le permite acceder al recurso en cuestión. También se la conoce como
    la fase de <em>comparación</em>.</p>

    <p><module>mod_authnz_ldap</module> registra tanto un proveedor de
    autenticación authn_ldap como un manejador de autorización authz_ldap.
    El proveedor de autenticación authn_ldap puede activarse mediante la
    directiva <directive module="mod_auth_basic">AuthBasicProvider</directive>
    usando el valor <code>ldap</code>. El manejador authz_ldap amplía los
    tipos de autorización de la directiva <directive
    module="mod_authz_core">Require</directive> añadiendo los valores
    <code>ldap-user</code>, <code>ldap-dn</code> y
    <code>ldap-group</code>.</p>

<section id="authenphase"><title>La Fase de
    Autenticación</title>

    <p>Durante la fase de autenticación, <module>mod_authnz_ldap</module>
    busca en el directorio una entrada que coincida con el nombre de usuario
    que pasa el cliente HTTP. Si se encuentra una única coincidencia,
    <module>mod_authnz_ldap</module> intenta vincularse al servidor de
    directorio usando el DN de la entrada junto con la contraseña
    proporcionada por el cliente HTTP. Como primero hace una búsqueda y
    después una vinculación, a menudo se la denomina la fase de
    búsqueda/vinculación. Estos son los pasos que se siguen durante la
    fase de búsqueda/vinculación.</p>

    <ol>
      <li>Generar un filtro de búsqueda combinando el atributo y el filtro
      indicados en la directiva <directive module="mod_authnz_ldap"
      >AuthLDAPURL</directive> con el nombre de usuario que pasa el
      cliente HTTP.</li>

      <li>Buscar en el directorio usando el filtro generado. Si la
      búsqueda no devuelve exactamente una entrada, se deniega o se
      rechaza el acceso.</li>

      <li>Obtener el nombre distinguido de la entrada recuperada de la
      búsqueda e intentar vincularse al servidor LDAP usando ese DN y la
      contraseña pasada por el cliente HTTP. Si la vinculación no tiene
      éxito, se deniega o se rechaza el acceso.</li>
    </ol>

    <p>Las siguientes directivas se usan durante la fase de
    búsqueda/vinculación</p>

    <table>
      <columnspec><column width=".3"/><column width=".7"/></columnspec>
      <tr>
        <td><directive module="mod_authnz_ldap">AuthLDAPURL</directive></td>

        <td>Especifica el servidor LDAP, el DN
        base, el atributo a usar en la búsqueda, así como el filtro de
        búsqueda adicional a usar.</td>
      </tr>

      <tr>
        <td><directive module="mod_authnz_ldap">AuthLDAPBindDN</directive></td>

        <td>Un DN opcional con el que vincularse
        durante la fase de búsqueda.</td>
      </tr>

      <tr>
        <td><directive
        module="mod_authnz_ldap">AuthLDAPBindPassword</directive></td>

        <td>Una contraseña opcional con la que
        vincularse durante la fase de búsqueda.</td>
      </tr>
    </table>
</section>

<section id="authorphase"><title>La Fase de Autorización</title>

    <p>Durante la fase de autorización, <module>mod_authnz_ldap</module>
    intenta determinar si el usuario está autorizado a acceder al
    recurso. Muchas de estas comprobaciones requieren que
    <module>mod_authnz_ldap</module> realice una operación de comparación
    en el servidor LDAP. Por esto a esta fase a menudo se la denomina la
    fase de comparación. <module>mod_authnz_ldap</module> acepta las
    siguientes directivas <directive module="mod_authz_core">Require</directive>
    para determinar si las credenciales son aceptables:</p>

    <ul>
      <li>Conceder acceso si hay una directiva <a
      href="#reqgroup"><code>Require ldap-user</code></a>, y el nombre de
      usuario de la directiva coincide con el nombre de usuario pasado por
      el cliente.</li>

      <li>Conceder acceso si hay una directiva <a href="#reqdn"><code>Require
      ldap-dn</code></a>, y el DN de la directiva coincide con el DN
      obtenido del directorio LDAP.</li>

      <li>Conceder acceso si hay una directiva <a
      href="#reqgroup"><code>Require ldap-group</code></a>, y el DN
      obtenido del directorio LDAP (o el nombre de usuario pasado por el
      cliente) aparece en el grupo LDAP o, potencialmente, en uno de sus
      subgrupos.</li>

      <li>Conceder acceso si hay una directiva <a href="#reqattribute">
      <code>Require ldap-attribute</code></a>, y el atributo obtenido del
      directorio LDAP coincide con el valor indicado.</li>

      <li>Conceder acceso si hay una directiva <a href="#reqfilter">
      <code>Require ldap-filter</code></a>, y el filtro de búsqueda
      encuentra correctamente un único objeto de usuario que coincide con el
      dn del usuario autenticado.</li>

      <li>Conceder acceso si hay una directiva <a href="#reqsearch">
      <code>Require ldap-search</code></a>, y el filtro de búsqueda
      devuelve correctamente un único objeto coincidente con cualquier
      nombre distinguido.</li>

      <li>en caso contrario, se deniega o se rechaza el acceso</li>
    </ul>

    <p>También pueden usarse otros valores de <directive
    module="mod_authz_core">Require</directive>, lo que puede requerir
    cargar módulos de autorización adicionales.</p>

    <ul>
        <li>Conceder acceso a todos los usuarios autenticados correctamente
        si hay una directiva <a href="#requser"><code>Require
        valid-user</code></a>. (requiere <module>mod_authz_user</module>)</li>

        <li>Conceder acceso si hay una directiva <a
        href="#reqgroup"><code>Require group</code></a>, y se ha cargado
        <module>mod_authz_groupfile</module> con la directiva <directive
        module="mod_authz_groupfile">AuthGroupFile</directive> establecida.</li>

        <li>otros...</li>
     </ul>


    <p><module>mod_authnz_ldap</module> usa las siguientes directivas
    durante la fase de comparación:</p>

    <table>
      <columnspec><column width=".4"/><column width=".6"/></columnspec>
      <tr>
        <td><directive module="mod_authnz_ldap">AuthLDAPURL</directive> </td>

        <td>El atributo especificado en la URL se
        usa en las operaciones de comparación para la operación
        <code>Require ldap-user</code>.</td>
      </tr>

      <tr>
        <td><directive
        module="mod_authnz_ldap">AuthLDAPCompareDNOnServer</directive></td>

        <td>Determina el comportamiento de la
        directiva <code>Require ldap-dn</code>.</td>
      </tr>

      <tr>
        <td><directive
        module="mod_authnz_ldap">AuthLDAPGroupAttribute</directive></td>

        <td>Determina el atributo a usar para las
        comparaciones en la directiva <code>Require ldap-group</code>.</td>
      </tr>

      <tr>
        <td><directive
        module="mod_authnz_ldap">AuthLDAPGroupAttributeIsDN</directive></td>

        <td>Especifica si se debe usar el DN del
        usuario o el nombre de usuario al hacer comparaciones para la
        directiva <code>Require ldap-group</code>.</td>
      </tr>

      <tr>
        <td><directive
        module="mod_authnz_ldap">AuthLDAPMaxSubGroupDepth</directive></td>

        <td>Determina la profundidad máxima de
        subgrupos que se evaluará durante las comparaciones en la directiva
        <code>Require ldap-group</code>.</td>
      </tr>

      <tr>
        <td><directive
        module="mod_authnz_ldap">AuthLDAPSubGroupAttribute</directive></td>

        <td>Determina el atributo a usar al obtener
        los miembros de los subgrupos del grupo actual durante las
        comparaciones en la directiva <code>Require ldap-group</code>.</td>
      </tr>

      <tr>
        <td><directive
        module="mod_authnz_ldap">AuthLDAPSubGroupClass</directive></td>

        <td>Especifica los valores objectClass de
        LDAP usados para identificar si los objetos de directorio
        consultados son realmente objetos de grupo (en contraposición a
        objetos de usuario) durante el procesamiento de subgrupos de la
        directiva <code>Require ldap-group</code>.</td>
      </tr>
    </table>
</section>
</section>

<section id="requiredirectives"><title>Las Directivas Require</title>

    <p>Las directivas <directive module="mod_authz_core">Require</directive>
    de Apache se usan durante la fase de autorización para garantizar que
    un usuario tiene permitido acceder a un recurso. mod_authnz_ldap
    amplía los tipos de autorización con <code>ldap-user</code>,
    <code>ldap-dn</code>, <code>ldap-group</code>,
    <code>ldap-attribute</code> y <code>ldap-filter</code>. También se
    pueden usar otros tipos de autorización, aunque puede que requieran
    cargar módulos de autorización adicionales.</p>

    <p>Desde la versión 2.4.8, se soportan <a href="../expr.html">expresiones</a>
    dentro de las directivas require de LDAP.</p>

<section id="requser"><title>Require ldap-user</title>

    <p>La directiva <code>Require ldap-user</code> especifica qué nombres
    de usuario pueden acceder al recurso. Una vez que
    <module>mod_authnz_ldap</module> ha obtenido un DN único del
    directorio, realiza una operación de comparación LDAP usando el
    nombre de usuario indicado en <code>Require ldap-user</code> para
    comprobar si ese nombre de usuario forma parte de la entrada LDAP que se
    acaba de obtener. Se puede conceder acceso a varios usuarios poniendo
    varios nombres de usuario en la línea, separados por espacios. Si un
    nombre de usuario tiene un espacio, debe ir rodeado de comillas dobles.
    También se puede conceder acceso a varios usuarios usando varias
    directivas <code>Require ldap-user</code>, con un usuario por línea.
    Por ejemplo, con un <directive
    module="mod_authnz_ldap">AuthLDAPURL</directive> de
    <code>ldap://ldap/o=Example?cn</code> (es decir, se usa <code>cn</code>
    para las búsquedas), podrían usarse las siguientes directivas Require
    para restringir el acceso:</p>
<highlight language="config">
Require ldap-user "Barbara Jenson"
Require ldap-user "Fred User"
Require ldap-user "Joe Manager"
</highlight>

    <p>Debido a la forma en que <module>mod_authnz_ldap</module> gestiona
    esta directiva, Barbara Jenson podría iniciar sesión como <code>Barbara
    Jenson</code>, <code>Babs Jenson</code> o cualquier otro <code>cn</code>
    que tenga en su entrada LDAP. Solo se necesita la única línea
    <code>Require ldap-user</code> para dar soporte a todos los valores del
    atributo en la entrada del usuario.</p>

    <p>Si en lugar del atributo <code>cn</code> se hubiera usado el
    atributo <code>uid</code> en la URL anterior, las tres líneas de
    arriba podrían condensarse en</p>
<highlight language="config">
Require ldap-user bjenson fuser jmanager
</highlight>
</section>

<section id="reqgroup"><title>Require ldap-group</title>

    <p>Esta directiva especifica un grupo LDAP cuyos miembros tienen
    acceso permitido. Toma el nombre distinguido del grupo LDAP.</p>

    <note type="warning">No rodee el nombre del grupo con comillas.
    A diferencia de <code>Require ldap-user</code>, el proveedor
    <code>ldap-group</code> no soporta valores entre comillas.</note>

    <p>Por ejemplo, suponga que existiera la siguiente entrada en el
    directorio LDAP:</p>
<example><pre>
dn: cn=Administrators, o=Example
objectClass: groupOfUniqueNames
uniqueMember: cn=Barbara Jenson, o=Example
uniqueMember: cn=Fred User, o=Example
</pre></example>

    <p>La siguiente directiva concedería acceso tanto a Fred como a
    Barbara:</p>
<highlight language="config">
Require ldap-group cn=Administrators, o=Example
</highlight>

    <p>Los miembros también pueden encontrarse dentro de subgrupos de un
    grupo LDAP especificado si <directive
    module="mod_authnz_ldap">AuthLDAPMaxSubGroupDepth</directive> se
    establece en un valor mayor que 0. Por ejemplo, suponga que existen
    las siguientes entradas en el directorio LDAP:</p>
<example><pre>
dn: cn=Employees, o=Example
objectClass: groupOfUniqueNames
uniqueMember: cn=Managers, o=Example
uniqueMember: cn=Administrators, o=Example
uniqueMember: cn=Users, o=Example

dn: cn=Managers, o=Example
objectClass: groupOfUniqueNames
uniqueMember: cn=Bob Ellis, o=Example
uniqueMember: cn=Tom Jackson, o=Example

dn: cn=Administrators, o=Example
objectClass: groupOfUniqueNames
uniqueMember: cn=Barbara Jenson, o=Example
uniqueMember: cn=Fred User, o=Example

dn: cn=Users, o=Example
objectClass: groupOfUniqueNames
uniqueMember: cn=Allan Jefferson, o=Example
uniqueMember: cn=Paul Tilley, o=Example
uniqueMember: cn=Temporary Employees, o=Example

dn: cn=Temporary Employees, o=Example
objectClass: groupOfUniqueNames
uniqueMember: cn=Jim Swenson, o=Example
uniqueMember: cn=Elliot Rhodes, o=Example
</pre></example>

    <p>Las siguientes directivas permitirían el acceso a Bob Ellis, Tom
    Jackson, Barbara Jenson, Fred User, Allan Jefferson y Paul Tilley, pero
    no permitirían el acceso a Jim Swenson ni a Elliot Rhodes (ya que
    están a una profundidad de subgrupo de 2):</p>
<highlight language="config">
Require ldap-group cn=Employees, o=Example
AuthLDAPMaxSubGroupDepth 1
</highlight>

    <p>El comportamiento de esta directiva se modifica mediante las
    directivas <directive
    module="mod_authnz_ldap">AuthLDAPGroupAttribute</directive>, <directive
    module="mod_authnz_ldap">AuthLDAPGroupAttributeIsDN</directive>, <directive
    module="mod_authnz_ldap">AuthLDAPMaxSubGroupDepth</directive>, <directive
    module="mod_authnz_ldap">AuthLDAPSubGroupAttribute</directive> y
    <directive module="mod_authnz_ldap">AuthLDAPSubGroupClass</directive>.</p>
</section>

<section id="reqdn"><title>Require ldap-dn</title>

    <p>La directiva <code>Require ldap-dn</code> permite al administrador
    conceder acceso en base a nombres distinguidos. Especifica un DN que
    debe coincidir para que se conceda el acceso. Si el nombre distinguido
    obtenido del servidor de directorio coincide con el nombre distinguido
    indicado en <code>Require ldap-dn</code>, se concede la
    autorización.</p>

    <note type="warning">No rodee el nombre distinguido con comillas.
    A diferencia de <code>Require ldap-user</code>, el proveedor
    <code>ldap-dn</code> no soporta valores entre comillas.</note>

    <p>La siguiente directiva concedería acceso a un DN específico:</p>
<highlight language="config">
Require ldap-dn cn=Barbara Jenson, o=Example
</highlight>

    <p>El comportamiento de esta directiva se modifica mediante la
    directiva <directive
    module="mod_authnz_ldap">AuthLDAPCompareDNOnServer</directive>.</p>
</section>

<section id="reqattribute"><title>Require ldap-attribute</title>

    <p>La directiva <code>Require ldap-attribute</code> permite al
    administrador conceder acceso en base a atributos del usuario
    autenticado en el directorio LDAP. Si el atributo en el directorio
    coincide con el valor indicado en la configuración, se concede el
    acceso.</p>

    <p>La siguiente directiva concedería acceso a cualquiera que tenga el
    atributo employeeType = active</p>

    <highlight language="config">
Require ldap-attribute employeeType="active"
</highlight>

    <p>Se pueden especificar varios pares atributo/valor en la misma
    línea separados por espacios, o bien pueden especificarse en varias
    directivas <code>Require ldap-attribute</code>. El efecto de listar
    varios pares atributo/valor es una operación OR. Se concederá acceso
    si alguno de los valores de atributo listados coincide con el valor del
    atributo correspondiente en el objeto de usuario. Si el valor del
    atributo contiene un espacio, solo el valor debe ir entre comillas
    dobles.</p>

    <p>La siguiente directiva concedería acceso a cualquiera que tenga el
    atributo city igual a "San Jose" o status igual a "Active"</p>

    <highlight language="config">
Require ldap-attribute city="San Jose" status="active"
</highlight>

</section>

<section id="reqfilter"><title>Require ldap-filter</title>

    <p>La directiva <code>Require ldap-filter</code> permite al
    administrador conceder acceso en base a un filtro de búsqueda LDAP
    complejo. Si el dn devuelto por la búsqueda del filtro coincide con el
    dn del usuario autenticado, se concede el acceso.</p>

    <p>La siguiente directiva concedería acceso a cualquiera que tenga un
    teléfono móvil y esté en el departamento de marketing</p>

    <highlight language="config">
Require ldap-filter "&amp;(cell=*)(department=marketing)"
</highlight>

    <p>La diferencia entre la directiva <code>Require ldap-filter</code> y
    la directiva <code>Require ldap-attribute</code> es que
    <code>ldap-filter</code> realiza una operación de búsqueda en el
    directorio LDAP usando el filtro de búsqueda indicado, en lugar de una
    simple comparación de atributo. Si todo lo que se necesita es una
    simple comparación de atributo, la operación de comparación realizada
    por <code>ldap-attribute</code> será más rápida que la operación de
    búsqueda usada por <code>ldap-filter</code>, especialmente en un
    directorio grande.</p>

    <p>Cuando se usa una <a href="../expr.html">expresión</a> dentro del
    filtro, hay que tener cuidado de que los filtros LDAP se escapen
    correctamente para protegerse de inyecciones LDAP. Para ello se puede
    usar la función ldap.</p>

<highlight language="config">
&lt;LocationMatch "^/dav/(?&lt;SITENAME&gt;[^/]+)/"&gt;
  Require ldap-filter "(memberOf=cn=%{ldap:%{unescape:%{env:MATCH_SITENAME}},ou=Websites,o=Example)"
&lt;/LocationMatch&gt;
</highlight>

</section>

<section id="reqsearch"><title>Require ldap-search</title>

    <p>La directiva <code>Require ldap-search</code> permite al
    administrador conceder acceso en base a un filtro de búsqueda LDAP
    genérico usando una <a href="../expr.html">expresión</a>. Si hay
    exactamente una coincidencia con el filtro de búsqueda,
    independientemente del nombre distinguido, se concede el acceso.</p>

    <p>La siguiente directiva concedería acceso a las URLs que coincidan
    con los objetos indicados en el servidor LDAP:</p>

<highlight language="config">
&lt;LocationMatch "^/dav/(?&lt;SITENAME&gt;[^/]+)/"&gt;
Require ldap-search "(cn=%{ldap:%{unescape:%{env:MATCH_SITENAME}} Website)"
&lt;/LocationMatch&gt;
</highlight>

    <p>Nota: hay que tener cuidado de que cualquier expresión se escape
    correctamente para protegerse de inyecciones LDAP. Se puede usar la
    función <strong>ldap</strong> como en el ejemplo anterior.</p>

</section>

</section>

<section id="examples"><title>Ejemplos</title>

    <ul>
      <li>
        Conceder acceso a cualquiera que exista en el directorio LDAP,
        usando su UID para las búsquedas.
<highlight language="config">
AuthLDAPURL "ldap://ldap1.example.com:389/ou=People, o=Example?uid?sub?(objectClass=*)"
Require valid-user
</highlight>
      </li>

      <li>
        El siguiente ejemplo es igual que el anterior; pero sin los
        campos que tienen valores por defecto útiles. Observe también el
        uso de un servidor LDAP redundante.
<highlight language="config">
AuthLDAPURL "ldap://ldap1.example.com ldap2.example.com/ou=People, o=Example"
Require valid-user
</highlight>
      </li>

      <li>
        El siguiente ejemplo es similar al anterior, pero usa el nombre
        común en lugar del UID. Tenga en cuenta que esto podría ser
        problemático si varias personas en el directorio comparten el
        mismo <code>cn</code>, porque una búsqueda sobre <code>cn</code>
        <strong>debe</strong> devolver exactamente una entrada. Por eso
        este enfoque no se recomienda: es mejor elegir un atributo que
        esté garantizado como único en su directorio, como
        <code>uid</code>.
<highlight language="config">
AuthLDAPURL "ldap://ldap.example.com/ou=People, o=Example?cn"
Require valid-user
</highlight>
      </li>

      <li>
        Conceder acceso a cualquiera en el grupo Administrators. Los
        usuarios deben autenticarse usando su UID.
<highlight language="config">
AuthLDAPURL ldap://ldap.example.com/o=Example?uid
Require ldap-group cn=Administrators, o=Example
</highlight>
      </li>

      <li>
        Conceder acceso a cualquiera en el grupo cuyo nombre coincida con
        el nombre de host del host virtual. En este ejemplo se usa una
        <a href="../expr.html">expresión</a> para construir el filtro.
<highlight language="config">
AuthLDAPURL ldap://ldap.example.com/o=Example?uid
Require ldap-group cn=%{SERVER_NAME}, o=Example
</highlight>
      </li>

      <li>
        El siguiente ejemplo asume que todas las personas de Example que
        llevan un buscapersonas alfanumérico tendrán un atributo LDAP
        <code>qpagePagerID</code>. El ejemplo concederá acceso solo a las
        personas (autenticadas mediante su UID) que tengan buscapersonas
        alfanuméricos:
<highlight language="config">
AuthLDAPURL ldap://ldap.example.com/o=Example?uid??(qpagePagerID=*)
Require valid-user
</highlight>
      </li>

      <li>
        <p>El siguiente ejemplo demuestra el poder del uso de filtros para
        cumplir requisitos administrativos complicados. Sin filtros, habría
        sido necesario crear un nuevo grupo LDAP y asegurarse de que los
        miembros del grupo permanecieran sincronizados con los usuarios de
        buscapersonas. Esto se vuelve trivial con filtros. El objetivo es
        conceder acceso a cualquiera que tenga un buscapersonas, además de
        conceder acceso a Joe Manager, que no tiene buscapersonas, pero
        necesita acceder al mismo recurso:</p>
<highlight language="config">
AuthLDAPURL ldap://ldap.example.com/o=Example?uid??(|(qpagePagerID=*)(uid=jmanager))
Require valid-user
</highlight>

        <p>Esto último puede parecer confuso al principio, así que ayuda
        evaluar cómo se vería el filtro de búsqueda según quién se
        conecte, como se muestra abajo. Si Fred User se conecta como
        <code>fuser</code>, el filtro se vería así</p>

        <example>(&amp;(|(qpagePagerID=*)(uid=jmanager))(uid=fuser))</example>

        <p>La búsqueda anterior solo tendrá éxito si <code>fuser</code>
        tiene un buscapersonas. Cuando Joe Manager se conecta como
        <code>jmanager</code>, el filtro se ve así</p>

        <example>(&amp;(|(qpagePagerID=*)(uid=jmanager))(uid=jmanager))</example>

        <p>La búsqueda anterior tendrá éxito tanto si <code>jmanager</code>
        tiene un buscapersonas como si no.</p>
      </li>
    </ul>
</section>

<section id="usingtls"><title>Usar TLS</title>

    <p>Para usar TLS, consulte las directivas de <module>mod_ldap</module>
    <directive module="mod_ldap">LDAPTrustedClientCert</directive>, <directive
    module="mod_ldap">LDAPTrustedGlobalCert</directive> y <directive
    module="mod_ldap">LDAPTrustedMode</directive>.</p>

    <p>Se puede añadir un segundo parámetro opcional a <directive
    module="mod_authnz_ldap">AuthLDAPURL</directive> para sobrescribir el
    tipo de conexión por defecto establecido por <directive
    module="mod_ldap">LDAPTrustedMode</directive>. Esto permitirá que la
    conexión establecida por una URL <code>ldap://</code> se actualice a
    una conexión segura en el mismo puerto.</p>
</section>

<section id="usingssl"><title>Usar SSL</title>

    <p>Para usar SSL, consulte las directivas de <module>mod_ldap</module>
    <directive module="mod_ldap">LDAPTrustedClientCert</directive>, <directive
    module="mod_ldap">LDAPTrustedGlobalCert</directive> y <directive
    module="mod_ldap">LDAPTrustedMode</directive>.</p>

    <p>Para indicar un servidor LDAP seguro, use <code>ldaps://</code> en
    la directiva <directive
    module="mod_authnz_ldap">AuthLDAPURL</directive>, en lugar de
    <code>ldap://</code>.</p>
</section>

<section id="exposed"><title>Exponer Información de Inicio de Sesión</title>

    <p>cuando este módulo realiza la <em>autenticación</em>, los atributos
    ldap indicados en la directiva <directive
    module="mod_authnz_ldap">AuthLDAPURL</directive> se colocan en
    variables de entorno con el prefijo "AUTHENTICATE_".</p>

    <p>cuando este módulo realiza la <em>autorización</em>, los atributos
    ldap indicados en la directiva <directive
    module="mod_authnz_ldap">AuthLDAPURL</directive> se colocan en
    variables de entorno con el prefijo "AUTHORIZE_".</p>

    <p>Si el campo de atributos contiene el nombre de usuario, el nombre
    común y el número de teléfono de un usuario, un programa CGI tendrá
    acceso a esta información sin necesidad de hacer una segunda consulta
    LDAP independiente para obtener esta información adicional.</p>

    <p>Esto tiene el potencial de simplificar drásticamente la codificación
    y la configuración necesarias en algunas aplicaciones web.</p>

</section>

<section id="activedirectory"><title>Usar Active Directory</title>

    <p>Una instalación de Active Directory puede soportar varios dominios
    al mismo tiempo. Para distinguir usuarios entre dominios, se puede
    añadir a la entrada de un usuario en el directorio un identificador
    llamado User Principle Name (UPN). Este UPN normalmente toma la forma
    del nombre de cuenta del usuario, seguido de los componentes de
    dominio del dominio en cuestión, por ejemplo
    <code>somebody@nz.example.com</code>.</p>

    <p>Puede que desee configurar el módulo
    <module>mod_authnz_ldap</module> para autenticar a los usuarios
    presentes en cualquiera de los dominios que forman el bosque de Active
    Directory. De esta forma, tanto
    <code>somebody@nz.example.com</code> como
    <code>someone@au.example.com</code> pueden autenticarse usando la
    misma consulta al mismo tiempo.</p>

    <p>Para hacer esto práctico, Active Directory soporta el concepto de
    Global Catalog. Este Global Catalog es una copia de solo lectura de
    atributos seleccionados de todos los servidores de Active Directory
    dentro del bosque de Active Directory. Consultar el Global Catalog
    permite consultar todos los dominios en una única consulta, sin que la
    consulta tenga que abarcar servidores a través de enlaces
    potencialmente lentos.</p>

    <p>Si está activado, el Global Catalog es un servidor de directorio
    independiente que se ejecuta en el puerto 3268 (3269 para SSL). Para
    buscar un usuario, haga una búsqueda de subárbol del atributo
    <code>userPrincipalName</code>, con una raíz de búsqueda vacía, de esta
    forma:</p>

<highlight language="config">
AuthLDAPBindDN apache@example.com
AuthLDAPBindPassword password
AuthLDAPURL ldap://10.0.0.1:3268/?userPrincipalName?sub
</highlight>

    <p>Los usuarios necesitarán introducir su User Principal Name como
    nombre de inicio de sesión, en la forma
    <code>somebody@nz.example.com</code>.</p>

</section>

<section id="frontpage"><title>Usar Microsoft
    FrontPage con mod_authnz_ldap</title>

    <p>Normalmente, FrontPage usa archivos de usuarios/grupos específicos
    de la web FrontPage (es decir, los módulos <module>mod_authn_file</module>
    y <module>mod_authz_groupfile</module>) para gestionar toda la
    autenticación. Desgraciadamente, no es posible simplemente cambiar a
    autenticación LDAP añadiendo las directivas apropiadas, porque eso
    romperá los formularios de <em>Permisos</em> del cliente de FrontPage,
    que intentan modificar los archivos de autorización estándar basados
    en texto.</p>

    <p>Una vez creada una web de FrontPage, añadirle autenticación LDAP es
    cuestión de añadir las siguientes directivas a <em>todos</em> los
    archivos <code>.htaccess</code> que se crean en la web</p>
<highlight language="config">
AuthLDAPURL       "the url"
AuthGroupFile     "mygroupfile"
Require group     "mygroupfile"
</highlight>

<section id="howitworks"><title>Cómo Funciona</title>

    <p>FrontPage restringe el acceso a una web añadiendo la directiva
    <code>Require valid-user</code> a los archivos <code>.htaccess</code>.
    La directiva <code>Require valid-user</code> tendrá éxito para
    cualquier usuario que sea válido <em>por lo que respecta a LDAP</em>.
    Esto significa que cualquiera que tenga una entrada en el directorio
    LDAP se considera un usuario válido, mientras que FrontPage solo
    considera válidas a las personas del archivo de usuarios local. Al
    sustituir ldap-group por la autorización mediante archivo de grupo, se
    permite que Apache consulte el archivo de usuarios local (que gestiona
    FrontPage), en lugar de LDAP, al autorizar al usuario.</p>

    <p>Una vez añadidas las directivas como se indica arriba, los
    usuarios de FrontPage podrán realizar todas las operaciones de
    administración desde el cliente de FrontPage.</p>
</section>

<section id="fpcaveats"><title>Advertencias</title>

    <ul>
      <li>Al elegir la URL LDAP, el atributo a usar para la autenticación
      debería ser algo que también sea válido para incluir en un archivo
      de usuarios de <module>mod_authn_file</module>. El ID de usuario es
      ideal para esto.</li>

      <li>Al añadir usuarios mediante FrontPage, los administradores de
      FrontPage deberían elegir nombres de usuario que ya existan en el
      directorio LDAP (por razones obvias). Además, la contraseña que el
      administrador introduce en el formulario se ignora, ya que Apache
      en realidad autenticará contra la contraseña de la base de datos
      LDAP, y no contra la contraseña del archivo de usuarios local. Esto
      podría causar confusión a los administradores web.</li>

      <!-- XXX is that true? was mod_auth before the aaa change -->
      <li>Apache debe compilarse con <module>mod_auth_basic</module>,
      <module>mod_authn_file</module> y
      <module>mod_authz_groupfile</module> para poder usar el soporte de
      FrontPage. Esto es porque Apache seguirá usando el archivo de grupo
      de <module>mod_authz_groupfile</module> para determinar el alcance
      del acceso de un usuario a la web de FrontPage.</li>

      <li>Las directivas deben colocarse en los archivos
      <code>.htaccess</code>. Intentar ponerlas dentro de directivas
      <directive module="core" type="section">Location</directive> o
      <directive module="core" type="section">Directory</directive> no
      funcionará. Esto es porque <module>mod_authnz_ldap</module> tiene
      que poder obtener la directiva <directive
      module="mod_authz_groupfile">AuthGroupFile</directive> que se
      encuentra en los archivos <code>.htaccess</code> de FrontPage, para
      saber dónde buscar la lista de usuarios válidos. Si las directivas
      de <module>mod_authnz_ldap</module> no están en el mismo archivo
      <code>.htaccess</code> que las directivas de FrontPage, entonces el
      truco no funcionará, porque <module>mod_authnz_ldap</module> nunca
      tendrá la oportunidad de procesar el archivo <code>.htaccess</code>,
      y no podrá encontrar el archivo de usuarios gestionado por
      FrontPage.</li>
    </ul>
</section>
</section>

<directivesynopsis>
<name>AuthLDAPAuthorizePrefix</name>
<description>Especifica el prefijo para las variables de entorno
establecidas durante la autorización</description>
<syntax>AuthLDAPAuthorizePrefix <var>prefix</var></syntax>
<default>AuthLDAPAuthorizePrefix AUTHORIZE_</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>
<compatibility>Disponible desde la versión 2.3.6</compatibility>
<usage>
    <p>Esta directiva le permite sobrescribir el prefijo usado para las
    variables de entorno establecidas durante la autorización LDAP. Si se
    indica <code>AUTHENTICATE_</code>, los consumidores de estas variables
    de entorno verán la misma información tanto si LDAP ha realizado la
    autenticación, como la autorización, o ambas.</p>

    <note><title>Nota</title>
    No se establece ninguna variable de autorización cuando un usuario se
    autoriza en base a <code>Require valid-user</code>.
    </note>
</usage>
</directivesynopsis>


<directivesynopsis>
<name>AuthLDAPBindAuthoritative</name>
<description>Determina si se usan otros proveedores de autenticación
cuando un usuario puede asociarse a un DN pero el servidor no puede
vincularse correctamente con las credenciales del usuario.</description>
<syntax>AuthLDAPBindAuthoritative off|on</syntax>
<default>AuthLDAPBindAuthoritative on</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>
<usage>
    <p>Por defecto, los proveedores de autenticación siguientes solo se
    consultan si un usuario no puede asociarse a un DN, pero no si el
    usuario puede asociarse a un DN y su contraseña no puede verificarse
    con una vinculación LDAP. Si <directive>AuthLDAPBindAuthoritative</directive>
    se establece a <code>off</code>, otros módulos de autenticación
    configurados tendrán la oportunidad de validar al usuario si la
    vinculación LDAP (con las credenciales del usuario actual) falla por
    cualquier motivo.</p>
    <p> Esto permite que los usuarios presentes tanto en LDAP como en
    <directive module="mod_authn_file">AuthUserFile</directive> se
    autentiquen cuando el servidor LDAP está disponible pero la cuenta del
    usuario está bloqueada o la contraseña no es utilizable por cualquier
    otro motivo.</p>
</usage>
<seealso><directive module="mod_authn_file">AuthUserFile</directive></seealso>
<seealso><directive module="mod_auth_basic">AuthBasicProvider</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>AuthLDAPInitialBindAsUser</name>
<description>Determina si el servidor realiza la búsqueda inicial de DN
usando el propio nombre de usuario de la autenticación basic del usuario,
en lugar de hacerlo de forma anónima o con credenciales fijas para el
servidor</description>
<syntax>AuthLDAPInitialBindAsUser off|on</syntax>
<default>AuthLDAPInitialBindAsUser off</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>
<compatibility>Disponible desde la versión 2.3.6</compatibility>
<usage>
    <p>Por defecto, el servidor convierte el nombre de usuario de la
     autenticación basic en un nombre distinguido LDAP (DN), bien de
     forma anónima, o bien con un usuario y contraseña dedicados. Esta
     directiva obliga al servidor a usar literalmente el nombre de
     usuario y la contraseña proporcionados por el usuario entrante para
     realizar la búsqueda inicial del DN.</p>

     <p> Si el nombre de usuario literal no puede vincularse
     directamente, pero necesita alguna transformación cosmética, consulte
     <directive module="mod_authnz_ldap">
     AuthLDAPInitialBindPattern</directive>.</p>

     <p> Esta directiva solo debería usarse cuando su servidor LDAP no
         acepta búsquedas anónimas y no puede usar un <directive
         module="mod_authnz_ldap">AuthLDAPBindDN</directive> dedicado.
     </p>

     <note><title>No disponible solo con autorización</title>
         Esta directiva solo puede usarse si este módulo autentica al
         usuario, y no tiene ningún efecto cuando este módulo se usa
         exclusivamente para la autorización.
     </note>
</usage>
<seealso><directive module="mod_authnz_ldap">AuthLDAPInitialBindPattern</directive></seealso>
<seealso><directive module="mod_authnz_ldap">AuthLDAPBindDN</directive></seealso>
<seealso><directive module="mod_authnz_ldap">AuthLDAPCompareAsUser</directive></seealso>
<seealso><directive module="mod_authnz_ldap">AuthLDAPSearchAsUser</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>AuthLDAPInitialBindPattern</name>
<description>Especifica la transformación del nombre de usuario de la
autenticación basic que se usará al vincularse al servidor LDAP para
realizar una búsqueda de DN</description>
<syntax>AuthLDAPInitialBindPattern <var>regex</var> <var>substitution</var></syntax>
<default>AuthLDAPInitialBindPattern (.*) $1 (se usa el nombre de usuario remoto literalmente)</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>
<compatibility>Disponible desde la versión 2.3.6</compatibility>
<usage>
    <p>Si <directive module="mod_authnz_ldap">AuthLDAPInitialBindAsUser</directive>
       se establece a <code>ON</code>, el nombre de usuario de la
       autenticación basic se transformará de acuerdo con los argumentos
       de expresión regular y sustitución.</p>

    <p> El argumento de expresión regular se compara con el nombre de
        usuario actual de la autenticación basic. El argumento de
        sustitución puede contener referencias hacia atrás, pero no
        admite ninguna otra interpolación de variables.</p>

    <p> Esta directiva solo debería usarse cuando su servidor LDAP no
        acepta búsquedas anónimas y no puede usar un <directive
        module="mod_authnz_ldap">AuthLDAPBindDN</directive> dedicado.
    </p>

    <highlight language="config">
AuthLDAPInitialBindPattern (.+) $1@example.com
    </highlight>
    <highlight language="config">
AuthLDAPInitialBindPattern (.+) cn=$1,dc=example,dc=com
    </highlight>

    <note><title>No disponible solo con autorización</title>
        Esta directiva solo puede usarse si este módulo autentica al
        usuario, y no tiene ningún efecto cuando este módulo se usa
        exclusivamente para la autorización.
    </note>
    <note><title>depuración</title>
        El DN sustituido se registra en la variable de entorno
        <code>LDAP_BINDASUSER</code>. Si la expresión regular no coincide
        con la entrada, se usa el nombre de usuario literal.
    </note>
</usage>
<seealso><directive module="mod_authnz_ldap">AuthLDAPInitialBindAsUser</directive></seealso>
<seealso><directive module="mod_authnz_ldap">AuthLDAPBindDN</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>AuthLDAPBindDN</name>
<description>DN opcional a usar para vincularse al servidor LDAP</description>
<syntax>AuthLDAPBindDN <var>distinguished-name</var></syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Un DN opcional usado para vincularse al servidor al buscar
    entradas. Si no se indica, <module>mod_authnz_ldap</module> usará una
    vinculación anónima.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthLDAPBindPassword</name>
<description>Contraseña usada junto con el bind DN</description>
<syntax>AuthLDAPBindPassword <var>password</var></syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>
<compatibility><code>exec:</code> se añadió en la versión 2.4.5.</compatibility>

<usage>
    <p>Una contraseña de vinculación para usar junto con el bind DN.
    Tenga en cuenta que la contraseña de vinculación probablemente sean
    datos sensibles, y debería protegerse adecuadamente. Solo debería usar
    <directive module="mod_authnz_ldap">AuthLDAPBindDN</directive> y
    <directive>AuthLDAPBindPassword</directive> si realmente los necesita
    para buscar en el directorio.</p>

    <p>Si el valor empieza por exec: se ejecutará el comando resultante y
    la primera línea devuelta por el programa a la salida estándar se
    usará como contraseña.</p>
<highlight language="config">
#Contraseña usada tal cual
AuthLDAPBindPassword secret

#Ejecuta /path/to/program para obtener mi contraseña
AuthLDAPBindPassword exec:/path/to/program

#Ejecuta /path/to/otherProgram y proporciona argumentos
AuthLDAPBindPassword "exec:/path/to/otherProgram argument1"
</highlight>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthLDAPCharsetConfig</name>
<description>Archivo de configuración de conversión de idioma a juego de
caracteres</description>
<syntax>AuthLDAPCharsetConfig <var>file-path</var></syntax>
<contextlist><context>server config</context>
</contextlist>

<usage>
    <p>La directiva <directive>AuthLDAPCharsetConfig</directive>
    establece la ubicación del archivo de configuración de conversión de
    idioma a juego de caracteres. <var>File-path</var> es relativa a
    <directive module="core">ServerRoot</directive>. Este archivo indica
    la lista de extensiones de idioma asociadas a juegos de caracteres.
    La mayoría de los administradores usan el archivo
    <code>charset.conv</code> proporcionado, que asocia las extensiones
    de idioma más comunes a juegos de caracteres.</p>

    <p>El archivo contiene líneas con el siguiente formato:</p>

    <example>
      <var>Language-Extension</var> <var>charset</var> [<var>Language-String</var>] ...
    </example>

    <p>No importan las mayúsculas o minúsculas de la extensión. Se
    ignoran las líneas en blanco y las líneas que empiezan con un
    carácter almohadilla (<code>#</code>).</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthLDAPCompareAsUser</name>
<description>Usar las credenciales del usuario autenticado para realizar
las comparaciones de autorización</description>
<syntax>AuthLDAPCompareAsUser on|off</syntax>
<default>AuthLDAPCompareAsUser off</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>
<compatibility>Disponible desde la versión 2.3.6</compatibility>

<usage>
    <p>Cuando se establece, y <module>mod_authnz_ldap</module> ha
    autenticado al usuario, las comparaciones LDAP para la autorización
    usan el nombre distinguido (DN) obtenido en la consulta y la
    contraseña de autenticación HTTP basic del usuario autenticado, en
    lugar de las credenciales configuradas en el servidor.</p>

    <p> Las comprobaciones de autorización <code>ldap-attribute</code>,
    <code>ldap-user</code> y <code>ldap-group</code> (solo de un nivel)
    usan comparaciones.</p>

    <p>Esta directiva solo tiene efecto en las comparaciones realizadas
    durante el procesamiento de grupos anidados cuando también está
    activada <directive module="mod_authnz_ldap">
    AuthLDAPSearchAsUser</directive>.</p>

    <p> Esta directiva solo debería usarse cuando su servidor LDAP no
        acepta comparaciones anónimas y no puede usar un <directive
        module="mod_authnz_ldap">AuthLDAPBindDN</directive> dedicado.
    </p>
</usage>
<seealso><directive module="mod_authnz_ldap">AuthLDAPInitialBindAsUser</directive></seealso>
<seealso><directive module="mod_authnz_ldap">AuthLDAPSearchAsUser</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>AuthLDAPCompareDNOnServer</name>
<description>Usar el servidor LDAP para comparar los DNs</description>
<syntax>AuthLDAPCompareDNOnServer on|off</syntax>
<default>AuthLDAPCompareDNOnServer on</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Cuando se establece, <module>mod_authnz_ldap</module> usará el
    servidor LDAP para comparar los DNs. Esta es la única forma
    totalmente fiable de comparar DNs. <module>mod_authnz_ldap</module>
    buscará en el directorio el DN indicado con la directiva <a
    href="#reqdn"><code>Require dn</code></a>, y después obtendrá el DN y
    lo comparará con el DN obtenido de la entrada del usuario. Si esta
    directiva no está establecida, <module>mod_authnz_ldap</module>
    simplemente hace una comparación de cadenas. Es posible obtener
    falsos negativos con este enfoque, pero es mucho más rápido. Tenga en
    cuenta que la caché de <module>mod_ldap</module> puede acelerar la
    comparación de DN en la mayoría de los casos.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthLDAPDereferenceAliases</name>
<description>Cuándo el módulo deberá resolver los alias</description>
<syntax>AuthLDAPDereferenceAliases never|searching|finding|always</syntax>
<default>AuthLDAPDereferenceAliases always</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Esta directiva indica cuándo <module>mod_authnz_ldap</module>
    resolverá los alias durante las operaciones LDAP. El valor por
    defecto es <code>always</code>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthLDAPGroupAttribute</name>
<description>Atributos LDAP usados para identificar a los usuarios
miembros de los grupos.</description>
<syntax>AuthLDAPGroupAttribute <var>attribute</var></syntax>
<default>AuthLDAPGroupAttribute member uniqueMember</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Esta directiva especifica qué atributos LDAP se usan para
    comprobar los usuarios miembros dentro de los grupos. Se pueden usar
    varios atributos indicando esta directiva varias veces. Si no se
    indica, <module>mod_authnz_ldap</module> usa los atributos
    <code>member</code> y <code>uniqueMember</code>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthLDAPGroupAttributeIsDN</name>
<description>Usar el DN del nombre de usuario del cliente al comprobar
la pertenencia a un grupo</description>
<syntax>AuthLDAPGroupAttributeIsDN on|off</syntax>
<default>AuthLDAPGroupAttributeIsDN on</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Cuando se establece a <code>on</code>, esta directiva indica que
    se use el nombre distinguido del nombre de usuario del cliente al
    comprobar la pertenencia a un grupo. En caso contrario, se usará el
    nombre de usuario. Por ejemplo, suponga que el cliente envió el
    nombre de usuario <code>bjenson</code>, que corresponde al DN LDAP
    <code>cn=Babs Jenson, o=Example</code>. Si esta directiva está
    establecida, <module>mod_authnz_ldap</module> comprobará si el grupo
    tiene <code>cn=Babs Jenson, o=Example</code> como miembro. Si esta
    directiva no está establecida, <module>mod_authnz_ldap</module>
    comprobará si el grupo tiene <code>bjenson</code> como miembro.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthLDAPMaxSubGroupDepth</name>
<description>Especifica la profundidad máxima de anidamiento de
subgrupos que se evaluará antes de interrumpir la búsqueda del
usuario.</description>
<syntax>AuthLDAPMaxSubGroupDepth <var>Number</var></syntax>
<default>AuthLDAPMaxSubGroupDepth 0</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>
<compatibility>Disponible desde la versión 2.3.0, con un valor por
defecto de 10 en 2.4.x y en las primeras versiones de 2.5</compatibility>

<usage>
   <p>Cuando esta directiva se establece a un valor distinto de cero
   <code>X</code> combinado con el uso de la directiva <code>Require
   ldap-group someGroupDN</code>, se buscarán las credenciales de usuario
   proporcionadas como miembro del objeto de directorio
   <code>someGroupDN</code> o de cualquier grupo miembro del grupo
   actual, hasta el nivel de anidamiento máximo <code>X</code> indicado
   por esta directiva.</p>
   <p>Consulte la sección <a href="#reqgroup"><code>Require
   ldap-group</code></a> para un ejemplo más detallado.</p>

   <note><title>Rendimiento de los grupos anidados</title>
   <p> Cuando <directive>AuthLDAPSubGroupAttribute</directive> se solapa
   con <directive>AuthLDAPGroupAttribute</directive> (como ocurre por
   defecto y como exigen los esquemas LDAP habituales), la búsqueda sin
   caché de subgrupos en grupos grandes puede ser muy lenta. Si usa
   grupos grandes y no anidados, mantenga
   <directive>AuthLDAPMaxSubGroupDepth</directive> establecido a
   cero.</p>
   </note>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthLDAPRemoteUserAttribute</name>
<description>Usar el valor del atributo devuelto durante la consulta de
usuario para establecer la variable de entorno REMOTE_USER</description>
<syntax>AuthLDAPRemoteUserAttribute uid</syntax>
<default>none</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Si esta directiva está establecida, el valor de la variable de
    entorno <code>REMOTE_USER</code> se establecerá al valor del
    atributo indicado. Asegúrese de que este atributo está incluido en
    la lista de atributos de la definición de <directive
    module="mod_authnz_ldap">AuthLDAPURL</directive>, de lo contrario
    esta directiva no tendrá ningún efecto. Esta directiva, si está
    presente, tiene prioridad sobre <directive
    module="mod_authnz_ldap">AuthLDAPRemoteUserIsDN</directive>. Esta
    directiva es útil si quiere que la gente inicie sesión en un sitio
    web usando una dirección de correo electrónico, pero una aplicación
    de backend espera el nombre de usuario como un userid.</p>
    <p> Esta directiva solo tiene efecto cuando este módulo se usa para
    la autenticación.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthLDAPRemoteUserIsDN</name>
<description>Usar el DN del nombre de usuario del cliente para
establecer la variable de entorno REMOTE_USER</description>
<syntax>AuthLDAPRemoteUserIsDN on|off</syntax>
<default>AuthLDAPRemoteUserIsDN off</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Si esta directiva se establece a on, el valor de la variable de
    entorno <code>REMOTE_USER</code> se establecerá al nombre
    distinguido completo del usuario autenticado, en lugar de solo el
    nombre de usuario pasado por el cliente. Está desactivada por
    defecto.</p>
    <p> Esta directiva solo tiene efecto cuando este módulo se usa para
    la autenticación.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthLDAPSearchAsUser</name>
<description>Usar las credenciales del usuario autenticado para realizar
las búsquedas de autorización</description>
<syntax>AuthLDAPSearchAsUser on|off</syntax>
<default>AuthLDAPSearchAsUser off</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>
<compatibility>Disponible desde la versión 2.3.6</compatibility>

<usage>
    <p>Cuando se establece, y <module>mod_authnz_ldap</module> ha
    autenticado al usuario, las búsquedas LDAP para la autorización usan
    el nombre distinguido (DN) obtenido en la consulta y la contraseña de
    autenticación HTTP basic del usuario autenticado, en lugar de las
    credenciales configuradas en el servidor.</p>

    <p> Las comprobaciones de autorización <code>ldap-filter</code> y
    <code>ldap-dn</code> usan búsquedas.</p>

    <p>Esta directiva solo tiene efecto en las comparaciones realizadas
    durante el procesamiento de grupos anidados cuando también está
    activada <directive module="mod_authnz_ldap">
    AuthLDAPCompareAsUser</directive>.</p>

    <p> Esta directiva solo debería usarse cuando su servidor LDAP no
        acepta búsquedas anónimas y no puede usar un <directive
        module="mod_authnz_ldap">AuthLDAPBindDN</directive> dedicado.
    </p>
</usage>
<seealso><directive module="mod_authnz_ldap">AuthLDAPInitialBindAsUser</directive></seealso>
<seealso><directive module="mod_authnz_ldap">AuthLDAPCompareAsUser</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>AuthLDAPSubGroupAttribute</name>
<description>Especifica las etiquetas de atributo, un valor por línea de
directiva, usadas para distinguir los miembros del grupo actual que son
grupos.</description>
<syntax>AuthLDAPSubGroupAttribute <var>attribute</var></syntax>
<default>AuthLDAPSubGroupAttribute member uniqueMember</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>
<compatibility>Disponible desde la versión 2.3.0</compatibility>

<usage>
    <p>Un objeto de grupo LDAP puede contener miembros que son usuarios y
    miembros que son grupos (denominados grupos anidados o subgrupos). La
    directiva <directive>AuthLDAPSubGroupAttribute</directive> identifica
    las etiquetas de los miembros de grupo, y la directiva <directive
    module="mod_authnz_ldap">AuthLDAPGroupAttribute</directive>
    identifica las etiquetas de los miembros de usuario. Se pueden usar
    varios atributos indicando esta directiva varias veces. Si no se
    indica, <module>mod_authnz_ldap</module> usa los atributos
    <code>member</code> y <code>uniqueMember</code>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthLDAPSubGroupClass</name>
<description>Especifica qué valores objectClass de LDAP identifican
objetos de directorio que son grupos durante el procesamiento de
subgrupos.</description>
<syntax>AuthLDAPSubGroupClass <var>LdapObjectClass</var></syntax>
<default>AuthLDAPSubGroupClass groupOfNames groupOfUniqueNames</default>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>
<compatibility>Disponible desde la versión 2.3.0</compatibility>

<usage>
    <p>Un objeto de grupo LDAP puede contener miembros que son usuarios y
    miembros que son grupos (denominados grupos anidados o subgrupos). La
    directiva <directive module="mod_authnz_ldap">AuthLDAPSubGroupAttribute</directive>
    identifica las etiquetas de los miembros que pueden ser subgrupos del
    grupo actual (en contraposición a miembros de usuario). La directiva
    <directive>AuthLDAPSubGroupClass</directive> especifica los valores
    objectClass de LDAP usados para verificar que estos posibles
    subgrupos son realmente objetos de grupo. Los subgrupos verificados
    pueden entonces buscarse para encontrar más miembros de usuario o de
    subgrupo. Se pueden usar varios atributos indicando esta directiva
    varias veces. Si no se indica, <module>mod_authnz_ldap</module> usa
    los valores <code>groupOfNames</code> y
    <code>groupOfUniqueNames</code>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>AuthLDAPURL</name>
<description>URL que especifica los parámetros de búsqueda LDAP</description>
<syntax>AuthLDAPURL <var>url</var> [NONE|SSL|TLS|STARTTLS]</syntax>
<contextlist><context>directory</context><context>.htaccess</context>
</contextlist>
<override>AuthConfig</override>

<usage>
    <p>Una URL de RFC 2255 que indica los parámetros de búsqueda
    LDAP a usar. La sintaxis de la URL es</p>
<example>ldap://host:port/basedn?attribute?scope?filter</example>
    <p>Si quiere indicar más de una URL LDAP que Apache deba probar por
    turnos, la sintaxis es:</p>
<highlight language="config">
AuthLDAPURL "ldap://ldap1.example.com ldap2.example.com/dc=..."
</highlight>
<note type="warning"><title>Advertencia</title>
<p>Si indica varios servidores, necesita encerrar toda la cadena de la
URL entre comillas; de lo contrario obtendrá un error: "AuthLDAPURL
takes one argument, URL to define LDAP connection.." Por supuesto, puede
usar parámetros de búsqueda en cada una de ellas.</p>
</note>

<dl>
<dt>ldap</dt>

        <dd>Para LDAP normal, use la cadena
        <code>ldap</code>. Para LDAP seguro, use <code>ldaps</code> en su
        lugar. El LDAP seguro solo está disponible si Apache se enlazó
        con una biblioteca LDAP con soporte SSL.</dd>

<dt>host:port</dt>

        <dd>
          <p>El nombre/puerto del servidor ldap (por defecto
          <code>localhost:389</code> para <code>ldap</code>, y
          <code>localhost:636</code> para <code>ldaps</code>). Para
          indicar varios servidores LDAP redundantes, simplemente liste
          todos los servidores, separados por espacios.
          <module>mod_authnz_ldap</module> intentará conectar con cada
          servidor por turnos, hasta que consiga una conexión exitosa. Si
          se indican varios servidores ldap, entonces toda la URL LDAP
          debe encerrarse entre comillas dobles.</p>

          <p>Una vez establecida una conexión con un servidor, esa
          conexión permanece activa durante toda la vida del proceso
          <program>httpd</program>, o hasta que el servidor LDAP se
          caiga.</p>

          <p>Si el servidor LDAP se cae y rompe una conexión existente,
          <module>mod_authnz_ldap</module> intentará reconectar,
          empezando por el servidor principal, y probando cada servidor
          redundante por turnos. Tenga en cuenta que esto es distinto de
          una búsqueda round-robin real.</p>
        </dd>

<dt>basedn</dt>

        <dd>El DN de la rama del directorio desde donde deben empezar
        todas las búsquedas. Como mínimo, debe ser la parte superior de
        su árbol de directorio, pero también podría indicar un subárbol
        del directorio.</dd>

<dt>attribute</dt>

        <dd>El atributo a buscar. Aunque RFC 2255 permite una
        lista de atributos separada por comas, solo se usará el primer
        atributo, independientemente de cuántos se proporcionen. Si no
        se proporciona ningún atributo, el valor por defecto es usar
        <code>uid</code>. Es buena idea elegir un atributo que sea único
        en todas las entradas del subárbol que vaya a usar. Todos los
        atributos listados se colocarán en el entorno con un prefijo
        AUTHENTICATE_ para que los usen otros módulos.</dd>

<dt>scope</dt>

        <dd>El alcance de la búsqueda. Puede ser <code>one</code> o
        <code>sub</code>. Tenga en cuenta que RFC 2255 también
        soporta un alcance <code>base</code>, pero este módulo no lo
        soporta. Si no se proporciona el alcance, o si se indica el
        alcance <code>base</code>, el valor por defecto es usar un
        alcance <code>sub</code>.</dd>

<dt>filter</dt>

        <dd>Un filtro de búsqueda LDAP válido. Si no se proporciona, el
        valor por defecto es <code>(objectClass=*)</code>, que buscará
        todos los objetos del árbol. Los filtros están limitados a
        aproximadamente 8000 caracteres (la definición de
        <code>MAX_STRING_LEN</code> en el código fuente de Apache). Esto
        debería ser más que suficiente para cualquier aplicación. En la
        versión 2.4.10 y posteriores, la palabra clave <code>none</code>
        desactiva el uso de un filtro; esto es necesario en algunos
        servidores LDAP primitivos.</dd>
</dl>

    <p>Al hacer búsquedas, el atributo, el filtro y el nombre de usuario
    pasado por el cliente HTTP se combinan para crear un filtro de
    búsqueda con esta forma
    <code>(&amp;(<var>filter</var>)(<var>attribute</var>=<var>username</var>))</code>.</p>

    <p>Por ejemplo, considere una URL
    <code>ldap://ldap.example.com/o=Example?cn?sub?(posixid=*)</code>.
    Cuando un cliente intenta conectar usando un nombre de usuario
    <code>Babs Jenson</code>, el filtro de búsqueda resultante será
    <code>(&amp;(posixid=*)(cn=Babs Jenson))</code>.</p>

    <p>Se puede añadir un parámetro opcional para permitir que la URL
    LDAP sobrescriba el tipo de conexión. Este parámetro puede ser uno de
    los siguientes:</p>

<dl>
    <dt>NONE</dt>
        <dd>Establece una conexión no segura en el puerto LDAP por
        defecto. Esto es lo mismo que <code>ldap://</code> en el puerto
        389.</dd>
    <dt>SSL</dt>
        <dd>Establece una conexión segura en el puerto LDAP seguro por
        defecto. Esto es lo mismo que <code>ldaps://</code></dd>
    <dt>TLS | STARTTLS</dt>
        <dd>Establece una conexión segura mediante actualización en el
        puerto LDAP por defecto. Esta conexión se iniciará en el puerto
        389 por defecto y después se actualizará a una conexión segura
        en el mismo puerto.</dd>
</dl>

    <p>Consulte arriba ejemplos de URLs de <directive
    module="mod_authnz_ldap">AuthLDAPURL</directive>.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
