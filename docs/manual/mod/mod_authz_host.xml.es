<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933687 -->
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

<modulesynopsis metafile="mod_authz_host.xml.meta">

<name>mod_authz_host</name>
<description>Autorizaciones de grupo basadas en el host (nombre o
dirección IP)</description>
<status>Base</status>
<sourcefile>mod_authz_host.c</sourcefile>
<identifier>authz_host_module</identifier>
<compatibility>El proveedor <code>forward-dns</code> se añadió en la versión 2.4.19</compatibility>

<summary>
    <p>Los proveedores de autorización implementados por <module>mod_authz_host</module> se
    registran mediante la directiva <directive module="mod_authz_core">Require</directive>.
    La directiva se puede referenciar dentro de una sección
    <directive module="core" type="section">Directory</directive>,
    <directive module="core" type="section">Files</directive>,
    o <directive module="core" type="section">Location</directive>,
    así como en archivos <code><a href="core.html#accessfilename">.htaccess</a>
    </code>, para controlar el acceso a partes concretas del servidor.
    El acceso puede controlarse en función del nombre de host o la dirección IP del cliente.</p>

    <p>En general, las directivas de restricción de acceso se aplican a todos
    los métodos de acceso (<code>GET</code>, <code>PUT</code>,
    <code>POST</code>, etc.). Este es el comportamiento deseado en la mayoría
    de los casos. Sin embargo, es posible restringir algunos métodos, dejando
    otros sin restringir, incluyendo las directivas
    en una sección <directive module="core" type="section">Limit</directive>.</p>
</summary>

<seealso><a href="../howto/auth.html">Autenticación, autorización
    y control de acceso</a></seealso>
<seealso><directive module="mod_authz_core">Require</directive></seealso>
<seealso><a href="mod_authz_core.html#authzresults">Estados de resultado de autorización</a></seealso>

<section id="requiredirectives"><title>Las directivas Require</title>

    <p>La directiva <directive module="mod_authz_core">Require</directive>
    de Apache se usa durante la fase de autorización para garantizar que a un usuario se le permite o
    deniega el acceso a un recurso. mod_authz_host amplía
    los tipos de autorización con <code>ip</code>, <code>host</code>,
    <code>forward-dns</code> y <code>local</code>.
    También se pueden usar otros tipos de autorización, pero
    pueden requerir que se carguen módulos de autorización adicionales.</p>

    <p>Estos proveedores de autorización afectan a qué hosts pueden
    acceder a un área del servidor. El acceso puede controlarse
    por nombre de host, dirección IP, o rango de direcciones IP.</p>

    <p>Desde la v2.4.8, las <a href="../expr.html">expresiones</a> son compatibles
    dentro de las directivas require basadas en host.</p>

<section id="reqip"><title>Require ip</title>

    <p>El proveedor <code>ip</code> permite controlar el acceso al servidor
    en función de la dirección IP del cliente remoto.
    Cuando se especifica <code>Require ip <var>ip-address</var></code>,
    se permite el acceso a la petición si la dirección IP coincide.</p>

    <p>Una dirección IP completa:</p>

    <highlight language="config">
Require ip 10.1.2.3
Require ip 192.168.1.104 192.168.1.205
    </highlight>

    <p>Una dirección IP de un host al que se le permite el acceso</p>

    <p>Una dirección IP parcial:</p>

    <highlight language="config">
Require ip 10.1
Require ip 10 172.20 192.168.2
    </highlight>
    <p>Los primeros 1 a 3 bytes de una dirección IP, para restricción
    de subred.</p>

    <p>Un par red/máscara de red:</p>

    <highlight language="config">
      Require ip 10.1.0.0/255.255.0.0
    </highlight>
    <p>Una red a.b.c.d, y una máscara de red w.x.y.z. Para una
    restricción de subred más detallada.</p>

    <p>Una especificación de red/nnn CIDR:</p>

    <highlight language="config">
      Require ip 10.1.0.0/16
    </highlight>
    <p>Similar al caso anterior, salvo que la máscara de red consiste en
    nnn bits de orden superior a 1.</p>

    <p>Observe que los tres últimos ejemplos anteriores coinciden exactamente con el
    mismo conjunto de hosts.</p>

    <p>Las direcciones IPv6 y las subredes IPv6 se pueden especificar como se muestra
    a continuación:</p>

    <highlight language="config">
Require ip 2001:db8::a00:20ff:fea7:ccea
Require ip 2001:db8:1:1::a
Require ip 2001:db8:2:1::/64
Require ip 2001:db8:3::/48
    </highlight>

    <p>Nota: Como las direcciones IP se analizan al arrancar, las expresiones
    no se evalúan en el momento de la petición.</p>

</section>

<section id="reqhost"><title>Require host</title>

    <p>El proveedor <code>host</code> permite controlar el acceso al servidor
    en función del nombre de host del cliente remoto.
    Cuando se especifica <code>Require host <var>host-name</var></code>,
    se permite el acceso a la petición si el nombre de host coincide.</p>

    <p>Un nombre de dominio (parcial)</p>

    <highlight language="config">
Require host example.org
Require host .net example.edu
    </highlight>

    <p>Se permite el acceso a los hosts cuyos nombres coinciden con, o terminan en,
    esta cadena. Solo coinciden componentes completos, de modo que el
    ejemplo anterior coincidirá con <code>foo.example.org</code>, pero no
    coincidirá con <code>fooexample.org</code>. Esta configuración hará que
    Apache realice una doble búsqueda inversa de DNS sobre la dirección IP
    del cliente, independientemente del valor de la directiva
    <directive module="core">HostnameLookups</directive>. Realizará
    una búsqueda inversa de DNS sobre la dirección IP para encontrar el
    nombre de host asociado, y después una búsqueda directa sobre el nombre de host para asegurarse
    de que coincide con la dirección IP original. Solo si la DNS directa
    e inversa son coherentes y el nombre de host coincide se
    permitirá el acceso.</p>

</section>

<section id="reqfwddns"><title>Require forward-dns</title>

    <p>El proveedor <code>forward-dns</code> permite controlar el acceso al servidor
    en función de nombres de host simples. Cuando se especifica
    <code>Require forward-dns <var>host-name</var></code>,
    se permite el acceso a todas las direcciones IP correspondientes a
    <code><var>host-name</var></code>.</p>

    <p>A diferencia del proveedor <code>host</code>, este proveedor no
    depende de búsquedas inversas de DNS: simplemente consulta la DNS para obtener el nombre de host
    y permite el acceso a un cliente si su IP coincide. Como consecuencia, solo
    funcionará con nombres de host completos que se puedan resolver en DNS, no con nombres de dominio parciales.
    Sin embargo, como no se usa la DNS inversa, y las búsquedas de DNS se producen en el momento del procesamiento
    de la petición (en lugar de al arrancar), funcionará con clientes que usen un servicio de DNS dinámico.</p>

    <highlight language="config">
Require forward-dns dynamic.example.org
    </highlight>

    <p>Se concederá acceso a un cliente cuya IP se resuelva a partir del nombre
    <code>dynamic.example.org</code>.</p>

    <p>El proveedor <code>forward-dns</code> se añadió en la versión 2.4.19.</p>
</section>

<section id="reqlocal"><title>Require local</title>

    <p>El proveedor <code>local</code> permite el acceso al servidor si se cumple
    alguna de las siguientes condiciones:</p>

    <ul>
        <li>la dirección del cliente coincide con 127.0.0.0/8</li>
        <li>la dirección del cliente es ::1</li>
        <li>la dirección del cliente y la del servidor de la conexión son
        la misma</li>
    </ul>

    <p>Esto permite una forma conveniente de coincidir con conexiones que se originan
    en el host local:</p>

    <highlight language="config">
    Require local
    </highlight>

</section>

<section id="proxy"><title>Nota de seguridad</title>

    <p>Si está reenviando contenido a su servidor mediante proxy, debe tener en cuenta
    que la dirección del cliente será la dirección de su servidor proxy,
    no la dirección del cliente, por lo que usar la directiva <code>Require</code>
    en este contexto puede no hacer lo que usted espera. Consulte
    <module>mod_remoteip</module> para una posible solución a este
    problema.</p>

</section>

</section>

</modulesynopsis>
