<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1936574 -->
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

<modulesynopsis metafile="mod_privileges.xml.meta">

<name>mod_privileges</name>
<description>Soporte para privilegios de Solaris y para ejecutar hosts virtuales
bajo distintos ID de usuario.</description>
<status>Deprecated</status>
<sourcefile>mod_privileges.c</sourcefile>
<identifier>privileges_module</identifier>
<compatibility>Disponible en Apache 2.3 y posteriores, en las plataformas Solaris 10 y
OpenSolaris</compatibility>

<summary>
<p>Este módulo permite que distintos hosts virtuales se ejecuten con distintos
ID de <var>User</var> y <var>Group</var> de Unix, y con distintos
<a href="https://docs.oracle.com/cd/E19253-01/816-4863/6mb20lvfd/index.html"
>privilegios de Solaris</a>. En particular, ofrece una solución al
problema de la separación de privilegios entre distintos hosts virtuales, prometida
inicialmente por el abandonado MPM perchild. También ofrece otras mejoras de
seguridad.</p>

<p>A diferencia de perchild, <module>mod_privileges</module>
no es en sí mismo un MPM. Funciona <em>dentro</em> de un modelo de procesamiento para
establecer privilegios y User/Group <em>por cada petición</em> en un proceso en ejecución.
Por lo tanto, no es compatible con un MPM con hilos, y se negará
a ejecutarse bajo uno.</p>

<p><module>mod_privileges</module> plantea problemas de seguridad similares a
los de <a href="../suexec.html">suexec</a>. Pero, a diferencia de suexec,
se aplica no solo a los programas CGI, sino a todo el ciclo de procesamiento
de la petición, incluidas las aplicaciones y subprocesos en proceso.
Es especialmente adecuado para ejecutar aplicaciones PHP bajo <strong>mod_php</strong>,
que tampoco es compatible con los MPM con hilos. También es muy adecuado
para otras aplicaciones de scripting en proceso, como <strong>mod_perl</strong>,
<strong>mod_python</strong> y <strong>mod_ruby</strong>, y para
aplicaciones implementadas en C como módulos de apache donde la separación
de privilegios es un problema a tener en cuenta.</p>

</summary>

<section id="security"><title>Consideraciones de seguridad</title>

<p><module>mod_privileges</module> introduce nuevos problemas de seguridad
en situaciones en las que puede ejecutarse <strong>código no confiable</strong>
<strong>dentro del proceso del servidor web</strong>. Esto se aplica a
módulos no confiables, y a scripts ejecutados bajo módulos como
mod_php o mod_perl. Los scripts que se ejecutan externamente (por ejemplo, como CGI
o en un servidor de aplicaciones detrás de mod_proxy o mod_jk) NO se ven
afectados.</p>

<p>Los problemas de seguridad básicos de mod_privileges son:</p>
<ul><li>Ejecutarse como un usuario del sistema introduce los mismos problemas de
    seguridad que mod_suexec, y equivalentes cercanos como cgiwrap y suphp.</li>
<li>Una extensión de usuario maliciosa (módulo o script) que conozca el
    funcionamiento de los privilegios podría escalar sus privilegios a cualquier cosa disponible
    para el proceso httpd en cualquier host virtual. Esto introduce nuevos riesgos
    si (y solo si) mod_privileges se compila con la
    opción <var>BIG_SECURITY_HOLE</var>.</li>
<li>Una extensión de usuario maliciosa (módulo o script) que conozca el
    funcionamiento de los privilegios podría escalar privilegios para establecer su ID de usuario
    como el de otro usuario (y/o grupo) del sistema.</li>
</ul>

<p>La directiva <directive>PrivilegesMode</directive> le permite
elegir el modo <var>FAST</var> o <var>SECURE</var>. Puede
mezclar modos, usando el modo <var>FAST</var> para usuarios de confianza y
rutas de código completamente auditadas, mientras impone el modo SECURE donde un
usuario no confiable tiene margen para introducir código.</p>
<p>Antes de describir los modos, debemos también presentar los casos de uso
objetivo: Benigno frente a Hostil. En una situación benigna, quiere
separar a los usuarios por su comodidad, y protegerlos a ellos y al servidor
frente a los riesgos que plantean errores honestos, pero confía en que sus usuarios
no están subvirtiendo deliberadamente la seguridad del sistema. En una situación
hostil (por ejemplo, el hosting comercial) puede tener usuarios atacando
deliberadamente el sistema o atacándose entre sí.</p>
<dl>
<dt>Modo FAST</dt>
<dd>En el modo <var>FAST</var>, las peticiones se ejecutan en proceso con el
uid/gid y los privilegios seleccionados, por lo que la sobrecarga es insignificante.
Esto es adecuado para situaciones benignas, pero no es seguro frente a un
atacante que escale privilegios con un módulo o script en proceso.</dd>
<dt>Modo SECURE</dt>
<dd>Una petición en modo <var>SECURE</var> lanza un subproceso, que
después libera los privilegios. Este es un caso muy similar al de ejecutar CGI
con suexec, pero para todo el ciclo de la petición, y con la ventaja
de un control detallado de los privilegios.</dd>
</dl>
<p>Puede seleccionar distintos modos de <directive>PrivilegesMode</directive> para
cada host virtual, e incluso en un contexto de directorio dentro de un host
virtual. El modo <var>FAST</var> es apropiado cuando el usuario o usuarios son
de confianza y/o no tienen privilegios para cargar código en proceso.
El modo <var>SECURE</var> es apropiado para los casos en los que podría ejecutarse
código no confiable en proceso. Sin embargo, incluso en modo <var>SECURE</var>,
no hay protección frente a un usuario malicioso que sea capaz de
introducir código que conozca el funcionamiento de los privilegios y se ejecute <em>antes del inicio del
ciclo de procesamiento de la petición.</em></p>

</section>
<directivesynopsis>
<name>PrivilegesMode</name>
<description>Compensa velocidad y eficiencia de procesamiento frente a seguridad contra
código malicioso que conozca el funcionamiento de los privilegios.</description>
<syntax>PrivilegesMode FAST|SECURE|SELECTIVE</syntax>
<default>PrivilegesMode FAST</default>
<contextlist>
	<context>server config</context>
	<context>virtual host</context>
	<context>directory</context>
</contextlist>
<compatibility>Disponible en Solaris 10 y OpenSolaris con
MPM sin hilos (<module>prefork</module> o un MPM personalizado).</compatibility>
<usage><p>Esta directiva compensa rendimiento frente a seguridad contra
código malicioso que conozca el funcionamiento de los privilegios. En modo <var>SECURE</var>, cada petición
se ejecuta en un subproceso seguro, lo que supone una penalización considerable de rendimiento.
En modo <var>FAST</var>, el servidor no está protegido frente a la escalada
de privilegios como se ha explicado antes.</p>
<p>Esta directiva se comporta de forma ligeramente distinta entre un contexto
	<code>&lt;Directory&gt;</code> (incluidos equivalentes como Location/Files/If) y uno
	de nivel superior o <code>&lt;VirtualHost&gt;</code>.</p>
<p>En el nivel superior, establece un valor por defecto que heredarán los hosts virtuales.
	En un host virtual, el modo FAST o SECURE actúa sobre toda la
	petición HTTP, y cualquier configuración en un contexto
	<code>&lt;Directory&gt;</code> será <strong>ignorada</strong>. Un tercer pseudomodo,
	SELECTIVE, difiere la elección entre FAST y SECURE a las directivas en un
	contexto <code>&lt;Directory&gt;</code>.</p>
<p>En un contexto <code>&lt;Directory&gt;</code>, solo es aplicable
	cuando se ha establecido el modo SELECTIVE para el VirtualHost. En este
	contexto solo pueden establecerse FAST o SECURE (SELECTIVE no
tendría sentido).</p>
<note type="warning"><title>Advertencia</title>
	Cuando se selecciona el modo SELECTIVE para un host virtual, la activación
	de los privilegios debe retrasarse hasta <em>después</em> de que la fase
	de mapeo del procesamiento de la petición haya determinado qué
	contexto <code>&lt;Directory&gt;</code> se aplica a la petición.
	Esto podría dar a un atacante la oportunidad de introducir
	código a través de un <directive module="mod_rewrite">RewriteMap</directive>
	que se ejecute en el contexto de nivel superior o <code>&lt;VirtualHost&gt;</code>
	<em>antes</em> de que se hayan liberado los privilegios y se haya establecido el userid/gid.
</note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>VHostUser</name>
<description>Establece el ID de usuario con el que se ejecuta un host virtual.</description>
<syntax>VHostUser <var>unix-userid</var></syntax>
<default>Hereda el userid especificado en
<directive module="mod_unixd">User</directive></default>
<contextlist><context>virtual host</context></contextlist>
<compatibility>Disponible en Solaris 10 y OpenSolaris con
MPM sin hilos (<module>prefork</module> o un MPM personalizado).</compatibility>

<usage>
    <p>La directiva <directive>VHostUser</directive> establece el userid de Unix
    con el que el servidor procesará las peticiones a un host virtual.
    El userid se establece antes de procesar la petición y se restablece después,
    usando <a
    href="https://docs.oracle.com/cd/E19253-01/816-4863/6mb20lvfd/index.html"
    >privilegios de Solaris</a>. Dado que la configuración se aplica al
    <em>proceso</em>, esto no es compatible con los MPM con hilos.</p>
    <p><var>Unix-userid</var> es uno de los siguientes:</p>
    <dl>
      <dt>Un nombre de usuario</dt>
      <dd>Hace referencia al usuario indicado por su nombre.</dd>

      <dt><code>#</code> seguido de un número de usuario.</dt>
      <dd>Hace referencia a un usuario por su número.</dd>
    </dl>

    <note type="warning"><title>Seguridad</title>
    <p>¡Esta directiva no se puede usar para ejecutar apache como root!
    No obstante, abre posibles problemas de seguridad similares a
    los tratados en la documentación de
    <a href="../suexec.html">suexec</a>.</p></note>
</usage>
<seealso><directive module="mod_unixd">User</directive></seealso>
<seealso><directive module="mod_suexec">SuexecUserGroup</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>VHostGroup</name>
<description>Establece el ID de grupo con el que se ejecuta un host virtual.</description>
<syntax>VHostGroup <var>unix-groupid</var></syntax>
<default>Hereda el id de grupo especificado en
<directive module="mod_unixd">Group</directive></default>
<contextlist><context>virtual host</context></contextlist>
<compatibility>Disponible en Solaris 10 y OpenSolaris con
MPM sin hilos (<module>prefork</module> o un MPM personalizado).</compatibility>

<usage>
    <p>La directiva <directive>VHostGroup</directive> establece el grupo de Unix
    con el que el servidor procesará las peticiones a un host virtual.
    El grupo se establece antes de procesar la petición y se restablece después,
    usando <a
    href="https://docs.oracle.com/cd/E19253-01/816-4863/6mb20lvfd/index.html"
    >privilegios de Solaris</a>. Dado que la configuración se aplica al
    <em>proceso</em>, esto no es compatible con los MPM con hilos.</p>
    <p><var>Unix-group</var> es uno de los siguientes:</p>
    <dl>
      <dt>Un nombre de grupo</dt>
      <dd>Hace referencia al grupo indicado por su nombre.</dd>

      <dt><code>#</code> seguido de un número de grupo.</dt>
      <dd>Hace referencia a un grupo por su número.</dd>
    </dl>

    <note type="warning"><title>Seguridad</title>
    <p>¡Esta directiva no se puede usar para ejecutar apache como root!
    No obstante, abre posibles problemas de seguridad similares a
    los tratados en la documentación de
    <a href="../suexec.html">suexec</a>.</p></note>
</usage>
<seealso><directive module="mod_unixd">Group</directive></seealso>
<seealso><directive module="mod_suexec">SuexecUserGroup</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>VHostSecure</name>
<description>Determina si el servidor se ejecuta con seguridad reforzada
para el host virtual.</description>
<syntax>VHostSecure On|Off</syntax>
<default>VHostSecure On</default>
<contextlist><context>virtual host</context></contextlist>
<compatibility>Disponible en Solaris 10 y OpenSolaris con
MPM sin hilos (<module>prefork</module> o un MPM personalizado).</compatibility>

<usage>
    <p>Determina si el host virtual procesa las peticiones con
    la seguridad reforzada mediante la eliminación de los <a
    href="https://docs.oracle.com/cd/E19253-01/816-4863/6mb20lvfd/index.html"
    >privilegios</a> que rara vez se necesitan en un servidor web, pero que
    están disponibles por defecto para un usuario normal de Unix y por lo tanto
    pueden ser necesarios para módulos y aplicaciones. Se recomienda
    mantener el valor por defecto (On) a menos que impida la ejecución de alguna
    aplicación. Dado que la configuración se aplica al <em>proceso</em>, esto no es
    compatible con los MPM con hilos.</p>
    <note><title>Nota</title>
    <p>Si <directive>VHostSecure</directive> impide la ejecución de una
    aplicación, esto puede ser una señal de advertencia de que conviene
    revisar la seguridad de dicha aplicación.</p></note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>VHostCGIMode</name>
<description>Determina si el host virtual puede ejecutar
subprocesos, y los privilegios disponibles para los subprocesos.</description>
<syntax>VHostCGIMode On|Off|Secure</syntax>
<default>VHostCGIMode On</default>
<contextlist><context>virtual host</context></contextlist>
<compatibility>Disponible en Solaris 10 y OpenSolaris con
MPM sin hilos (<module>prefork</module> o un MPM personalizado).</compatibility>

<usage>
    <p>Determina si al host virtual se le permite ejecutar fork y exec,
    los <a
    href="https://docs.oracle.com/cd/E19253-01/816-4863/6mb20lvfd/index.html"
    >privilegios</a> necesarios para ejecutar subprocesos. Si se establece en
    <var>Off</var>, se deniegan al host virtual esos privilegios y no
    podrá ejecutar los programas o scripts CGI tradicionales bajo el
    tradicional <module>mod_cgi</module>, ni programas externos similares, como los
    creados por <module>mod_ext_filter</module> o por
    <directive module="mod_rewrite">RewriteMap</directive> <var>prog</var>.
    Tenga en cuenta que esto no impide la ejecución de programas CGI bajo modelos
    alternativos de proceso y seguridad, como <a href="https://httpd.apache.org/mod_fcgid/"
    >mod_fcgid</a>, que es una solución recomendada en Solaris.</p>
    <p>Si se establece en <var>On</var> o <var>Secure</var>, se permite al host
    virtual ejecutar programas y scripts externos como se ha descrito arriba.
    Establecer <directive>VHostCGIMode</directive> en <var>Secure</var> tiene
    el efecto de denegar privilegios a los subprocesos, tal y como se describe
    para <directive>VHostSecure</directive>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>DTracePrivileges</name>
<description>Determina si se activan los privilegios necesarios para dtrace.</description>
<syntax>DTracePrivileges On|Off</syntax>
<default>DTracePrivileges Off</default>
<contextlist><context>server config</context></contextlist>
<compatibility>Disponible en Solaris 10 y OpenSolaris con
MPM sin hilos (<module>prefork</module> o un MPM personalizado).</compatibility>

<usage>
    <p>Esta directiva, de ámbito global al servidor, determina si Apache se ejecutará con
    los <a
    href="https://docs.oracle.com/cd/E19253-01/816-4863/6mb20lvfd/index.html"
    >privilegios</a> necesarios para ejecutar
    <a href="https://docs.oracle.com/cd/E19253-01/819-5488/gbwaz/index.html">dtrace</a>.
    Tenga en cuenta que <var>DTracePrivileges On</var> no activará por sí
    mismo DTrace, pero <var>DTracePrivileges Off</var> impedirá que
    funcione.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>VHostPrivs</name>
<description>Asigna privilegios arbitrarios a un host virtual.</description>
<syntax>VHostPrivs [+-]?<var>privilege-name</var> [[+-]?privilege-name] ...</syntax>
<default>None</default>
<contextlist><context>virtual host</context></contextlist>
<compatibility>Disponible en Solaris 10 y OpenSolaris con
MPM sin hilos (<module>prefork</module> o un MPM personalizado)
y cuando <module>mod_privileges</module> se compila con la
opción de compilación <var>BIG_SECURITY_HOLE</var>.</compatibility>

<usage>
    <p><directive>VHostPrivs</directive> se puede usar para asignar <a
    href="https://docs.oracle.com/cd/E19253-01/816-4863/6mb20lvfd/index.html"
    >privilegios</a> arbitrarios a un host virtual. Cada <var>privilege-name</var>
    es el nombre de un privilegio de Solaris, como <var>file_setid</var>
    o <var>sys_nfs</var>.</p>

    <p>Un <var>privilege-name</var> puede ir opcionalmente precedido por
    + o -, que respectivamente permitirán o denegarán un privilegio.
    Si no se usa ni + ni -, se denegarán todos los privilegios que de otro modo
    se asignarían al host virtual. Puede usar esto para sobrescribir
    cualquiera de los conjuntos por defecto y construir su propio conjunto de privilegios.</p>

    <note type="warning"><title>Seguridad</title>
    <p>Esta directiva puede abrir enormes agujeros de seguridad en apache, hasta
    el punto de permitir ejecutar peticiones con privilegios de nivel root. No la
    use a menos que entienda completamente lo que está haciendo.</p></note>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>VHostCGIPrivs</name>
<description>Asigna privilegios arbitrarios a los subprocesos creados
por un host virtual.</description>
<syntax>VHostCGIPrivs [+-]?<var>privilege-name</var> [[+-]?privilege-name] ...</syntax>
<default>None</default>
<contextlist><context>virtual host</context></contextlist>
<compatibility>Disponible en Solaris 10 y OpenSolaris con
MPM sin hilos (<module>prefork</module> o un MPM personalizado)
y cuando <module>mod_privileges</module> se compila con la
opción de compilación <var>BIG_SECURITY_HOLE</var>.</compatibility>

<usage>
    <p><directive>VHostCGIPrivs</directive> se puede usar para asignar <a
    href="https://docs.oracle.com/cd/E19253-01/816-4863/6mb20lvfd/index.html"
    >privilegios</a> arbitrarios a los subprocesos creados por un host virtual, tal y como se
    explica en <directive>VHostCGIMode</directive>. Cada <var>privilege-name</var>
    es el nombre de un privilegio de Solaris, como <var>file_setid</var>
    o <var>sys_nfs</var>.</p>

    <p>Un <var>privilege-name</var> puede ir opcionalmente precedido por
    + o -, que respectivamente permitirán o denegarán un privilegio.
    Si no se usa ni + ni -, se denegarán todos los privilegios que de otro modo
    se asignarían al host virtual. Puede usar esto para sobrescribir
    cualquiera de los conjuntos por defecto y construir su propio conjunto de privilegios.</p>

    <note type="warning"><title>Seguridad</title>
    <p>Esta directiva puede abrir enormes agujeros de seguridad en los subprocesos de apache,
    hasta el punto de permitir ejecutarlos con privilegios de nivel root. No la
    use a menos que entienda completamente lo que está haciendo.</p></note>
</usage>
</directivesynopsis>



</modulesynopsis>
