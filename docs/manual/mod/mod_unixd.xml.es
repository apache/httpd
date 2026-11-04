<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1874187 -->
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

<modulesynopsis metafile="mod_unixd.xml.meta">

<name>mod_unixd</name>
<description>Seguridad básica (obligatoria) para plataformas de la familia Unix.</description>
<status>Base</status>
<sourcefile>mod_unixd.c</sourcefile>
<identifier>unixd_module</identifier>

<seealso><a href="../suexec.html">Soporte de suEXEC</a></seealso>

<directivesynopsis>
<name>Group</name>
<description>Grupo bajo el cual el servidor responderá a las
peticiones</description>
<syntax>Group <var>unix-group</var></syntax>
<default>Group #-1</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>La directiva <directive>Group</directive> establece el grupo bajo el
    cual el servidor responderá a las peticiones. Para usar esta
    directiva, el servidor debe iniciarse inicialmente como <code>root</code>. Si
    inicia el servidor como un usuario sin privilegios de root, no podrá cambiar al
    grupo especificado y, en su lugar, seguirá ejecutándose con el grupo del
    usuario original. <var>Unix-group</var> puede ser uno de:</p>

    <dl>
      <dt>Un nombre de grupo</dt>
      <dd>Hace referencia al grupo indicado por su nombre.</dd>

      <dt><code>#</code> seguido de un número de grupo.</dt>
      <dd>Hace referencia a un grupo por su número.</dd>
    </dl>

    <example><title>Ejemplo</title>
    <highlight language="config">
      Group www-group
      </highlight>
    </example>

    <p>Se recomienda configurar un nuevo grupo específicamente para
    ejecutar el servidor. Si el <directive>User</directive> configurado
    es miembro de algún grupo suplementario, el proceso también
    se convertirá en miembro de esos grupos.</p>

    <note type="warning"><title>Seguridad</title>
      <p>No establezca <directive>Group</directive> (ni <directive
      module="mod_unixd">User</directive>) a <code>root</code> a menos que
      sepa exactamente lo que está haciendo y cuáles son los riesgos.
      No se recomienda usar el grupo <code>nobody</code>,
      que no está pensado para su uso por demonios de ejecución prolongada.</p>
    </note>

</usage>
<seealso><directive module="mod_privileges">VHostGroup</directive></seealso>
<seealso><directive module="mod_suexec">SuexecUserGroup</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>User</name>
<description>El ID de usuario bajo el cual el servidor responderá a las
peticiones</description>
<syntax>User <var>unix-userid</var></syntax>
<default>User #-1</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>La directiva <directive>User</directive> establece el ID de usuario con el
    que el servidor responderá a las peticiones. Para usar esta
    directiva, el servidor debe iniciarse inicialmente como <code>root</code>.
    Si inicia el servidor como un usuario sin privilegios de root, no podrá cambiar
    al usuario con menos privilegios y, en su lugar, seguirá ejecutándose como
    ese usuario original. Si inicia el servidor como <code>root</code>,
    es normal que el proceso padre siga ejecutándose como root.
    <var>Unix-userid</var> puede ser uno de:</p>

    <dl>
      <dt>Un nombre de usuario</dt>
      <dd>Hace referencia al usuario indicado por su nombre.</dd>

      <dt># seguido de un número de usuario.</dt>
      <dd>Hace referencia a un usuario por su número.</dd>
    </dl>

    <p>El usuario no debería tener privilegios que le permitan
    acceder a archivos que no están pensados para ser visibles desde el
    exterior y, del mismo modo, el usuario no debería poder
    ejecutar código que no esté destinado a peticiones HTTP. Se
    recomienda configurar un nuevo usuario y grupo específicamente para
    ejecutar el servidor.</p>

    <note type="warning"><title>Seguridad</title>
      <p>No establezca <directive>User</directive> (ni <directive
      module="mod_unixd">Group</directive>) a <code>root</code> a menos que
      sepa exactamente lo que está haciendo y cuáles son los riesgos.
      No se recomienda usar el usuario <code>nobody</code>,
      que no está pensado para su uso por demonios de ejecución prolongada.</p>
    </note>

</usage>
<seealso><directive module="mod_privileges">VHostUser</directive></seealso>
<seealso><directive module="mod_suexec">SuexecUserGroup</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>ChrootDir</name>
<description>Directorio en el que apache ejecuta chroot(8) tras el arranque.</description>
<syntax>ChrootDir <var>/path/to/directory</var></syntax>
<default>none</default>
<contextlist><context>server config</context></contextlist>
<modulelist><module>mod_unixd</module></modulelist>

<usage>
    <p>Esta directiva indica al servidor que haga <var>chroot(8)</var> al
    directorio especificado tras el arranque, pero antes de aceptar peticiones
    de la red.</p>
    <p>Tenga en cuenta que ejecutar el servidor bajo chroot no es sencillo,
    y requiere una configuración adicional, especialmente si está ejecutando
    scripts como CGI o PHP. Asegúrese de estar bien
    familiarizado con el funcionamiento de chroot antes de intentar usar
    esta característica.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>Suexec</name>
<description>Activa o desactiva la característica suEXEC</description>
<syntax>Suexec On|Off</syntax>
<default>On si el binario suexec existe con el propietario y modo adecuados,
Off en caso contrario</default>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Cuando está en On, el arranque fallará si el binario suexec no existe
    o tiene un propietario o modo de archivo no válido.</p>
    <p>Cuando está en Off, suEXEC se desactivará aunque el binario suexec exista
    y tenga un propietario y modo de archivo válidos.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
