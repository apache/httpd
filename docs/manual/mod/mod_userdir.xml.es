<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1875785 -->
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

<modulesynopsis metafile="mod_userdir.xml.meta">

<name>mod_userdir</name>
<description>Directorios específicos de usuario</description>
<status>Base</status>
<sourcefile>mod_userdir.c</sourcefile>
<identifier>userdir_module</identifier>

<summary>
<note type="warning">Al usar este módulo, está permitiendo que varios usuarios
alojen contenido dentro del mismo origen. La política del mismo origen es un
principio clave de Javascript y de la seguridad web. Al alojar páginas web en el mismo
origen, estas páginas pueden leerse y controlarse entre sí, y los problemas de seguridad en
una página pueden afectar a otra. Esto es especialmente peligroso en combinación
con páginas web que incluyen contenido dinámico y autenticación, y cuando
sus usuarios no necesariamente confían entre sí.</note>

<p>Este módulo permite acceder a directorios específicos de usuario usando la
sintaxis <code>http://example.com/~user/</code>.</p>
</summary>

<seealso><a href="../urlmapping.html">Correspondencia de URLs al
sistema de archivos</a></seealso>
<seealso><a href="../howto/public_html.html">tutorial de public_html
</a></seealso>

<directivesynopsis>

<name>UserDir</name>
<description>Ubicación de los directorios específicos de usuario</description>
<syntax>UserDir <em>directory-filename</em> [<em>directory-filename</em>] ...
</syntax>
<contextlist><context>server config</context> <context>virtual
host</context></contextlist>

<usage>

    <p>La directiva <directive>UserDir</directive> establece el
    directorio real dentro del directorio personal de un usuario que se usará cuando se recibe una petición de un
    documento para un usuario. <em>Directory-filename</em> es
    uno de los siguientes:</p>

    <ul>
      <li>El nombre de un directorio o un patrón como los que se muestran
      a continuación.</li>

      <li>La palabra clave <code>disabled</code>. Esto desactiva
      <em>todas</em> las traducciones de nombre de usuario a directorio, excepto las
      nombradas explícitamente con la palabra clave <code>enabled</code> (ver
      más abajo).</li>

      <li>La palabra clave <code>disabled</code> seguida de una
      lista de nombres de usuario separados por espacios. A los nombres de usuario que aparezcan en
      dicha lista <em>nunca</em> se les realizará la traducción de directorio,
      aunque aparezcan en una cláusula <code>enabled</code>.</li>

      <li>La palabra clave <code>enabled</code> seguida de una
      lista de nombres de usuario separados por espacios. A estos nombres de usuario se les
      realizará la traducción de directorio aunque haya una desactivación global
      en vigor, pero no si también aparecen en una cláusula
      <code>disabled</code>.</li>
    </ul>

    <p>Si ninguna de las palabras clave <code>enabled</code> ni
    <code>disabled</code> aparece en la directiva
    <directive>Userdir</directive>, el argumento se trata como un
    patrón de nombre de archivo, y se usa para convertir el nombre en una
    especificación de directorio. Una petición de
    <code>http://www.example.com/~bob/one/two.html</code> se
    traducirá a:</p>

    <table>
      <tr><th>Directiva UserDir usada</th>
          <th>Ruta traducida</th></tr>
      <tr><td>UserDir public_html</td>
          <td>~bob/public_html/one/two.html</td></tr>
      <tr><td>UserDir /usr/web</td>
          <td>/usr/web/bob/one/two.html</td></tr>
      <tr><td>UserDir /home/*/www</td>
          <td>/home/bob/www/one/two.html</td></tr>
    </table>

    <p>Las siguientes directivas enviarán redirecciones al cliente:</p>

    <table>
      <tr><th>Directiva UserDir usada</th>
          <th>Ruta traducida</th></tr>
      <tr><td>UserDir http://www.example.com/users</td>
          <td>http://www.example.com/users/bob/one/two.html</td></tr>
      <tr><td>UserDir http://www.example.com/*/usr</td>
          <td>http://www.example.com/bob/usr/one/two.html</td></tr>
      <tr><td>UserDir http://www.example.com/~*/</td>
          <td>http://www.example.com/~bob/one/two.html</td></tr>
    </table>

    <note>
      <strong>Tenga cuidado al usar esta directiva; por ejemplo,
      <code>"UserDir ./"</code> haría corresponder <code>"/~root"</code> con
      <code>"/"</code>, lo cual probablemente no sea deseable. Se recomienda
      encarecidamente que su configuración incluya una declaración
      "<code>UserDir disabled root</code>". Consulte también la directiva <directive
      module="core">Directory</directive> y la página de <a
      href="../misc/security_tips.html">Consejos de seguridad</a> para
      más información.</strong>
    </note>

    <p>Ejemplos adicionales:</p>

    <p>Para permitir que unos pocos usuarios tengan directorios <code>UserDir</code>, pero
    no el resto, use lo siguiente:</p>

    <highlight language="config">
UserDir disabled
UserDir enabled user1 user2 user3
    </highlight>

    <p>Para permitir que la mayoría de los usuarios tengan directorios <code>UserDir</code>, pero
    denegárselo a unos pocos, use lo siguiente:</p>

    <highlight language="config">
      UserDir disabled user4 user5 user6
    </highlight>

    <p>También es posible especificar directorios de usuario alternativos.
    Si usa un comando como:</p>

    <highlight language="config">
      UserDir "public_html" "/usr/web" "http://www.example.com/"
    </highlight>

    <p>Con una petición de
    <code>http://www.example.com/~bob/one/two.html</code>, se intentará
    encontrar la página primero en <code>~bob/public_html/one/two.html</code>, después en
    <code>/usr/web/bob/one/two.html</code>, y finalmente se enviará una
    redirección a <code>http://www.example.com/bob/one/two.html</code>.</p>

    <p>Si añade una redirección, debe ser la última alternativa de la lista.
    Apache httpd no puede determinar si la redirección tuvo éxito o no, así que si tiene
    la redirección antes en la lista, esa será siempre la alternativa
    que se use.</p>

    <p>La sustitución de directorio de usuario no está activa por defecto en las versiones
    2.1.4 y posteriores. En versiones anteriores, se asumía <code>UserDir public_html</code>
    si no había ninguna directiva <directive>UserDir</directive>
    presente.</p>

    <note><title>Detalles de la fusión</title>
    <p>Las listas de usuarios habilitados y deshabilitados específicos se sustituyen, no se fusionan,
    del ámbito global al del host virtual</p></note>

</usage>

<seealso>
  <a href="../howto/public_html.html">Tutorial de directorios web por usuario</a>
</seealso>

</directivesynopsis>
</modulesynopsis>

