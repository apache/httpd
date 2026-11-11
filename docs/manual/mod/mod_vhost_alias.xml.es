<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933743 -->
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

<modulesynopsis metafile="mod_vhost_alias.xml.meta">

<name>mod_vhost_alias</name>
<description>Proporciona alojamiento virtual masivo configurado
dinámicamente</description>
<status>Extension</status>
<sourcefile>mod_vhost_alias.c</sourcefile>
<identifier>vhost_alias_module</identifier>

<summary>
    <p>Este módulo crea hosts virtuales configurados dinámicamente,
    permitiendo que la dirección IP y/o la cabecera <code>Host:</code>
    de la petición HTTP se usen como parte del nombre de ruta para
    determinar qué archivos servir. Esto permite usar fácilmente un
    gran número de hosts virtuales con configuraciones similares.</p>

    <note><title>Nota</title>
      <p>Si se usan <module>mod_alias</module> o <module>mod_userdir</module>
      para traducir URIs a nombres de archivo, estos tendrán prioridad
      sobre las directivas de <module>mod_vhost_alias</module> descritas
      a continuación. Por ejemplo, la siguiente configuración asignará
      <code>/cgi-bin/script.pl</code> a <code>
      /usr/local/apache2/cgi-bin/script.pl</code> en todos los casos:</p>

      <highlight language="config">
ScriptAlias "/cgi-bin/" "/usr/local/apache2/cgi-bin/"
VirtualScriptAlias "/never/found/%0/cgi-bin/"
      </highlight>
    </note>
</summary>

<seealso><directive module="core">UseCanonicalName</directive></seealso>
<seealso><a href="../vhosts/mass.html">Alojamiento virtual masivo
    configurado dinámicamente</a></seealso>

<section id="interpol">
    <title>Interpolación del nombre de directorio</title>

    <p>Todas las directivas de este módulo interpolan una cadena en
    un nombre de ruta. La cadena interpolada (en adelante llamada el
    "nombre") puede ser el nombre del servidor (vea la directiva
    <directive module="core">UseCanonicalName</directive>
    para más detalles sobre cómo se determina esto) o la dirección IP
    del host virtual en el servidor, en formato decimal con puntos. La
    interpolación se controla mediante especificadores inspirados en
    <code>printf</code>, que tienen varios formatos:</p>

    <note><title>Nota</title>
    <p>El directorio interpolado debe ser una ruta absoluta. El
    valor especial <code>none</code> puede usarse para desactivar la
    directiva.</p>
    </note>

<table>
<columnspec><column width=".2"/><column width=".6"/></columnspec>
<tr><td><code>%%</code></td>
<td>inserta un <code>%</code></td></tr>

<tr><td><code>%p</code></td>
<td>inserta el número de puerto del host virtual</td></tr>

<tr><td><code>%N.M</code></td>
<td>inserta (parte de) el nombre</td></tr>

</table>

    <p><code>N</code> y <code>M</code> se usan para especificar
    subcadenas del nombre. <code>N</code> selecciona entre los
    componentes del nombre separados por puntos, y <code>M</code>
    selecciona caracteres dentro de lo que <code>N</code> haya
    seleccionado. <code>M</code> es opcional y toma el valor cero por
    defecto si no está presente; el punto debe estar presente si y
    solo si <code>M</code> está presente. La interpretación es la
    siguiente:</p>

    <table>
      <columnspec><column width=".1"/><column width=".4"/></columnspec>
      <tr><td><code>0</code></td>
      <td>el nombre completo</td></tr>

      <tr><td><code>1</code></td>
      <td>la primera parte</td></tr>

      <tr><td><code>2</code></td>
      <td>la segunda parte</td></tr>

      <tr><td><code>-1</code></td>
      <td>la última parte</td></tr>

      <tr><td><code>-2</code></td>
      <td>la penúltima parte</td></tr>

      <tr><td><code>2+</code></td>
      <td>la segunda parte y todas las siguientes</td></tr>

      <tr><td><code>-2+</code></td>
      <td>la penúltima parte y todas las anteriores</td></tr>

      <tr><td><code>1+</code> y <code>-1+</code></td>
      <td>lo mismo que <code>0</code></td></tr>
    </table>

    <p>Si <code>N</code> o <code>M</code> son mayores que el número
    de partes disponibles, se interpola un único guion bajo. </p>

</section>

<section id="examples">
    <title>Ejemplos</title>

    <p>Para hosts virtuales simples basados en nombre podría usar
    las siguientes directivas en el archivo de configuración de su
    servidor:</p>

    <highlight language="config">
UseCanonicalName    Off
VirtualDocumentRoot "/usr/local/apache/vhosts/%0"
    </highlight>

    <p>Una petición de
    <code>http://www.example.com/directory/file.html</code> se
    satisfará con el archivo
    <code>/usr/local/apache/vhosts/www.example.com/directory/file.html</code>.
    </p>

    <p>Para un número muy grande de hosts virtuales es buena idea
    organizar los archivos para reducir el tamaño del directorio
    <code>vhosts</code>. Para ello podría usar lo siguiente en su
    archivo de configuración:</p>

    <highlight language="config">
UseCanonicalName    Off
VirtualDocumentRoot "/usr/local/apache/vhosts/%3+/%2.1/%2.2/%2.3/%2"
    </highlight>

    <p>Una petición de
    <code>http://www.domain.example.com/directory/file.html</code>
    se satisfará con el archivo
    <code>/usr/local/apache/vhosts/example.com/d/o/m/domain/directory/file.html</code>.</p>

    <p>Se puede lograr una distribución más uniforme de los archivos
    aplicando un hash desde el final del nombre, por ejemplo: </p>

<highlight language="config">
VirtualDocumentRoot "/usr/local/apache/vhosts/%3+/%2.-1/%2.-2/%2.-3/%2"
</highlight>

    <p>La petición del ejemplo provendría de
    <code>/usr/local/apache/vhosts/example.com/n/i/a/domain/directory/file.html</code>.</p>

    <p>Alternativamente podría usar: </p>

<highlight language="config">
VirtualDocumentRoot "/usr/local/apache/vhosts/%3+/%2.1/%2.2/%2.3/%2.4+"
</highlight>

    <p>La petición del ejemplo provendría de
    <code>/usr/local/apache/vhosts/example.com/d/o/m/ain/directory/file.html</code>.</p>

<p> Una petición muy habitual de los usuarios es poder dirigir varios dominios a varias
raíces de documentos sin tener que preocuparse por la longitud o el número de partes del
nombre de host solicitado. Si el nombre de host solicitado es <code>sub.www.domain.example.com</code>
en lugar de simplemente <code>www.domain.example.com</code>, entonces usar %3+ hará que la raíz de
documentos sea <code>/usr/local/apache/vhosts/domain.example.com/...</code> en lugar del
directorio <code>example.com</code> deseado. En estos casos, puede ser conveniente usar
la combinación <code>%-2.0.%-1.0</code>, que siempre dará el nombre de dominio y el
tld, por ejemplo <code>example.com</code>, independientemente del número de subdominios añadidos
al nombre de host. De este modo, se puede crear una configuración que dirija todos los subdominios
de primer, segundo o tercer nivel al mismo directorio:
</p>
<highlight language="config">
VirtualDocumentRoot "/usr/local/apache/vhosts/%-2.0.%-1.0"
</highlight>
<p>
En el ejemplo anterior, tanto <code>www.example.com</code> como <code>www.sub.example.com</code>
o <code>example.com</code> apuntarán todos a <code>/usr/local/apache/vhosts/example.com</code>.
</p>

    <p>Para hosts virtuales basados en IP podría usar lo siguiente en
    su archivo de configuración:</p>

    <highlight language="config">
UseCanonicalName DNS
VirtualDocumentRootIP "/usr/local/apache/vhosts/%1/%2/%3/%4/docs"
VirtualScriptAliasIP  "/usr/local/apache/vhosts/%1/%2/%3/%4/cgi-bin"
    </highlight>

    <p>Una petición de
    <code>http://www.domain.example.com/directory/file.html</code>
    se satisfaría con el archivo
    <code>/usr/local/apache/vhosts/10/20/30/40/docs/directory/file.html</code>
    si la dirección IP de <code>www.domain.example.com</code> fuera
    10.20.30.40. Una petición de
    <code>http://www.domain.example.com/cgi-bin/script.pl</code> se
    satisfaría ejecutando el programa
    <code>/usr/local/apache/vhosts/10/20/30/40/cgi-bin/script.pl</code>.</p>

    <p>Si desea incluir el carácter <code>.</code> en una directiva
    <code>VirtualDocumentRoot</code>, pero entra en conflicto con
    un especificador <code>%</code>, puede evitar el problema de la
    siguiente manera:</p>

    <highlight language="config">
VirtualDocumentRoot "/usr/local/apache/vhosts/%2.0.%3.0"
    </highlight>

    <p>Una petición de
    <code>http://www.domain.example.com/directory/file.html</code>
    se satisfará con el archivo
    <code>/usr/local/apache/vhosts/domain.example/directory/file.html</code>.</p>

    <p>Las directivas <directive module="mod_log_config">LogFormat</directive>
    <code>%V</code> y <code>%A</code> son útiles
    junto con este módulo.</p>
</section>

<directivesynopsis>
<name>VirtualDocumentRoot</name>
<description>Configura dinámicamente la ubicación de la raíz de
documentos de un host virtual dado</description>
<syntax>VirtualDocumentRoot <em>interpolated-directory</em>|none</syntax>
<default>VirtualDocumentRoot none</default>
<contextlist>
<context>server config</context>
<context>virtual host</context>
</contextlist>

<usage>

    <p>La directiva <directive>VirtualDocumentRoot</directive> le permite
    determinar dónde encontrará Apache HTTP Server sus documentos en función del
    valor del nombre del servidor. El resultado de expandir
    <em>interpolated-directory</em> se usa como raíz del árbol de
    documentos de forma similar al argumento de la directiva
    <directive module="core">DocumentRoot</directive>.
    Si <em>interpolated-directory</em> es <code>none</code>, entonces
    <directive>VirtualDocumentRoot</directive> se desactiva. Esta directiva
    no puede usarse en el mismo contexto que <directive
    module="mod_vhost_alias">VirtualDocumentRootIP</directive>.</p>

<note type="warning"><title>Nota</title>
<directive>VirtualDocumentRoot</directive> tendrá prioridad sobre cualquier directiva
<directive module="core">DocumentRoot</directive> que haya puesto en el mismo
contexto o en contextos hijos. Poner <directive>VirtualDocumentRoot</directive>
en el ámbito global del servidor tendrá, en la práctica, prioridad sobre las directivas
<directive module="core">DocumentRoot</directive> en cualquier host virtual definido más
adelante, a menos que establezca <directive>VirtualDocumentRoot</directive> a <code>None</code>
en cada host virtual.
</note>

</usage>

</directivesynopsis>

<directivesynopsis>
<name>VirtualDocumentRootIP</name>
<description>Configura dinámicamente la ubicación de la raíz de
documentos de un host virtual dado</description>
<syntax>VirtualDocumentRootIP <em>interpolated-directory</em>|none</syntax>
<default>VirtualDocumentRootIP none</default>
<contextlist>
<context>server config</context>
<context>virtual host</context>
</contextlist>

<usage>

<p>La directiva <directive>VirtualDocumentRootIP</directive> es como la
    directiva <directive module="mod_vhost_alias">VirtualDocumentRoot</directive>,
    salvo que usa la dirección IP del extremo del servidor de la
    conexión para la interpolación del directorio en lugar del nombre
    del servidor.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>VirtualScriptAlias</name>
<description>Configura dinámicamente la ubicación del directorio CGI para
un host virtual dado</description>
<syntax>VirtualScriptAlias <em>interpolated-directory</em>|none</syntax>
<default>VirtualScriptAlias none</default>
<contextlist>
<context>server config</context>
<context>virtual host</context>
</contextlist>

<usage>

    <p>La directiva <directive>VirtualScriptAlias</directive> le permite
    determinar dónde encontrará Apache httpd los scripts CGI de forma
    similar a como lo hace <directive module="mod_vhost_alias"
    >VirtualDocumentRoot</directive> para otros documentos. Coincide con
    las peticiones de URIs que empiezan por <code>/cgi-bin/</code>, de
    forma similar a como lo haría <directive
    module="mod_alias">ScriptAlias</directive>
    <code>/cgi-bin/</code>.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>VirtualScriptAliasIP</name>
<description>Configura dinámicamente la ubicación del directorio CGI para
un host virtual dado</description>
<syntax>VirtualScriptAliasIP <em>interpolated-directory</em>|none</syntax>
<default>VirtualScriptAliasIP none</default>
<contextlist>
<context>server config</context>
<context>virtual host</context>
</contextlist>

<usage>

    <p>La directiva <directive>VirtualScriptAliasIP</directive> es como la
    directiva <directive module="mod_vhost_alias">VirtualScriptAlias</directive>,
    salvo que usa la dirección IP del extremo del servidor de la
    conexión para la interpolación del directorio en lugar del nombre
    del servidor.</p>

    </usage>

</directivesynopsis>
</modulesynopsis>
