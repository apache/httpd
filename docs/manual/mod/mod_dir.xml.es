<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933851 -->
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

<modulesynopsis metafile="mod_dir.xml.meta">
<name>mod_dir</name>
<description>Proporciona redirecciones de "barra final" y
    sirve archivos de índice de directorio</description>
<status>Base</status>
<sourcefile>mod_dir.c</sourcefile>
<identifier>dir_module</identifier>

<summary>
    <p>El índice de un directorio puede proceder de una de dos fuentes:</p>

    <ul>
      <li>Un archivo escrito por el usuario, normalmente llamado
      <code>index.html</code>. La directiva <directive module="mod_dir"
      >DirectoryIndex</directive> establece el
      nombre de este archivo. Esto lo controla
      <module>mod_dir</module>.</li>

      <li>En caso contrario, un listado generado por el servidor. Esto lo
      proporciona <module>mod_autoindex</module>.</li>
    </ul>
    <p>Las dos funciones están separadas para que pueda eliminar (o
    reemplazar) por completo la generación automática de índices si así lo
    desea.</p>

    <p>Se emite una redirección de "barra final" cuando el servidor
    recibe una petición para una URL
    <code>http://servername/foo/dirname</code> donde
    <code>dirname</code> es un directorio. Los directorios requieren una
    barra final, por lo que <module>mod_dir</module> emite una redirección a
    <code>http://servername/foo/dirname/</code>.</p>
</summary>

<directivesynopsis>
<name>DirectoryIndex</name>
<description>Lista de recursos a buscar cuando el cliente solicita
un directorio</description>
<syntax>DirectoryIndex
    disabled | <var>local-url</var> [<var>local-url</var>] ...</syntax>
<default>DirectoryIndex index.html</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>Indexes</override>

<usage>
    <p>La directiva <directive>DirectoryIndex</directive> establece la
    lista de recursos a buscar cuando el cliente solicita un índice
    del directorio especificando una / al final del nombre del
    directorio. <var>Local-url</var> es la URL (codificada con %) de un documento en
    el servidor relativa al directorio solicitado; normalmente es el
    nombre de un archivo en el directorio. Pueden indicarse varias URLs, en
    cuyo caso el servidor devolverá la primera que encuentre. Si
    ninguno de los recursos existe y la opción <code>Indexes</code> está
    activada, el servidor generará su propio listado del
    directorio.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      DirectoryIndex index.html
      </highlight>
    </example>

    <p>entonces una petición de <code>http://example.com/docs/</code>
    devolvería <code>http://example.com/docs/index.html</code> si
    existe, o listaría el directorio si no existiera.</p>

    <p>Tenga en cuenta que los documentos no necesitan ser relativos al
    directorio;</p>

    <highlight language="config">
      DirectoryIndex index.html index.txt  /cgi-bin/index.pl
    </highlight>

    <p>haría que se ejecutara el script CGI <code>/cgi-bin/index.pl</code>
    si no existieran <code>index.html</code> ni <code>index.txt</code>
    en un directorio.</p>

    <p>Un único argumento "disabled" evita que <module>mod_dir</module>
    busque un índice. Un argumento "disabled" se interpretará
    literalmente si tiene algún argumento antes o después de él, aunque sean "disabled"
    también.</p>

    <note>Varias directivas <directive>DirectoryIndex</directive>
    dentro del <a href="../sections.html"><em>mismo contexto</em></a> se añadirán
    a la lista de recursos a buscar en lugar de sustituirla:
    </note>
    <highlight language="config">
# Ejemplo A: Establece index.html como página de índice y añade index.php a esa lista también.
&lt;Directory "/foo"&gt;
    DirectoryIndex index.html
    DirectoryIndex index.php
&lt;/Directory&gt;

# Ejemplo B: Es idéntico al ejemplo A, salvo que se hace con una sola directiva.
&lt;Directory "/foo"&gt;
    DirectoryIndex index.html index.php
&lt;/Directory&gt;

# Ejemplo C: Para sustituir la lista, debe reiniciarla explícitamente primero:
# En este ejemplo, solo index.php permanecerá como recurso de índice.
&lt;Directory "/foo"&gt;
    DirectoryIndex index.html
    DirectoryIndex disabled
    DirectoryIndex index.php
&lt;/Directory&gt;
    </highlight>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>DirectoryIndexRedirect</name>
<description>Configura una redirección externa para los índices de directorio.
</description>
<syntax>DirectoryIndexRedirect on | off | permanent | temp | seeother |
<var>3xx-code</var>
</syntax>
<default>DirectoryIndexRedirect off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>Indexes</override>
<compatibility>Disponible en la versión 2.3.14 y posteriores</compatibility>

<usage>
    <p>Por defecto, el <directive>DirectoryIndex</directive> se selecciona
    y se devuelve al cliente de forma transparente. <directive
    >DirectoryIndexRedirect</directive> hace que se emita en su lugar
    una redirección externa.</p>

    <p>El argumento puede ser:</p>
    <ul>
     <li><code>on</code>: emite una redirección 302 al recurso de índice.</li>
     <li><code>off</code>: no emite ninguna redirección. Este es el comportamiento heredado de mod_dir.</li>
     <li><code>permanent</code>: emite una redirección 301 (permanente) al recurso de índice.</li>
     <li><code>temp</code>: tiene el mismo efecto que <code>on</code></li>
     <li><code>seeother</code>: emite una redirección 303 (también conocida como "See Other") al recurso de índice.</li>
     <li><var>3xx-code</var>: emite una redirección marcada con el código 3xx elegido.</li>
    </ul>


    <example><title>Ejemplo</title>
    <highlight language="config">
      DirectoryIndexRedirect on
      </highlight>
    </example>

    <p>Una petición de <code>http://example.com/docs/</code>
    devolvería una redirección temporal a <code
    >http://example.com/docs/index.html</code>
    si existe.</p>

</usage>
</directivesynopsis>


<directivesynopsis>
<name>DirectorySlash</name>
<description>Activa o desactiva las redirecciones de barra final</description>
<syntax>DirectorySlash On|Off</syntax>
<default>DirectorySlash On</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>Indexes</override>

<usage>
    <p>La directiva <directive>DirectorySlash</directive> determina si
    <module>mod_dir</module> debe corregir las URLs que apuntan a un
    directorio o no.</p>

    <p>Normalmente, si un usuario solicita un recurso sin barra final que
    apunta a un directorio, <module>mod_dir</module> lo redirige al mismo
    recurso, pero <em>con</em> barra final, por varias buenas razones:</p>

    <ul>
    <li>El usuario finalmente está solicitando la URL canónica del recurso</li>
    <li><module>mod_autoindex</module> funciona correctamente. Como no emite
    la ruta en el enlace, apuntaría a la ruta incorrecta.</li>
    <li><directive module="mod_dir">DirectoryIndex</directive> se evaluará
    <em>solo</em> para los directorios solicitados con barra final.</li>
    <li>Las referencias a URLs relativas dentro de páginas html funcionarán correctamente.</li>
    </ul>

    <p>Si no desea este efecto <em>y</em> las razones anteriores no se le
    aplican, puede desactivar la redirección como se muestra a continuación. Sin
    embargo, tenga en cuenta que hacerlo puede tener implicaciones de seguridad.</p>

    <highlight language="config">
# ¡vea la advertencia de seguridad más abajo!
&lt;Location "/some/path"&gt;
    DirectorySlash Off
    SetHandler some-handler
&lt;/Location&gt;
    </highlight>

    <note type="warning"><title>Advertencia de seguridad</title>
    <p>Desactivar la redirección de barra final puede dar lugar a una
    divulgación de información. Considere una situación en la que
    <module>mod_autoindex</module> está activo (<code>Options +Indexes</code>)
    y <directive module="mod_dir">DirectoryIndex</directive> está establecido a un
    recurso válido (por ejemplo, <code>index.html</code>) y no hay ningún otro
    gestor especial definido para esa URL. En este caso, una petición con barra
    final mostraría el archivo <code>index.html</code>. <strong>Pero una petición
    sin barra final listaría el contenido del directorio</strong>.</p>
    </note>
	<p>Tenga también en cuenta que algunos navegadores pueden convertir erróneamente
	peticiones POST en GET (descartando así los datos POST) cuando se emite una
	redirección.</p>
</usage>
</directivesynopsis>
<directivesynopsis>
<name>FallbackResource</name>
<description>Define una URL por defecto para las peticiones que no corresponden a un archivo o gestor</description>
<syntax>FallbackResource disabled | <var>local-url</var></syntax>
<default>disabled - httpd devolverá 404 (Not Found)</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>Indexes</override>
<compatibility>El argumento <code>disabled</code> está disponible en la versión 2.4.4 y
posteriores</compatibility>
<usage>
    <p>Use esto para establecer un gestor para cualquier URL que no corresponda a nada
    en su sistema de archivos, y que de otro modo devolvería HTTP 404 (Not Found).
    Por ejemplo</p>
    <highlight language="config">
        FallbackResource /not-404.php
    </highlight>
    <p>hará que las peticiones de archivos inexistentes sean gestionadas por
    <code>not-404.php</code>, mientras que las peticiones de archivos que sí
    existen no se ven afectadas.</p>
    <p>A menudo resulta conveniente que un único archivo o recurso
    gestione todas las peticiones a un directorio concreto, excepto aquellas
    que correspondan a un archivo o script existente. Esto se suele
    denominar un "controlador frontal" ('front controller').</p>
    <p>En versiones anteriores de httpd, este efecto normalmente requería
    <module>mod_rewrite</module> y el uso de las comprobaciones <code>-f</code> y
    <code>-d</code> para la existencia de archivos y directorios. Ahora esto
    solo requiere una línea de configuración.</p>
    <highlight language="config">
        FallbackResource /index.php
    </highlight>
    <p>Los archivos existentes, como imágenes, archivos css, etc., se
    servirán con normalidad.</p>
    <p>Use el argumento <code>disabled</code> para desactivar esta función
    si no se desea la herencia desde un directorio padre.</p>
    <p>En una sub-URI, como <em>http://example.com/blog/</em>, esta
    <em>sub-URI</em> debe indicarse como <var>local-url</var>:</p>
    <highlight language="config">
&lt;Directory "/web/example.com/htdocs/blog"&gt;
    FallbackResource /blog/index.php
&lt;/Directory&gt;
&lt;Directory "/web/example.com/htdocs/blog/images"&gt;
    FallbackResource disabled
&lt;/Directory&gt;
    </highlight>
    <p>Un gestor de reserva (en el caso anterior, <code>/blog/index.php</code>)
    puede acceder a la URL solicitada originalmente mediante la variable de
    servidor <code>REQUEST_URI</code>. Por ejemplo, para acceder a esta variable en PHP,
    use <code>$_SERVER['REQUEST_URI']</code>.</p>
    <note><title>Interacción con otros gestores</title>
    <p><directive>FallbackResource</directive> solo tiene efecto cuando no se
    ha asignado ningún otro gestor a la petición. Si una directiva como
    <directive module="core">SetHandler</directive> o
    <directive module="mod_mime">AddHandler</directive> ya ha
    asignado un gestor a una URL o extensión de archivo,
    <directive>FallbackResource</directive> no lo anulará. Por
    ejemplo, si usa
    <code>SetHandler application/x-httpd-php</code> en una
    sección <directive type="section" module="core">Directory</directive>,
    ese gestor se aplica a todas las peticiones de ese directorio, incluso las
    peticiones de archivos inexistentes, por lo que <directive>FallbackResource</directive>
    nunca se invocará.</p></note>
</usage>
<seealso><directive module="core">SetHandler</directive></seealso>
<seealso><directive module="mod_mime">AddHandler</directive></seealso>
<seealso><directive module="mod_dir">DirectoryCheckHandler</directive></seealso>
</directivesynopsis>
<directivesynopsis>
<name>DirectoryCheckHandler</name>
<description>Activa o desactiva cómo responde este módulo cuando hay otro gestor configurado</description>
<syntax>DirectoryCheckHandler On|Off</syntax>
<default>DirectoryCheckHandler Off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>Indexes</override>
<compatibility>Disponible en la versión 2.4.8 y posteriores. Las versiones anteriores a 2.4
se comportan implícitamente como si se hubiera especificado "DirectoryCheckHandler ON".</compatibility>
<usage>
    <p>La directiva <directive>DirectoryCheckHandler</directive> determina
    si <module>mod_dir</module> debe comprobar los índices de directorio o
    añadir barras finales cuando se ha configurado algún otro gestor para
    la URL actual. Los gestores pueden establecerse mediante directivas como
    <directive module="core">SetHandler</directive> o por otros módulos,
    como <module>mod_rewrite</module> durante las sustituciones por
    directorio.</p>

    <p>Cuando se establece en <code>On</code>, <module>mod_dir</module>
    no realizará ninguna acción si ya se ha configurado otro gestor
    para la URL.</p>

    <p>Cuando se establece en <code>Off</code> (el valor por defecto),
    <module>mod_dir</module> procesará la petición independientemente de
    cualquier otro gestor que pueda estar configurado. Esto permite servir
    índices de directorio incluso cuando se especifica una directiva
    <directive>SetHandler</directive> para todo un directorio, pero también
    puede provocar conflictos con módulos como <module>mod_rewrite</module>.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
