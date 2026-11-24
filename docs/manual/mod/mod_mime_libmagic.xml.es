<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
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

<modulesynopsis metafile="mod_mime_libmagic.xml.meta">

<name>mod_mime_libmagic</name>
<description>Determina el tipo MIME de un archivo a partir de su contenido
    usando libmagic</description>
<status>Extension</status>
<sourcefile>mod_mime_libmagic.c</sourcefile>
<identifier>mime_libmagic_module</identifier>
<compatibility>Disponible en Apache 2.5.1 y posteriores</compatibility>

<summary>
    <p>Este módulo determina el <glossary ref="mime-type">tipo MIME
    </glossary> de un archivo examinando su contenido, de la misma
    manera que lo hace el comando <code>file(1)</code>. Está pensado como una
    "segunda línea de defensa" para los archivos que
    <module>mod_mime</module> no puede tipar a partir de su extensión: se
    ejecuta después de <module>mod_mime</module> y no hace nada si ya se ha
    establecido un tipo.</p>

    <p>A diferencia de <module>mod_mime_magic</module>, que tiene su propia
    copia del motor de <code>file(1)</code> y su propia base de datos
    magic, este módulo usa la biblioteca <code>libmagic(3)</code> del
    sistema y la base de datos magic del paquete <code>file</code>,
    de manera que los tipos que informa son los mismos que informaría <code>file --mime-type</code>.
    El módulo solo se compila si libmagic se encuentra en el momento de
    configuración, y solo está activo en un servidor o host virtual
    donde <directive module="mod_mime_libmagic">MimeLibmagic</directive>
    está en <code>On</code>.</p>

    <p>Cuando libmagic informa <code>application/octet-stream</code>,
    el módulo no establece ningún tipo, dejando la respuesta sin cabecera
    <code>Content-Type</code>, tal como hace <module>mod_mime_magic</module>
    para el contenido no reconocido. Los directorios se tipan como
    <code>httpd/unix-directory</code> y los archivos vacíos como
    <code>text/plain</code>.</p>

    <p>El módulo no examina el interior de los archivos comprimidos y nunca
    establece un <code>Content-Encoding</code>: un archivo gzip se informa como
    <code>application/gzip</code>. Esto difiere de
    <module>mod_mime_magic</module>, que informa de la codificación del
    archivo comprimido.</p>
</summary>

<seealso><module>mod_mime</module></seealso>
<seealso><module>mod_mime_magic</module></seealso>

<section id="threads"><title>Rendimiento y sobrecarga de memoria</title>

    <p>Se crea un manejador de libmagic, se carga con la base de datos magic
    y se destruye en cada petición examinada. Cargar una base de datos compilada
    (<code>magic.mgc</code>) mapea el archivo en memoria en lugar de
    analizarlo, y las páginas mapeadas se comparten entre todos los procesos
    del servidor, por lo que esto es poco costoso. Si la base de datos configurada
    es un archivo de texto en lugar de uno compilado, se analiza en cada
    petición.</p>

    <p>Solo se leen y examinan los primeros <directive module="mod_mime_libmagic"
    >MimeLibmagicBytes</directive> bytes de un archivo, sea cual sea su
    tamaño.</p>

    <p>Examinar contenido de texto en particular puede asignar temporalmente unos
    pocos megabytes de memoria. Con un MPM con hilos y una biblioteca C
    que mantiene un heap independiente por hilo, cada hilo del servidor
    retiene su asignación máxima, por lo que el tamaño residente de un
    proceso hijo ocupado puede crecer en esa cantidad por hilo antes de
    estabilizarse. Esto no es una fuga de memoria.</p>
</section>

<directivesynopsis>
<name>MimeLibmagic</name>
<description>Activa la determinación del tipo MIME a partir del contenido del archivo</description>
<syntax>MimeLibmagic On|Off</syntax>
<default>MimeLibmagic Off</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>MimeLibmagic</directive> activa el
    módulo para un servidor o host virtual. Los archivos que
    <module>mod_mime</module> deja sin tipo, normalmente aquellos sin
    una extensión reconocida, tienen entonces su contenido examinado por
    libmagic.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
MimeLibmagic On
    </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>MimeLibmagicFile</name>
<description>La base de datos magic a usar</description>
<syntax>MimeLibmagicFile <var>file-path</var></syntax>
<default>La base de datos por defecto de la libmagic instalada</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>MimeLibmagicFile</directive> indica
    la base de datos magic, en lugar de la que viene compilada por defecto en
    libmagic (normalmente <code>/usr/share/misc/magic</code>, para la cual
    se carga el archivo <code>magic.mgc</code> compilado que la acompaña).
    La base de datos debe tener el formato descrito en
    <code>magic(5)</code>; el archivo distribuido con
    <module>mod_mime_magic</module> no es adecuado. Una ruta relativa
    se toma relativa a <directive module="core"
    >ServerRoot</directive>. Si la base de datos no se puede cargar, se
    registra un error por cada petición examinada y el archivo queda
    sin tipo.</p>

    <p>Tenga en cuenta que la variable de entorno <code>MAGIC</code>, si está
    definida cuando se inicia el servidor, sustituye al valor por defecto de la
    biblioteca, pero no a una base de datos indicada con esta directiva.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
MimeLibmagicFile /usr/share/misc/magic.mgc
    </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>MimeLibmagicBytes</name>
<description>Número de bytes de un archivo examinados</description>
<syntax>MimeLibmagicBytes <var>bytes</var></syntax>
<default>MimeLibmagicBytes 16384</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>MimeLibmagicBytes</directive> establece
    cuántos bytes desde el inicio de un archivo se leen y examinan.
    Los valores más altos permiten que las reglas magic que miran más adentro de un archivo
    puedan coincidir, a costa de leer más de cada archivo examinado. El
    máximo es 1048576.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>MimeLibmagicCharset</name>
<description>Añade un parámetro charset a los tipos de texto</description>
<syntax>MimeLibmagicCharset On|Off</syntax>
<default>MimeLibmagicCharset Off</default>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>Cuando <directive>MimeLibmagicCharset</directive> está en
    <code>On</code>, la codificación de caracteres que detecta libmagic (como
    <code>us-ascii</code>, <code>utf-8</code> o
    <code>iso-8859-1</code>) se añade como parámetro <code>charset</code>
    a los tipos <code>text/*</code>, dando por ejemplo
    <code>text/plain; charset=utf-8</code>. Los demás tipos no se ven
    afectados. Como con <directive module="core"
    >AddDefaultCharset</directive>, solo se debe confiar en el charset
    detectado cuando se sabe que el contenido está codificado de
    manera consistente.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
