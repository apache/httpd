<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1334018 -->
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

<modulesynopsis metafile="mod_mime_magic.xml.meta">

<name>mod_mime_magic</name>
<description>Determina el tipo MIME de un archivo
    examinando unos pocos bytes de su contenido</description>
<status>Extension</status>
<sourcefile>mod_mime_magic.c</sourcefile>
<identifier>mime_magic_module</identifier>

<summary>
    <p>Este módulo determina el <glossary ref="mime-type">tipo
    MIME</glossary> de los archivos del mismo modo que lo hace el comando
    Unix <code>file(1)</code>: examina los primeros bytes del archivo.
    Está pensado como una "segunda línea de defensa" para los casos que
    <module>mod_mime</module> no puede resolver.</p>

    <p>Este módulo se deriva de una versión libre del comando
    <code>file(1)</code> para Unix, que usa "números mágicos"
    y otras pistas del contenido de un archivo para determinar
    qué es ese contenido. Este módulo solo está activo si el archivo
    "magic" se especifica mediante la directiva <directive module="mod_mime_magic"
    >MimeMagicFile</directive>.</p>
</summary>

<section id="format"><title>Formato del archivo "magic"</title>

    <p>El contenido del archivo es texto ASCII plano en 4-5
    columnas. Se permiten líneas en blanco, pero se ignoran. Las líneas
    comentadas usan el carácter almohadilla (<code>#</code>). El resto de las
    líneas se analiza buscando las siguientes columnas:</p>

    <table style="zebra" border="1">
    <columnspec><column width=".15"/><column width=".8"/></columnspec>
    <tr><th>Columna</th><th>Descripción</th></tr>
    <tr><td>1</td>
        <td>número de byte desde el que empezar a comprobar<br />
         "<code>&gt;</code>" indica una dependencia de la línea anterior que
         no es "<code>&gt;</code>"</td></tr>

    <tr><td>2</td>
        <td><p>tipo de datos a comparar</p>
        <table border="1">
        <columnspec><column width=".2"/><column width=".7"/></columnspec>
        <tr><td><code>byte</code></td>
            <td>carácter único</td></tr>
        <tr><td><code>short</code></td>
            <td>entero de 16 bits en el orden de la máquina</td></tr>
        <tr><td><code>long</code></td>
            <td>entero de 32 bits en el orden de la máquina</td></tr>
        <tr><td><code>string</code></td>
            <td>cadena de longitud arbitraria</td></tr>
        <tr><td><code>date</code></td>
            <td>entero largo que representa una fecha (segundos desde el epoch de Unix/1970)</td></tr>
        <tr><td><code>beshort</code></td>
            <td>entero de 16 bits big-endian</td></tr>
        <tr><td><code>belong</code></td>
            <td>entero de 32 bits big-endian</td></tr>
        <tr><td><code>bedate</code></td>
            <td>fecha en entero de 32 bits big-endian</td></tr>
        <tr><td><code>leshort</code></td>
            <td>entero de 16 bits little-endian</td></tr>
        <tr><td><code>lelong</code></td>
            <td>entero de 32 bits little-endian</td></tr>
        <tr><td><code>ledate</code></td>
            <td>fecha en entero de 32 bits little-endian</td></tr>
        </table></td></tr>

    <tr><td>3</td>
        <td>contenido de los datos a comparar</td></tr>

    <tr><td>4</td>
        <td>tipo MIME si hay coincidencia</td></tr>

    <tr><td>5</td>
        <td>codificación MIME si hay coincidencia (opcional)</td></tr>
    </table>

    <p>Por ejemplo, las siguientes líneas del archivo "magic" reconocerían
    algunos formatos de audio:</p>

    <example>
<pre># Sun/NeXT audio data
0      string      .snd
&gt;12    belong      1       audio/basic
&gt;12    belong      2       audio/basic
&gt;12    belong      3       audio/basic
&gt;12    belong      4       audio/basic
&gt;12    belong      5       audio/basic
&gt;12    belong      6       audio/basic
&gt;12    belong      7       audio/basic
&gt;12    belong     23       audio/x-adpcm</pre>
    </example>

    <p>O estas reconocerían la diferencia entre archivos <code>*.doc</code>
    que contienen documentos de Microsoft Word o de FrameMaker. (Son
    formatos de archivo incompatibles que usan el mismo sufijo de archivo.)</p>

    <example>
<pre># Frame
0  string  \&lt;MakerFile        application/x-frame
0  string  \&lt;MIFFile          application/x-frame
0  string  \&lt;MakerDictionary  application/x-frame
0  string  \&lt;MakerScreenFon   application/x-frame
0  string  \&lt;MML              application/x-frame
0  string  \&lt;Book             application/x-frame
0  string  \&lt;Maker            application/x-frame

# MS-Word
0  string  \376\067\0\043            application/msword
0  string  \320\317\021\340\241\261  application/msword
0  string  \333\245-\0\0\0           application/msword</pre>
    </example>

    <p>Se puede incluir una codificación MIME opcional como quinta columna.
    Por ejemplo, esto permite reconocer archivos comprimidos con gzip y
    establecer su codificación.</p>

    <example>
<pre># gzip (GNU zip, not to be confused with
#       [Info-ZIP/PKWARE] zip archiver)

0  string  \037\213  application/octet-stream  x-gzip</pre>
    </example>
</section>

<section id="performance"><title>Cuestiones de rendimiento</title>
    <p>Este módulo no es adecuado para todos los sistemas. Si su sistema
    apenas llega a cumplir con su carga o si está realizando pruebas de
    rendimiento de un servidor web, puede que no quiera activarlo porque
    el procesamiento no es gratuito.</p>

    <p>Sin embargo, se hizo un esfuerzo por mejorar el rendimiento del
    código original de <code>file(1)</code> para que fuera adecuado en un
    servidor web con mucha carga. Se diseñó para un servidor en el que miles
    de usuarios publican sus propios documentos. Esto es probablemente muy
    habitual en intranets. Muchas veces resulta útil que el servidor pueda
    tomar decisiones más inteligentes sobre el contenido de un archivo de
    lo que permite el nombre del archivo... aunque solo sea para reducir las
    llamadas de "por qué no funciona mi página" cuando los usuarios nombran
    incorrectamente sus propios archivos. Debe decidir si el trabajo extra
    conviene a su entorno.</p>
</section>

<section id="notes"><title>Notas</title>
    <p>Las siguientes notas se aplican al módulo <module>mod_mime_magic</module>
    y se incluyen aquí para cumplir con las restricciones de copyright de los
    colaboradores que exigen su reconocimiento.</p>

    <note>
      <p>mod_mime_magic: búsqueda de tipo MIME mediante números mágicos de archivo<br />
      Copyright (c) 1996-1997 Cisco Systems, Inc.</p>

      <p>Este software fue presentado por Cisco Systems al Apache Group
      en julio de 1997. Las revisiones y derivados futuros de este código fuente
      deben reconocer a Cisco Systems como el colaborador original de este
      módulo. El resto de las condiciones de licencia y uso son las del
      Apache Group.</p>

      <p>Parte de este código se deriva de la versión libre del comando file
      publicada originalmente en comp.sources.unix. A continuación se incluye,
      según se requiere, la información de copyright de ese programa.</p>
    </note>

    <note>
      <p> - Copyright (c) Ian F. Darwin, 1987. Written by Ian F. Darwin.</p>

      <p>This software is not subject to any license of the American
      Telephone and Telegraph Company or of the Regents of the University
      of California.</p>

      <p>Permission is granted to anyone to use this software for any
      purpose on any computer system, and to alter it and redistribute it
      freely, subject to the following restrictions:</p>

      <ol>
        <li>The author is not responsible for the consequences of use of
        this software, no matter how awful, even if they arise from flaws
        in it.</li>

        <li>The origin of this software must not be misrepresented, either
        by explicit claim or by omission. Since few users ever read
        sources, credits must appear in the documentation.</li>

        <li>Altered versions must be plainly marked as such, and must not
        be misrepresented as being the original software. Since few users
        ever read sources, credits must appear in the documentation.</li>

        <li>This notice may not be removed or altered.</li>
      </ol>
    </note>

    <note>
      <p>Para cumplir con las condiciones del Sr. Darwin: esto se ha
      modificado de forma muy significativa respecto al comando "file" libre.</p>

      <ul>
        <li>archivo único (all-in-one) por conveniencia de compilación al pasar
        de una versión de Apache a la siguiente.</li>

        <li>La asignación de memoria se realiza a través de la estructura de pool
        de la API de Apache.</li>

        <li>A todas las funciones se les han pasado las estructuras de petición o
        de servidor necesarias de la API de Apache donde era necesario para llamar
        a otras rutinas de la API de Apache. (<em>p. ej.</em>, normalmente para
        registro, archivos, o asignación de memoria en sí misma o en una función
        llamada.)</li>

        <li>struct magic se ha convertido de un array a una lista enlazada simple
        porque solo crece un registro cada vez, solo se accede a ella secuencialmente,
        y la API de Apache no tiene un equivalente de
        <code>realloc()</code>.</li>

        <li>Se han modificado las funciones para que obtengan sus parámetros de la
        configuración del servidor en lugar de variables globales. (Debería ser
        reentrante ahora, pero no se ha probado en un entorno con hilos.)</li>

        <li>Los lugares donde antes se imprimían resultados en stdout ahora los
        guardan en una lista donde se usan para establecer el tipo MIME en el
        registro de petición de Apache.</li>

        <li>Se han eliminado las opciones de línea de comandos, ya que nunca se
        usarán aquí.</li>
      </ul>
    </note>
</section>

<directivesynopsis>
<name>MimeMagicFile</name>
<description>Activa la determinación del tipo MIME basada en el contenido del archivo
usando el archivo "magic" especificado</description>
<syntax>MimeMagicFile <var>file-path</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>MimeMagicFile</directive> puede usarse para
    activar este módulo; el archivo por defecto se distribuye en
    <code>conf/magic</code>. Las rutas no absolutas son relativas a la
    <directive module="core">ServerRoot</directive>. Los hosts virtuales
    usarán el mismo archivo que el servidor principal a menos que se use un
    ajuste más específico, en cuyo caso el ajuste más específico anula el
    archivo del servidor principal.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      MimeMagicFile conf/magic
      </highlight>
    </example>
</usage>
</directivesynopsis>
</modulesynopsis>
