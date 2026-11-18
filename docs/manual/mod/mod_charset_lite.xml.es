<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1673563 -->
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

<modulesynopsis metafile="mod_charset_lite.xml.meta">

<name>mod_charset_lite</name>
<description>Especifica la traducción o recodificación del juego de
caracteres</description>
<status>Extension</status>
<sourcefile>mod_charset_lite.c</sourcefile>
<identifier>charset_lite_module</identifier>

<summary>
    <p><module>mod_charset_lite</module> permite al servidor cambiar el
    juego de caracteres de las respuestas antes de enviarlas al cliente.
    En un entorno EBCDIC, Apache siempre traduce el contenido del
    protocolo HTTP (por ejemplo, las cabeceras de respuesta) de la página
    de códigos del locale del proceso Apache a ISO-8859-1, pero no el
    cuerpo de las respuestas. En cualquier entorno, puede usarse
    <module>mod_charset_lite</module> para especificar que los cuerpos de
    las respuestas deben traducirse. Por ejemplo, si los archivos se
    almacenan en EBCDIC, <module>mod_charset_lite</module> puede
    traducirlos a ISO-8859-1 antes de enviarlos al cliente.</p>

    <p>Este módulo proporciona un pequeño subconjunto de los mecanismos de
    configuración implementados por Russian Apache y su
    <code>mod_charset</code> asociado.</p>
</summary>

<section id="problems"><title>Problemas comunes</title>

    <section><title>Nombres de juego de caracteres no válidos</title>

      <p>Los parámetros de nombre de juego de caracteres de las
      directivas <directive module="mod_charset_lite"
      >CharsetSourceEnc</directive> y <directive
      module="mod_charset_lite">CharsetDefault</directive> deben ser
      aceptados por el mecanismo de traducción usado por
      <glossary>APR</glossary> en el sistema donde se despliega
      <module>mod_charset_lite</module>. Estos nombres de juego de
      caracteres no están estandarizados y normalmente no son los mismos
      que los valores correspondientes usados en las cabeceras http.
      Actualmente, APR solo puede usar iconv(3), así que puede probar
      fácilmente sus nombres de juego de caracteres usando el programa
      iconv(1), de la siguiente forma:</p>

      <example>
        iconv -f charsetsourceenc-value -t charsetdefault-value
      </example>
    </section>

    <section><title>Desajuste entre el juego de caracteres del contenido y
    las reglas de traducción</title>

      <p>Si las reglas de traducción no tienen sentido para el contenido,
      la traducción puede fallar de varias formas, entre ellas:</p>

      <ul>
      <li>El mecanismo de traducción puede devolver un código de retorno
      incorrecto, y la conexión se abortará.</li>

      <li>El mecanismo de traducción puede colocar silenciosamente
      caracteres especiales (por ejemplo, signos de interrogación) en el
      búfer de salida cuando no pueda traducir el búfer de entrada.</li>
      </ul>
    </section>
</section>

<directivesynopsis>
<name>CharsetSourceEnc</name>
<description>Juego de caracteres de origen de los archivos</description>
<syntax>CharsetSourceEnc <var>charset</var></syntax>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>CharsetSourceEnc</directive> especifica el
    juego de caracteres de origen de los archivos en el contenedor
    asociado.</p>

    <p>El valor del argumento <var>charset</var> debe ser aceptado como
    nombre de juego de caracteres válido por el soporte de juegos de
    caracteres de <glossary>APR</glossary>. En general, esto significa
    que debe estar soportado por iconv.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
&lt;Directory "/export/home/trawick/apacheinst/htdocs/convert"&gt;
    CharsetSourceEnc  UTF-16BE
    CharsetDefault    ISO-8859-1
&lt;/Directory&gt;
      </highlight>
    </example>

    <p>Los nombres de juego de caracteres de este ejemplo funcionan con el
    soporte de traducción de iconv en Solaris 8.</p>

     <note>
     Especificar el mismo juego de caracteres tanto para <directive module="mod_charset_lite">CharsetSourceEnc</directive>
     como para <directive module="mod_charset_lite">CharsetDefault</directive> desactiva la traducción. El juego de caracteres
     no tiene que coincidir con el de la respuesta, pero debe ser un juego de caracteres válido en el sistema.
     </note>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>CharsetDefault</name>
<description>Juego de caracteres al que traducir</description>
<syntax>CharsetDefault <var>charset</var></syntax>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>CharsetDefault</directive> especifica el
    juego de caracteres al que debe traducirse el contenido en el
    contenedor asociado.</p>

    <p>El valor del argumento <var>charset</var> debe ser aceptado como
    nombre de juego de caracteres válido por el soporte de juegos de
    caracteres de <glossary>APR</glossary>. En general, esto significa
    que debe estar soportado por iconv.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
&lt;Directory "/export/home/trawick/apacheinst/htdocs/convert"&gt;
    CharsetSourceEnc  UTF-16BE
    CharsetDefault    ISO-8859-1
&lt;/Directory&gt;
      </highlight>
    </example>

     <note>
     Especificar el mismo juego de caracteres tanto para <directive module="mod_charset_lite">CharsetSourceEnc</directive>
     como para <directive module="mod_charset_lite">CharsetDefault</directive> desactiva la traducción. El juego de caracteres
     no tiene que coincidir con el de la respuesta, pero debe ser un juego de caracteres válido en el sistema.
     </note>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>CharsetOptions</name>
<description>Configura el comportamiento de la traducción de juegos de
caracteres</description>
<syntax>CharsetOptions <var>option</var> [<var>option</var>] ...</syntax>
<default>CharsetOptions ImplicitAdd</default>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>La directiva <directive>CharsetOptions</directive> configura
    ciertos comportamientos de <module>mod_charset_lite</module>.
    <var>Option</var> puede ser uno de los siguientes:</p>

    <dl>
      <dt><code>ImplicitAdd | NoImplicitAdd</code></dt>

      <dd>La palabra clave <code>ImplicitAdd</code> especifica que
      <module>mod_charset_lite</module> debe insertar implícitamente su
      filtro cuando la configuración especifica que el juego de
      caracteres del contenido debe traducirse. Si la cadena de filtros se
      configura explícitamente usando la directiva <directive
      module="mod_mime">AddOutputFilter</directive>, debe especificarse
      <code>NoImplicitAdd</code> para que <module>mod_charset_lite</module>
      no añada su filtro.</dd>

      <dt><code>TranslateAllMimeTypes | NoTranslateAllMimeTypes</code></dt>
      <dd>Normalmente, <module>mod_charset_lite</module> solo realizará la
      traducción en un pequeño subconjunto de posibles tipos mime. Cuando
      se especifica la palabra clave <code>TranslateAllMimeTypes</code>
      para una sección de configuración dada, la traducción se realiza
      sin tener en cuenta el tipo mime.</dd>

    </dl>
</usage>
</directivesynopsis>

</modulesynopsis>
