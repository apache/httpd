<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1673932 -->
<!-- Spanish Translation: Daniel Ferradal <dferradal@apache.org> -->

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

<modulesynopsis metafile="mod_asis.xml.meta">

<name>mod_asis</name>
<description>Envía ficheros que contienen sus propias 
  cabeceras HTTP</description>
<status>Base</status>
<sourcefile>mod_asis.c</sourcefile>
<identifier>asis_module</identifier>

<summary>
    <p>Este módulo provee el handler <code>send-as-is</code>
      que hace que Apache HTTP Server envíe documentos sin añadir a ellos la 
      mayoría de las cabeceras típicas de HTTP.</p>

    <p>Esto se puede usar para enviar cualquier tipo de datos desde el servidor, 
      incluyendo redirecciones y otras respuestas HTTP especiales, sin 
      necesitar un script-cgi o un script nph.</p>

    <p>Por razones históricas, este módulo también procesará cualquier fichero
      con el tipo MIME <code>httpd/send-as-is</code>.</p>
</summary>

<seealso><module>mod_headers</module></seealso>
<seealso><module>mod_cern_meta</module></seealso>
<seealso><a href="../handler.html">Uso de Handler de Apache httpd</a></seealso>

<section id="usage"><title>Uso</title>

    <p>En el fichero de configuración del servidor, asociar ficheros con el 
      handler <code>send-as-is</code> <em>p. ej.</em></p>

    <highlight language="config">
AddHandler send-as-is asis
    </highlight>

    <p>Los contenidos de cualquier fichero con la extensión <code>.asis</code> 
    se enviarán por Apache httpd al cliente sin apenas cambios. En particular, 
    las cabeceras HTTP provienen del propio fichero según las reglas de 
    <module>mod_cgi</module>, así que un fichero "asis" debe incluir cabeceras 
    válidas, y también puede usar la cabecera CGI 
    <code>Status:</code> para determinar el código de la respuesta HTTP. La 
    cabecera <code>Content-Length:</code> se insertará automáticamente, o si se 
    incluye en el fichero, será corregida por httpd.</p>

    <p>Aquí hay un ejemplo de un fichero cuyo contenido se envía 
      <em>as is</em> (tal cual) para decirle al cliente que 
      un fichero se ha redirigido.</p>

    <example>
      Status: 301 Y ahora donde he dejado esa URL<br />
      Location: http://xyz.example.com/foo/bar.html<br />
      Content-type: text/html<br />
      <br />
      &lt;html&gt;<br />
      &lt;head&gt;<br />
      &lt;title&gt;Excusas flojas'R'us&lt;/title&gt;<br />
      &lt;/head&gt;<br />
      &lt;body&gt;<br />
      &lt;h1&gt;La excepcionalmente maravillosa página de Fred's se ha movido a<br />
      &lt;a href="http://xyz.example.com/foo/bar.html"&gt;Joe's&lt;/a&gt;
      site.<br />
      &lt;/h1&gt;<br />
      &lt;/body&gt;<br />
      &lt;/html&gt;
    </example>

    <note><title>Notas:</title>
    <p>El servidor siempre añade una cabecera <code>Date:</code> y 
    <code>Server:</code> a los datos que se devuelven al cliente, de manera que 
    estos no deben incluirse en el fichero. El servidor <em>no</em> añade una 
    cabecera <code>Last-Modified</code> ; probablemente debería.</p>
    </note>
</section>

</modulesynopsis>
