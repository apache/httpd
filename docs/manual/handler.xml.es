<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 151408:421100 (outdated) -->

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

<manualpage metafile="handler.xml.meta">

  <title>Uso de los Handlers en Apache</title>

  <summary>
    <p>Este documento describe el uso de los Handlers en Apache.</p>
  </summary>

  <section id="definition">
    <title>¿Qu&#233; es un Handler?</title>
    <related>
      <modulelist>
        <module>mod_actions</module>
        <module>mod_asis</module>
        <module>mod_cgi</module>
        <module>mod_imagemap</module>
        <module>mod_info</module>
        <module>mod_mime</module>
        <module>mod_negotiation</module>
        <module>mod_status</module>
     </modulelist>
      <directivelist>
        <directive module="mod_actions">Action</directive>
        <directive module="mod_mime">AddHandler</directive>
        <directive module="mod_mime">RemoveHandler</directive>
        <directive module="core">SetHandler</directive>
      </directivelist>
    </related>


    <p>Un "handler" es una representaci&#243;n interna de Apache de
    una acci&#243;n que se va a ejecutar cuando hay una llamada a un
    fichero. Generalmente, los ficheros tienen handlers
    impl&#237;citos, basados en el tipo de fichero de que se
    trata. Normalmente, todos los ficheros son simplemente servidos
    por el servidor, pero algunos tipos de ficheros se tratan de forma
    diferente.</p>

    <p>Apache 1.1 a&#241;ade la posibilidad de usar handlers
    explicitamente.  Bas&#225;ndose en la extension del fichero o en
    la ubicaci&#243;n en la que este, se pueden especificar handlers
    sin tener en cuenta el tipo de fichero de que se trate. Esto es
    una ventaja por dos razones. Primero, es una soluci&#243;n
    m&#225;s elegante. Segundo, porque a un fichero se le pueden
    asignar tanto un tipo <strong>como</strong> un handler. (Consulte
    tambi&#233;n la secci&#243;n <a
    href="mod/mod_mime.html#multipleext">Ficheros y extensiones
    m&#250;ltiples</a>.)</p>

    <p>Los Handlers pueden ser tanto ser compilados con el servidor
    como incluidos en un m&#243;dulo, como a&#241;adidos con la
    directiva <directive module="mod_actions">Action</directive>. Los
    handlers compilados con el servidor de la distribuci&#243;n
    est&#225;ndar de Apache son:</p>

    <ul>
      <li><strong>default-handler</strong>: Env&#237;a el fichero
      usando el <code>default_handler()</code>, que es el handler
      usado por defecto para tratar contenido
      est&#225;tico. (core)</li>

      <li><strong>send-as-is</strong>: Env&#237;a el fichero con
      cabeceras HTTP tal y como es. (<module>mod_asis</module>)</li>

      <li><strong>cgi-script</strong>: Trata el fichero como un sript
      CGI. (<module>mod_cgi</module>)</li>

      <li><strong>imap-file</strong>: Trata el fichero como un mapa de
      im&#225;genes. (<module>mod_imagemap</module>)</li>

      <li><strong>server-info</strong>: Extrae la informaci&#243;n de
      configuraci&#243;n del
      servidor. (<module>mod_info</module>)</li>

      <li><strong>server-status</strong>: Extrae el informe de estado
      del servidor. (<module>mod_status</module>)</li>

      <li><strong>type-map</strong>: Trata el fichero como una
      correspondencia de tipos para la negociaci&#243;n de contenidos.
      (<module>mod_negotiation</module>)</li> </ul> </section>
    
    <section id="examples"> <title>Ejemplos</title>

    <section id="example1">
      <title>Modificar contenido est&#225;tico usando un script
      CGI</title>

      <p>Las siguientes directivas hacen que cuando haya una
      petici&#243;n de ficheros con la extensi&#243;n
      <code>html</code> se lance el script CGI
      <code>footer.pl</code>.</p>

      <example>
        Action add-footer /cgi-bin/footer.pl<br/>
        AddHandler add-footer .html
      </example>

      <p>En este caso, el script CGI es el responsable de enviar el
      documento originalmente solicitado (contenido en la variable de
      entorno <code>PATH_TRANSLATED</code>) y de hacer cualquier
      modificaci&#243;n o a&#241;adido deseado.</p>

    </section>
    <section id="example2">
      <title>Archivos con cabaceras HTTP</title>

      <p>Las siguientes directivas activan el handler
      <code>send-as-is</code>, que se usa para ficheros que contienen
      sus propias cabeceras HTTP. Todos los archivos en el directorio
      <code>/web/htdocs/asis/</code> ser&#225;n procesados por el
      handler <code>send-as-is</code>, sin tener en cuenta su
      extension.</p>

      <example>
        &lt;Directory /web/htdocs/asis&gt;<br/>
        SetHandler send-as-is<br/>
        &lt;/Directory&gt;
      </example>

    </section>
  </section>
  <section id="programmer">
    <title>Nota para programadores</title>

    <p>Para implementar las funcionalidades de los handlers, se ha
    hecho un a&#241;adido a la <a href="developer/API.html">API de
    Apache</a> que puede que quiera usar. Para ser m&#225;s
    espec&#237;ficos, se ha a&#241;adido un nuevo registro a la
    estructura <code>request_rec</code>:</p>

    <example>
      char *handler
    </example>

    <p>Si quiere que su m&#243;dulo llame a un handler , solo tiene
    que a&#241;adir <code>r-&gt;handler</code> al nombre del handler
    en cualquier momento antes de la fase <code>invoke_handler</code>
    de la petici&#243;n. Los handlers se implementan siempre como se
    hac&#237;a antes, aunque usando el nombre del handler en vez de un
    tipo de contenido. Aunque no es de obligado cumplimiento, la
    convenci&#243;n de nombres para los handlers es que se usen
    palabras separadas por guiones, sin barras, de manera que no se
    invada el media type name-space.</p>
  </section>
</manualpage>






