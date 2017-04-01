<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 1673563 -->
<!-- Translated by Luis Gil de Bernabé Pfeiffer lgilbernabe[AT]apache.org -->
<!-- Reviewed by Sergio Ramos-->

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
    <title>¿Qué es un Handler?</title>
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


    <p>Un "handler" es una representación interna de Apache de
    una acción que se va a ejecutar cuando hay una llamada a un
    fichero. Generalmente, los ficheros tienen handlers
    implícitos, basados en el tipo de fichero de que se
    trata. Normalmente, todos los ficheros son simplemente servidos
    por el servidor, pero algunos tipos de ficheros se tratan de forma
    diferente.</p>

    <p>Handlers pueden ser usados de manera explicita,
     basándose en la extensión del fichero o en
    la ubicación en la que esté, se pueden especificar handlers
    sin tener en cuenta el tipo de fichero que se trate. Esto es
    una ventaja por dos razones. Primero, es una solución
    más elegante. Segundo, porque a un fichero se le pueden
    asignar tanto un tipo <strong>como</strong> un handler. (Consulte
    también la sección <a
    href="mod/mod_mime.html#multipleext">Ficheros y extensiones
    múltiples</a>.)</p>

    <p>Los Handlers pueden tanto ser compilados con el servidor
    como incluidos en un módulo, o añadidos con la
    directiva <directive module="mod_actions">Action</directive>. Los
    handlers que vienen incluidos en el core con el servidor de la distribución
    estándar de Apache son:</p>

    <ul>
      <li><strong>default-handler</strong>: Envía el fichero
      usando el <code>default_handler()</code>, que es el handler
      usado por defecto para tratar contenido
      estático. (core)</li>

      <li><strong>send-as-is</strong>: Envía el fichero con
      cabeceras HTTP tal y como es. (<module>mod_asis</module>)</li>

      <li><strong>cgi-script</strong>: Trata el fichero como un sript
      CGI. (<module>mod_cgi</module>)</li>

      <li><strong>imap-file</strong>: Trata el fichero como un mapa de
      imágenes. (<module>mod_imagemap</module>)</li>

      <li><strong>server-info</strong>: Extrae la información de
      configuración del
      servidor. (<module>mod_info</module>)</li>

      <li><strong>server-status</strong>: Extrae el informe del estado
      del servidor. (<module>mod_status</module>)</li>

      <li><strong>type-map</strong>: Trata el fichero como una
      correspondencia de tipos para la negociación de contenidos.
      (<module>mod_negotiation</module>)</li> 
    </ul> 
  </section>
    
    <section id="examples"> 
      <title>Ejemplos</title>

      <section id="example1">
      <title>Modificar contenido estático usando un script
      CGI</title>

      <p>Las siguientes directivas hacen que cuando haya una
      petición de ficheros con la extensión
      <code>html</code> se lance el script CGI
      <code>footer.pl</code>.</p>

      <example>
        Action add-footer /cgi-bin/footer.pl<br/>
        AddHandler add-footer .html
      </example>

      <p>En este caso, el script CGI es el responsable de enviar el
      documento originalmente solicitado (contenido en la variable de
      entorno <code>PATH_TRANSLATED</code>) y de hacer cualquier
      modificación o añadido deseado.</p>

    </section>
    <section id="example2">
      <title>Archivos con cabeceras HTTP</title>

      <p>Las siguientes directivas activan el handler
      <code>send-as-is</code>, que se usa para ficheros que contienen
      sus propias cabeceras HTTP. Todos los archivos en el directorio
      <code>/web/htdocs/asis/</code> serán procesados por el
      handler <code>send-as-is</code>, sin tener en cuenta su
      extension.</p>

      <highlight language="config">
&lt;Directory "/web/htdocs/asis"&gt;
    SetHandler send-as-is
&lt;/Directory&gt;
      </highlight>

    </section>
  </section>
  <section id="programmer">
    <title>Nota para programadores</title>

    <p>Para implementar las funcionalidades de los handlers, se ha
    hecho un añadido a la <a href="developer/API.html">API de
    Apache</a> que puede que quiera usar. Para ser más
    específicos, se ha añadido un nuevo registro a la
    estructura <code>request_rec</code>:</p>

    <highlight language="c">
      char *handler
    </highlight>

    <p>Si quiere que su módulo llame a un handler , solo tiene
    que añadir <code>r-&gt;handler</code> al nombre del handler
    en cualquier momento antes de la fase <code>invoke_handler</code>
    de la petición. Los handlers se implementan siempre como se
    hacía antes, aunque usando el nombre del handler en vez de un
    tipo de contenido. Aunque no es de obligado cumplimiento, la
    convención de nombres para los handlers es que se usen
    palabras separadas por guiones, sin barras, de manera que no se
    invada el media type name-space.</p>
  </section>
</manualpage>






