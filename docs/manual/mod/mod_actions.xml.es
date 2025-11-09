<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1673892 -->
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

<modulesynopsis metafile="mod_actions.xml.meta">

<name>mod_actions</name>

<description>Ejecuta scripts CGI basándose en el tipo de medio o método de la petición.</description>

<status>Base</status>
<sourcefile>mod_actions.c</sourcefile>
<identifier>actions_module</identifier>

<summary>
    <p>Este módulo tiene dos directivas. La directiva <directive
    module="mod_actions">Action</directive> le permite ejecutar scripts CGI siempre que se solicite un fichero con cierto  <glossary
    ref="mime-type">tipo de contenido MIME</glossary>. La direcitiva 
    <directive module="mod_actions">Script</directive> le permite ejecutar scripts CGI siempre que se use un método concreto en una petición. Esto hace mucho más fácil ejecutar scripts para procesar ficheros.</p>
</summary>

<seealso><module>mod_cgi</module></seealso>
<seealso><a href="../howto/cgi.html">Contenido Dinámico con CGI</a></seealso>
<seealso><a href="../handler.html">Uso de Handler de Apache httpd</a></seealso>

<directivesynopsis>
<name>Action</name>
<description>Activa un script CGI para un handler concreto o content-type</description>
<syntax>Action <var>action-type</var> <var>cgi-script</var> [virtual]</syntax>
<contextlist>
<context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context>
</contextlist>
<override>FileInfo</override>

<usage>
    <p>Esta directiva añade una acción, que activará <var>cgi-script</var> cuando <var>action-type</var> se activa por una petición. El <var>cgi-script</var> es el path-de-URL a un recurso designado como un script CGI script usando 
    <directive module="mod_alias">ScriptAlias</directive> o 
    <directive module="mod_mime">AddHandler</directive>. El 
    <var>action-type</var> puede ser un <a href="../handler.html">handler</a> o un <glossary ref="mime-type">tipo de contenido MIME</glossary>. Envía la URL y el path al fichero del documento solicitado usando las variables de entorno estándar de CGI <code>PATH_INFO</code> y <code>PATH_TRANSLATED</code>. El handler que se usa para esta petición en particular se envía usando la variable <code>REDIRECT_HANDLER</code>.</p>

    <example><title>Ejemplo: tipo MIME</title>
    <highlight language="config">
# Petición de ficheros de un tipo concreto de contenido MIME:
Action image/gif /cgi-bin/images.cgi
    </highlight>
    </example>

    <p>En este ejemplo, las peticiones de ficheros con contenido tipo MIME <code>image/gif</code> serán gestionadas por el script cgi especificado en <code>/cgi-bin/images.cgi</code>.</p>

    <example>
        <title>Ejemplo: Extensión de fichero</title>
    <highlight language="config">
# Ficheros con una extensión concreta
AddHandler my-file-type .xyz
Action my-file-type /cgi-bin/program.cgi
    </highlight>
    </example>
    <p>En este ejemplo, las peticiones a ficheros con una extensión de fichero
    <code>.xyz</code> serán gestionadas por el script cgi especificado en
    <code>/cgi-bin/program.cgi</code>.</p>

    <p>El modificador opcional <code>virtual</code> desactiva la comprobación para saber si el fichero realmente existe. Esto es útil, por ejemplo, si quiere usar la directiva <directive>Action</directive> en ubicaciones virtuales.</p>

    <highlight language="config">
&lt;Location "/news"&gt;
    SetHandler news-handler
    Action news-handler /cgi-bin/news.cgi virtual
&lt;/Location&gt;
    </highlight>
</usage>

<seealso><directive module="mod_mime">AddHandler</directive></seealso>
</directivesynopsis>

<directivesynopsis>
<name>Script</name>
<description>Activa un script CGI para peticiones con un método concreto.</description>
<syntax>Script <var>method</var> <var>cgi-script</var></syntax>
<contextlist>
<context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<usage>
    <p>Esta directiva añade una acción, que activará <var>cgi-script</var> cuando se solicita un fichero usando un método especificado en el parámetro <var>method</var>. El <var>cgi-script</var> es el path-de-URL al recurso que ha sido designado como un script CGI usando <directive
    module="mod_alias">ScriptAlias</directive> o <directive
    module="mod_mime">AddHandler</directive>. La URL y la ruta al fichero del documento solicitado se envía usando las variables de entorno estándar de CGI <code>PATH_INFO</code> y <code>PATH_TRANSLATED</code>.</p>

    <note>
      Se puede usar cualquier nombre de método arbitrario. <strong>Los nombres de Método son sensibles a mayúsculas</strong>, así que <code>Script PUT</code> and <code>Script put</code> tienen dos efectos totalmente diferentes.
    </note>

    <p>Tenga en cuenta que el comando <directive>Script</directive> solo define acciones por defecto. Si se llama a un script CGI, o algún otro recurso que esté capacitado para gestionar el método solicitado internamente, éste se utilizará. También tenga en cuenta que solo se invocará <directive>Script</directive> con un método <code>GET</code> si hay parámetros de query string presentes en la petición (<em>p.e.</em>, foo.html?hi). Si no, la petición se procesará normalmente.</p>

    <highlight language="config">
# todas las peticiones GET van aquí
Script GET /cgi-bin/search

# Un handler PUT de CGI
Script PUT /~bob/put.cgi
    </highlight>
</usage>
</directivesynopsis>

</modulesynopsis>