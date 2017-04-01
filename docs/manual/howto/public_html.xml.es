<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1745806 -->
<!-- Spanish translation : Daniel Ferradal -->
<!-- Reviewed by: Luis Gil de Bernabé Pfeiffer -->

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

<manualpage metafile="public_html.xml.meta">
<parentdocument href="./">How-To / Tutorials</parentdocument>

  <title>Directorios web por usuario</title>

<summary>
	<p>En sistemas con múltiples usuarios, cada usuario puede tener un website 
    en su directorio home usando la directiva <directive
    module="mod_userdir">UserDir</directive>. Los visitantes de una URL 
    <code>http://example.com/~username/</code> recibirán el contenido del 
    directorio home del usuario "<code>username</code>", en el subdirectorio 
    especificado por la directiva <directive module="mod_userdir">UserDir</directive>.</p>

	<p>Tenga en cuenta que, por defecto, el acceso a estos directorios 
    <strong>NO</strong> está activado. Puede permitir acceso cuando usa 
    <directive module="mod_userdir"
    >UserDir</directive> quitando el comentario de la línea:</p>

    <highlight language="config">
      #Include conf/extra/httpd-userdir.conf
    </highlight>

    <p>En el fichero por defecto de configuración <code>conf/httpd.conf</code>, 
    y adaptando el fichero <code>httpd-userdir.conf</code> según sea necesario, 
    o incluyendo las directivas apropiadas en un bloque 
    <directive module="core" type="section">Directory</directive> dentro del fichero 
    principal de configuración.</p>
</summary>

<seealso><a href="../urlmapping.html">Mapeando URLs al sistema de ficheros</a></seealso>

  <section id="related">
    <title>Directorios web por usuario</title>
    <related>
      <modulelist>
        <module>mod_userdir</module>
      </modulelist>
      <directivelist>
        <directive module="mod_userdir">UserDir</directive>
        <directive module="core">DirectoryMatch</directive>
        <directive module="core">AllowOverride</directive>
      </directivelist>
    </related>
    </section>

    <section id="userdir">
    <title>Configurando la ruta del fichero con UserDir</title>

    <p>La directiva <directive module="mod_userdir">UserDir</directive>
    especifica un directorio del que cargar contenido por usuario. Esta directiva 
    puede tener muchas formas distintas.</p>

    <p>Si se especifica una ruta que no empieza con una barra ("/"), se asume que 
      va a ser una ruta de directorio relativa al directorio home del usuario 
      especificado. Dada ésta configuración:</p>

    <highlight language="config">
UserDir public_html
    </highlight>

    <p>La URL <code>http://example.com/~rbowen/file.html</code> se traducirá en 
    la ruta del fichero <code>/home/rbowen/public_html/file.html</code></p>

    <p>Si la ruta que se especifica comienza con una barra ("/"), la ruta del 
      directorio se construirá usando esa ruta, más el usuario especificado en la 
      configuración:</p>

    <highlight language="config">
UserDir /var/html
    </highlight>

    <p>La URL <code>http://example.com/~rbowen/file.html</code> se traducirá en 
    la ruta del fichero <code>/var/html/rbowen/file.html</code></p>

    <p>Si se especifica una ruta que contiene un asterisco (*), se usará una ruta 
      en la que el asterisco se reemplaza con el nombre de usuario. Dada ésta configuración:</p>

    <highlight language="config">
UserDir /var/www/*/docs
    </highlight>

    <p>La URL <code>http://example.com/~rbowen/file.html</code> se traducirá en 
    la ruta del fichero <code>/var/www/rbowen/docs/file.html</code></p>

    <p>También se pueden configurar múltiples directorios o rutas de directorios.</p>

    <highlight language="config">
UserDir public_html /var/html
    </highlight>

    <p>Para la URL <code>http://example.com/~rbowen/file.html</code>,
    Apache buscará <code>~rbowen</code>. Si no lo encuentra, Apache buscará
    <code>rbowen</code> en <code>/var/html</code>. Si lo encuentra, la URL de más 
    arriba se traducirá en la ruta del fichero 
    <code>/var/html/rbowen/file.html</code></p>

  </section>

  <section id="redirect">
    <title>Redirigiendo a URLs externas</title>
    <p>La directiva <directive module="mod_userdir">UserDir</directive> puede 
    usarse para redirigir solcitudes de directorios de usuario a URLs externas.</p>

    <highlight language="config">
UserDir http://example.org/users/*/
    </highlight>

    <p>El ejemplo de aquí arriba redirigirá una solicitud para
    <code>http://example.com/~bob/abc.html</code> hacia
    <code>http://example.org/users/bob/abc.html</code>.</p>
  </section>

  <section id="enable">
    <title>Restringiendo qué usuarios pueden usar esta característica</title>

    <p>Usando la sintaxis que se muestra en la documentación de UserDir, usted 
      puede restringir a qué usuarios se les permite usar esta funcionalidad:</p>

    <highlight language="config">
UserDir disabled root jro fish
    </highlight>

    <p>La configuración de aquí arriba permitirá a todos los usuarios excepto a 
      los que se listan con la declaración <code>disabled</code>. Usted puede, 
      del mismo modo, deshabilitar esta característica para todos excepto algunos 
      usuarios usando una configuración como la siguiente:</p>

    <highlight language="config">
UserDir disabled
UserDir enabled rbowen krietz
    </highlight>

    <p>Vea la documentación de <directive module="mod_userdir">UserDir</directive> para más 
    ejemplos.</p>

  </section>

  <section id="cgi">
  <title>Activando un directorio cgi para cada usuario</title>

   <p>Para dar a cada usuario su propio directorio cgi-bin, puede usar una directiva 
   	<directive module="core" type="section">Directory</directive>
   para activar cgi en un subdirectorio en particular del directorio home del usuario.</p>

    <highlight language="config">
&lt;Directory "/home/*/public_html/cgi-bin/"&gt;
    Options ExecCGI
    SetHandler cgi-script
&lt;/Directory&gt;
    </highlight>

    <p>Entonces, asumiendo que <code>UserDir</code> está configurado con la 
    declaración <code>public_html</code>, un programa cgi <code>example.cgi</code> 
    podría cargarse de ese directorio así:</p>

    <example>
    http://example.com/~rbowen/cgi-bin/example.cgi
    </example>

    </section>

    <section id="htaccess">
    <title>Permitiendo a usuarios cambiar la configuración</title>

    <p>Si quiere permitir que usuarios modifiquen la configuración del servidor en 
    	su espacio web, necesitarán usar ficheros <code>.htaccess</code> para hacer 
    	estos cambios. Asegúrese de tener configurado <directive
    module="core">AllowOverride</directive> con un valor suficiente que permita a 
    los usuarios modificar las directivas que quiera permitir. 
    Vea el <a href="htaccess.html">tutorial de .htaccess</a> para obtener detalles adicionales sobre cómo funciona.</p>

  </section>

</manualpage>
