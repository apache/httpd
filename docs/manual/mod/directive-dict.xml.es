<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1544626:1799456 (outdated) -->
<!-- Spanish Revision: Daniel Ferradal -->
<!-- Spanish translation : Daniel Ferradal -->
<!-- Reviewer Luis Gil de Bernabé Pfeiffer -->

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

<manualpage metafile="directive-dict.xml.meta">

  <title>Términos que se Usan para Describir Directivas</title>

<summary>
    <p>Este documento describe los términos que se usan para describir
    cada <a href="directives.html">directiva de configuración</a> de
    Apache.</p>
</summary>
<seealso><a href="../configuring.html">Ficheros de Configuración</a></seealso>

<section id="Description"><title>Descripción</title>

    <p>Una breve descripción del propósito de la directiva.</p>
</section>

<section id="Syntax"><title>Sintaxis</title>

    <p>Indica el formato de la directiva tal y como aparecería en un fichero de 
    configuración. Esta sintaxis es muy específica de cada directiva, y se 
    describe con detalle en la definición de la directiva. Generalmente, el 
    nombre de la directiva va seguido de una serie de uno o más parámetros 
    separados por un espacio. Si un parámetro contiene un espacio, éste debe 
    especificarse entre comillas dobles. Los parámetros opcionales van 
    especificados entre corchetes. Donde un parámetro puede tener uno o más 
    valores, los valores posibles se separan con barras verticales "|". El Texto
    Literal se muestra con la fuente por defecto, mientras que los distintos 
    tipos de parámetros para los que una sustitución resulta necesaria son 
    <em>enfatizados</em>. Las directivas que pueden tomar una lista variada de 
    parámetros acaban en "..." indicando que el último parámetro se repite.</p>

    <p>Las Directivas usan un gran número de diferentes tipos de parámetros. A 
    continuación definimos algunos de los más comunes.</p>

    <dl>
      <dt><em>URL</em></dt>
      <dd>Un Localizador de Recursos Uniforme, incluye un esquema,
		  nombre de host, y un path opcional como en
      <code>http://www.example.com/path/to/file.html</code></dd>

      <dt><em>Ruta de URL</em></dt>
      <dd>La parte de una <em>url</em> que sigue al esquema y el
		  nombre de host como en <code>http://www.example.com/path/to/file.html</code>.
      El <em>url-path</em> representa una vista-web de un recurso, en
      contraposición a una vista de sistema-de-ficheros.</dd>

      <dt><em>Ruta del Fichero</em></dt>
      <dd>La ruta a un fichero en el sistema de ficheros local que
		  comienza desde el directorio raíz como en
      <code>/usr/local/apache/htdocs/path/to/file.html</code>.
      A menos que se especifique, una <em>ruta de fichero</em> que no comienza
      con una barra "/" se tratará como una ruta relativa a <a
      href="core.html#serverroot">ServerRoot</a>.</dd>

      <dt><em>Ruta del Directorio</em></dt>

      <dd>La ruta a un directorio en el sistema de ficheros local que
      comienza con el directorio raíz como en
      <code>/usr/local/apache/htdocs/path/to/</code>.</dd>

      <dt><em>Nombre del Fichero</em></dt>

      <dd>El nombre de un fichero sin ir acompañado de información de la ruta
      como en <code>file.html</code>.</dd>

      <dt><em>regex</em></dt>

      <dd>Una <glossary ref="regex">
      expresión regular</glossary> compatible con Perl. La definición
      de directiva especificará contra qué se compara la
      <em>regex</em>.</dd>

      <dt><em>extensión</em></dt>

      <dd>En general, esta es la parte del <em>nombre de fichero</em>
      que sigue al último punto. Sin embargo, Apache reconoce múltiples
      extensiones de fichero, así que si un <em>nombre de fichero</em>
      contiene más de un punto, cada parte separada por un punto del
      nombre de fichero después del primer punto es una <em>extensión</em>.
      Por ejemplo, el <em>nombre de fichero</em> <code>file.html.en</code>
      contiene dos extensiones: <code>.html</code> y
      <code>.en</code>. Para las directivas de Apache, podrá especificar
      la <em>extensiones</em> con o sin el punto inicial. Además, las 
      <em>extensiones</em> no son sensibles a mayúsculas o minúsculas.</dd>

      <dt><em>Tipo MIME</em></dt>

      <dd>Un método de describir el formato de un fichero que está formado
      por un tipo de formato mayor y un tipo de formato menor, separados de
      de una barra como en <code>text/html</code>.</dd>

      <dt><em>Variable de Entorno</em></dt>

      <dd>El nombre de una <a href="../env.html">variable de entorno</a>
      definida en el proceso de configuración de Apache. Tenga en cuenta
      que esto no es necesariamente lo mismo que la variable de entorno
      de un sistema operativo. Vea la <a
      href="../env.html">documentación de variable de entorno</a> para
      más detalles.</dd>
    </dl>
</section>

<section id="Default"><title>Por defecto</title>

    <p>Si la directiva tiene un valor por defecto (<em>p.ej.</em>, si
    la omite de la configuración completamente, el servidor Web Apache
    se comportará como si la hubiera configurado con un valor en 
    particular), se describe aquí. Si no tiene valor por defecto, esta 
    sección debería	indicar "<em>Ninguno</em>". Tenga en cuenta que el 
    valor por defecto listado aquí no es necesariamente el mismo que el   
    valor que toma la directiva en el httpd.conf por defecto distribuido 
    con el servidor.</p>
</section>

<section id="Context"><title>Contexto</title>

    <p>Esto indica dónde se acepta la directiva en los ficheros de 
    configuración. Es una lista separada por comas para uno o más de los 
    siguientes valores:</p>

    <dl>
      <dt>server config</dt>

      <dd>Esto indica que la directiva puede usarse en los ficheros de 
		  configuración del servidor (<em>p.ej.</em>, <code>httpd.conf</code>),
		  pero <strong>not</strong> dentro de cualquier contenedor
      <directive module="core" type="section">VirtualHost</directive>
      o <directive module="core" type="section">Directory</directive>. 
		  No se permite en ficheros <code>.htaccess</code> de ninguna 
		  manera.</dd>

      <dt>virtual host</dt>

      <dd>Este contexto significa que la directiva puede aparecer dentro de un
      contenedor <directive module="core" type="section">VirtualHost</directive>
      en el fichero de configuración del servidor.</dd>

      <dt>directory</dt>

      <dd>Una directiva marcada como válida en este contexto puede usarse dentro
      de contenedores <directive module="core"
      type="section">Directory</directive>, <directive type="section"
      module="core">Location</directive>, <directive module="core"
      type="section">Files</directive>, <directive module="core"
      type="section">If</directive>,  <directive
      module="mod_proxy" type="section">Proxy</directive> en los ficheros de
      configuración del servidor, sujeta a las restricciones destacadas en
      las <a href="../sections.html">Secciones de Configuración</a>.</dd>

      <dt>.htaccess</dt>

      <dd>Si una directiva es válida en este contexto, significa que puede 
      aparecer dentro de ficheros <code>.htaccess</code> por  <em>
      directorio</em>. Aunque podría no ser procesada, dependiendo de si
      la configuración de <a href="#Override">AllowOverride</a> está activa 
      en ese momento.</dd>
    </dl>

    <p>La directiva <em>sólo</em> se permite dentro del contexto designado; si
    intenta usarlo en algún otro, obtendrá un error de configuración que 
    impedirá que el servidor gestione correctamente las solicitudes en ese
    contexto, o impedirá que el servidor pueda funcionar completamente --
    <em>p.ej.</em>, el servidor no arrancará.</p>

    <p>Las ubicaciones válidas para la directiva son actualmente el resultado de 
    una función buleana OR de todos los contextos listados. En otras palabras, una 
    directiva que está marcada como válida en 
    "<code>server config, .htaccess</code>" puede usarse en el fichero
    <code>httpd.conf</code> y en ficheros <code>.htaccess</code>, pero no dentro 
    de contenedores <directive module="core" type="section">Directory</directive> 
    o <directive module="core" type="section">VirtualHost</directive>.</p>
</section>

<section id="Override"><title>Override</title>

    <p>Este atributo de directiva indica qué Override de configuración debe 
    estar activo para que la directiva se procese cuando aparece en un fichero 
    <code>.htaccess</code>. Si el <a href="#Context">contexto</a> de la 
    directiva no permite que aparezca en ficheros <code>.htaccess</code>, 
    entonces no se listará ningún contexto.</p>

    <p>Los Override o sobreescritura se activan con la directiva <directive
    module="core">AllowOverride</directive>, si se aplican a un ámbito en 
    particular (como por ejemplo un directorio) y todos sus descendientes, a 
    menos que se modifique más adelante por otras directivas
    <directive module="core">AllowOverride</directive> en niveles
    inferiores. La documentación para la directiva también muestra una lista de
    los posibles nombres de Override disponibles.</p>
</section>

<section id="Status"><title>Estado</title>

    <p>Esto indica cuan vinculada está esta directiva al servidor Web de Apache; 
    o en otras palabras, puede que necesite recompilar el servidor con un 
    conjunto mejor de módulos para obtener acceso a esta directiva y su 
    funcionalidad. Valores posibles para estar directiva son:</p>

    <dl>
      <dt>Core</dt>

      <dd>Si una directiva aparece listada con estado "Core", eso significa
      que forma parte de las partes más internas del Servidor Apache Web, y que
      siempre está disponible.</dd>

      <dt>MPM</dt>

      <dd>La directivas facilitadas por un
      <a href="../mpm.html">Módulo de Multi-Proceso</a> están etiquetadas con
      Estado "MPM". Este tipo de directiva estará disponible si y sólo si está 
      usando uno de los MPM listados en la línea <a href="#Module">Módulo</a> 
      de la definición de la directiva.</dd>

      <dt>Base</dt>

      <dd>Una directiva listada con estado "Base" está facilitada por uno
      de los módulos estándar de Apache que están compilados con el servidor
      por defecto, y por tanto está normalmente disponible a menos que usted 
      haga las acciones necesarias para eliminar este módulo de su 
      configuración.</dd>

      <dt>Extensión</dt>

      <dd>Una directiva con estado "Extensión" está facilitada por uno de los 
      módulos incluidos en el kit del servidor Apache, pero el módulo no 
      está compilado generalmente dentro del servidor. Para activar esta y su
      funcionalidad, necesitará cambiar la configuración de compilación
      del servidor y recompilar Apache.</dd>

      <dt>Experimental</dt>

      <dd>El estado "Experimental" indica que la directiva está disponible como
      parte del kit de Apache, pero usted tendrá que ir por su cuenta si intenta
      usarla. La directiva se documenta para aportar información, pero no tiene
      por qué estar soportada de manera oficial. El módulo que provee esta 
      directiva puede o puede que no esté compilado por defecto, compruebe
      la parte superior de la página que describe la directiva y el módulo para
      ver las anotaciones sobre su disponibilidad.</dd>
    </dl>
</section>

<section id="Module"><title>Módulo</title>

    <p>Ésto simplemente hace referencia al nombre del módulo original que provee 
    la directiva.</p>
</section>

<section id="Compatibility"><title>Compatibilidad</title>

    <p>Si la directiva no era parte de la distribución original de Apache 
    versión 2, la versión en la que se introdujo debería estar referida aquí. 
    Además, si la directiva solo está disponible en ciertas plataformas, se verá
    anotado aquí.</p>
</section>

</manualpage>
