<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.en.xsl"?>
<!-- English Revision: 103428:396609 (outdated) -->

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

  <title>T&#233;rminos usados en las descripciones de las
  Directivas</title>

<summary>
    <p>Este documento define los t&#233;rminos que se usan para describir
    las <a href="directives.html">directivas de configuraci&#243;n</a> de
    Apache.</p>
</summary>
<seealso><a href="../configuring.html">Fichero de
Configuraci&#243;n</a></seealso>

<section id="Description"><title>Descripci&#243;n</title>

<p>Descripci&#243;n resumida de para qu&#233; sirve la directiva.</p>
</section>

<section id="Syntax"><title>Sintaxis</title>

    <p>Explica el formato de la directiva en la manera en que
    aparecer&#237;a en un fichero de configuraci&#243;n. La sintaxis es
    espec&#237;fica para cada directiva, y se decribe en detalle en la
    definici&#243;n de cada una de ellas. Generalmente, es el nombre de la
    directiva seguido del argumento o argumentos que correspondan
    separados por espacios. Si un argumento contiene un espacio,
    entonces debe escribirse entre comillas. Los argumentos opcionales
    van entre corchetes ([]). Si cada argumento puede tomar m&#225;s de un
    valor, los valores posibles van separados por barras verticales
    "|".  Los textos literales (los que no hay que sustituir) est&#225;n en
    el tipo de letra por defecto del resto del texto, mientras que los
    que hay que sustituir est&#225;n <em>resaltados</em>. Las directivas
    que pueden tomar un n&#250;mero variable de argumentos terminan con
    puntos suspensivos ("...").</p>

    <p>Las directivas usan una gran variedad de tipos de
    argumentos. Algunos de los m&#225;s comunes son:</p>

    <dl>
      <dt><em>URL</em></dt>

      <dd>Un Localizador de Recursos Uniforme (Uniform Resource
      Locator) que consiste en un esquema (www), un nombre de host
      (example.com), y opcionalmente, una ruta; por ejemplo
      <code>http://www.example.com/path/to/file.html</code></dd>

      <dt><em>URL-path</em></dt>

      <dd>La parte de una <em>url</em> que va a continuaci&#243;n del
      esquema y del nombre de host, por ejemplo
      <code>/path/to/file.html</code>. El <em>url-path</em> representa
      al fichero visto desde el servidor web, en contraposici&#243;n a
      verlo tomando el sistema de ficheros como punto de
      referencia.</dd>

      <dt><em>file-path</em></dt>

      <dd>La ubicaci&#243;n de un fichero en el sistema de archivos local
      que empieza con el directorio raiz, por ejemplo,
      <code>/usr/local/apache/htdocs/path/to/file.html</code>.  A
      menos que se especifique otra cosa, un <em>file-path</em> que no
      empieza con una barra ser&#225; tratado como relativo a <a
      href="core.html#serverroot">ServerRoot</a>.</dd>

      <dt><em>directory-path</em></dt>

      <dd>La ubicaci&#243;n de un directorio en el sistema de archivos
      local que empieza en el directorio raiz, por ejemplo
      <code>/usr/local/apache/htdocs/path/to/</code>.</dd>

      <dt><em>filename</em></dt>

      <dd>El nombre de un fichero sin informaci&#243;n adicional sobre su
      ubicaci&#243;n, por ejemplo <code>file.html</code>.</dd>

      <dt><em>regex</em></dt>

      <dd>Una expresi&#243;n regular, que es una forma de describir un
      patr&#243;n para encontrar sus equivalencias en un texto. La
      definici&#243;n de la directiva especificar&#225; con qu&#233; se comparar&#225;
      <em>regex</em> para encontrar equivalencias.</dd>

      <dt><em>extension</em></dt>

      <dd>En general, es la parte del <em>filename</em> que va despu&#233;s
      del &#250;ltimo punto. Apache reconoce muchas de estas extensiones,
      de manera que si un <em>filename</em> contiene mas de un punto,
      cada parte separada por uno de esos puntos despu&#233;s del primero
      se trata como una <em>extensi&#243;n</em>.  Por ejemplo, el
      <em>filename</em> <code>file.html.en</code> contiene dos
      extensiones: <code>.html</code> y <code>.en</code>. Para las
      directivas de Apache, puede especificar <em>extensiones</em> con
      o sin punto delante. Las <em>extensiones</em> no distinguen
      may&#250;sculas de min&#250;sculas.</dd>

      <dt><em>MIME Type</em></dt>

      <dd>Es una forma de describir el formato de un fichero, que
      consiste en un tipo de formato principal y un tipo de formato
      secundario, separados por una barra, por ejemplo
      <code>text/html</code>.</dd>

      <dt><em>env-variable</em></dt>

      <dd>El nombre de una <a href="../env.html">variable de
      entorno</a> definida en el proceso de configuraci&#243;n de Apache.
      Tenga en cuenta que esto no es necesariamente exactamente lo
      mismo que una variable de entorno del sistema
      operativo. Consulte la <a href="../env.html">documentaci&#243;n sobre
      variables de entorno</a> si quiere obtener m&#225;s informaci&#243;n.</dd>
    </dl>
</section>

<section id="Default"><title>Valor por defecto</title>

    <p>Si una directiva tiene un valor por defecto (esto significa
    que, si no especifica un valor explicitamente en la
    configuraci&#243;n, el servidor Apache se comportar&#225; como si hubiera
    especificado ese valor por defecto). Si no existe un valor por
    defecto, en este apartado aparecer&#225; "<em>None</em>". Tenga en
    cuenta que el valor por defecto que se especifica aqu&#237; puede no
    ser el mismo que el que viene especificado para la directiva en el
    fichero de configuraci&#243;n httpd.conf que viene por defecto.</p>
</section>

<section id="Context"><title>Contexto</title>

    <p>Indica en qu&#233; parte de los ficheros de configuraci&#243;n del
    servidor se puede usar la directiva. Es una lista de elementos
    separados por comas. Los valores permitidos son los
    siguientes:</p>

    <dl>
      <dt>server config</dt>

      <dd>Significa que la directiva puede ser usada en los ficheros
      de configuraci&#243;n del servidor (<em>por ejemplo</em>,
      <code>httpd.conf</code>), pero <strong>no</strong> dentro de las
      secciones <directive module="core"
      type="section">VirtualHost</directive> ni <directive
      module="core" type="section">Directory</directive>. Tambi&#233;n
      significa que la directiva no puede usarse en los ficheros
      <code>.htaccess</code>.</dd>

      <dt>virtual host</dt>

      <dd>Este contexto significa que la directiva puede aparecer
      dentro de las secciones <directive module="core"
      type="section">VirtualHost</directive> de los ficheros de
      configuraci&#243;n del servidor.</dd>

      <dt>directory</dt>

      <dd>Una directiva marcada como v&#225;lida en este contexto puede
      usarse en las secciones <directive module="core"
      type="section">Directory</directive>, <directive type="section"
      module="core">Location</directive>, y <directive module="core"
      type="section">Files</directive> en los ficheros de
      configuraci&#243;n del servidor, ateni&#233;ndose en todo caso a las
      restricciones especificadas en el documento <a
      href="../sections.html">Modo de funcionamiento de las secciones
      Directory, Location y Files</a>.</dd>

      <dt>.htaccess</dt>

      <dd>Si una directiva es v&#225;lida en este contexto, eso significa
      que puede aparecer en los ficheros <code>.htaccess</code>. El
      valor de la directiva puede no ser procesada si hay sobre ella
      una orden de <a href="#Override" >sobreescritura</a> activa en
      ese momento.</dd>
    </dl>

    <p>Una directiva puede usarse <em>solo</em> en el contexto
    especificado, si la usa en otro sitio, se producir&#225; en error de
    configuraci&#243;n que har&#225; que el servidor no pueda servir peticiones
    en el contexto correctamente, o que el servidor no pueda
    funcionar en absoluto -- <em>por ejemplo</em>, puede que el
    servidor no se inicie.</p>

    <p>Las ubicaciones v&#225;lidas para una directiva son el resultado de
    la operaci&#243;n booleana OR de todos los contextos listados m&#225;s
    arriba en que est&#233; perimitido su uso. En otras palabras, una
    directiva que est&#233; marcada como v&#225;lida en "<code>server config,
    .htaccess</code>" puede usarse tanto en el fichero
    <code>httpd.conf</code> como en los ficheros
    <code>.htaccess</code>, pero no dentro de las secciones
    <directive module="core" type="section">Directory</directive> o
    <directive module="core"
    type="section">VirtualHost</directive>.</p>
</section>

<section id="Override"><title>Override</title>

    <p>Este atributo indica qu&#233; configuraci&#243;n de las especificadas
    para una directiva es la que prevalece cuando la directiva aparece
    en un fichero <code>.htaccess</code>. Si el <a href="#Context"
    >contexto</a> de una directiva no permite que aparezca en ficheros
    <code>.htaccess</code>, entonces no aparecer&#225; ning&#250;n contexto en
    este campo.</p>

    <p>Para que se aplique el valor especificado en este campo se usa
    la directiva <directive module="core">AllowOverride</directive>, y
    se aplica a un entorno en particular (por ejemplo un directorio)
    y todo lo que haya por debajo de &#233;l, a menos que haya alguna
    modificaci&#243;n posterior por directivas <directive
    module="core">AllowOverride</directive> a niveles m&#225;s bajos. La
    documentaci&#243;n de esta directiva tambi&#233;n especifica los valores que
    puede tomar override.</p>
</section>

<section id="Status"><title>Estado</title>

    <p>Indica el grado de integraci&#243;n con el el servidor web Apache
    que presenta la directiva; en otras palabras, puede que tenga que
    recompilar el servidor con un conjunto mejorado de m&#243;dulos para
    tener acceso a algunas directivas y a sus funcionalidades. Los
    valores posibles de este campo son:</p>

    <dl>
      <dt>Core</dt>

      <dd>Si una directiva tiene estado "Core", esto significa que su
      grado de integraci&#243;n con el servidor Apache es muy alto, y que
      est&#225; disponible siempre.</dd>

      <dt>MPM</dt>

      <dd>Una directiva etiquetada con el estado "MPM" pertenece a un
      <a href="../mpm.html">M&#243;dulo de MultiProcesamiento</a>. Este
      tipo de directiva estar&#225; disponible solamente si est&#225; usando uno
      de los MPMs listados en la l&#237;nea <a href="#Module">M&#243;dulo</a> de
      la deficinici&#243;n de la directiva.</dd>

      <dt>Base</dt>

      <dd>Una directiva etiquetada con el estado "Base" est&#225; soportada
      por uno de los m&#243;dulos est&#225;ndar de Apache, que est&#225; compilado en
      el servidor por defecto, y est&#225; siempre disponible a no ser que
      haya eliminado ese m&#243;dulo espec&#237;ficamente.</dd>

      <dt>Extension</dt>

      <dd>Una directiva con el estado "Extension" pertenece a un
      m&#243;dulo incluido en el kit del servidor Apache, pero que no est&#225;
      normalmente compilado en el servidor. Para activar la directiva
      y sus funcionalidades, tendr&#225; que recompilar Apache.</dd>

      <dt>Experimental</dt>

      <dd>El estado "Experimental" indica que la directiva est&#225;
      disponible como parte de la distribuci&#243;n Apache, pero que su correcto
      funcionamiento no est&#225; todav&#237;a probado. Puede que la directiva
      est&#233; siendo documentada para completarla, o puede que no se
      ofrezca soporte. El m&#243;dulo que ofrece la directiva puede o no
      estar compilado por defecto; compruebe la parte superior de la
      p&#225;gina que describe la directiva y sus m&#243;dulos para ver si hay
      alguna indicaci&#243;n sobre su disponibilidad.</dd>
    </dl>
</section>

<section id="Module"><title>M&#243;dulo</title>

    <p>Indica el m&#243;dulo en el cual se define la directiva.</p>
</section>

<section id="Compatibility"><title>Compatibilidad</title>

    <p>Si una directiva no era originalmente parte de la versi&#243;n 2.0
    de la distribuci&#243;n de Apache, la versi&#243;n en la que fue introducida
    debe aparecer aqu&#237;. Adem&#225;s, si la directiva est&#225; disponible solo
    en algunas plataformas, tambi&#233;n debe figurar aqu&#237;.</p>
</section>

</manualpage>



