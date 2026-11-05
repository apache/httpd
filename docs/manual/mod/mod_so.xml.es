<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1917015 -->
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

<modulesynopsis metafile="mod_so.xml.meta">

<name>mod_so</name>
<description>Carga de código ejecutable y
módulos en el servidor en el momento de inicio o reinicio</description>
<status>Extension</status>
<sourcefile>mod_so.c</sourcefile>
<identifier>so_module</identifier>
<compatibility>Este es un módulo Base (siempre incluido) en
Windows</compatibility>

<summary>

    <p>En sistemas operativos seleccionados, este módulo puede usarse para
    cargar módulos en el servidor HTTP Apache en tiempo de ejecución mediante el mecanismo <a
    href="../dso.html">Dynamic Shared Object</a> (DSO),
    en lugar de requerir una recompilación.</p>

    <p>En Unix, el código cargado normalmente procede de archivos de objeto
    compartido (generalmente con extensión <code>.so</code>); en Windows
    puede tener la extensión <code>.so</code> o <code>.dll</code>.</p>

    <note type="warning"><title>Advertencia</title>
    <p>Los módulos compilados para una versión principal del servidor HTTP Apache
    generalmente no funcionarán en otra. (por ejemplo, 1.3 frente a 2.0, o 2.0 frente a
    2.2) Suele haber cambios en la API entre una versión principal y
    otra que requieren que los módulos se modifiquen para funcionar con la nueva
    versión.</p>
    </note>
</summary>

<section id="windows"><title>Crear módulos cargables para Windows</title>

    <note><title>Nota</title>
    <p>En Windows, donde los archivos cargables normalmente tienen la extensión
    <code>.dll</code>, los módulos de httpd se llaman
    <code>mod_whatever.so</code>, igual que en las demás plataformas.
    Sin embargo, puede encontrar módulos de terceros, como PHP por
    ejemplo, que siguen usando la convención <code>.dll</code>.</p>

    <p>Aunque <code>mod_so</code> todavía carga módulos con nombres
    <code>ApacheModuleFoo.dll</code>, se prefiere la nueva convención de
    nombres; si está convirtiendo su módulo cargable para 2.0,
    cambie el nombre a esta convención de 2.0.</p></note>

    <p>La API de módulos de httpd no cambia entre las versiones de Unix y
    Windows. Muchos módulos se ejecutarán en Windows con pocos o ningún
    cambio respecto a Unix, aunque otros dependen de aspectos de la
    arquitectura Unix que no están presentes en Windows, y
    no funcionarán.</p>

    <p>Cuando un módulo funciona, puede añadirse al servidor de
    una de dos maneras. Como en Unix, puede compilarse dentro del
    servidor. Como httpd para Windows no tiene el
    programa <code>Configure</code> de httpd para Unix, el archivo fuente
    del módulo debe añadirse al archivo de proyecto ApacheCore, y
    sus símbolos deben añadirse al archivo
    <code>os\win32\modules.c</code>.</p>

    <p>La segunda manera es compilar el módulo como una DLL, una biblioteca
    compartida que puede cargarse en el servidor en tiempo de ejecución, usando
    la directiva <directive>LoadModule</directive>. Estas DLL de módulo pueden
    distribuirse y ejecutarse en cualquier instalación de httpd para Windows,
    sin recompilar el servidor.</p>

    <p>Para crear una DLL de módulo, es necesario un pequeño cambio en el
    archivo fuente del módulo: el registro del módulo debe exportarse desde
    la DLL (que se creará más adelante; ver más abajo). Para ello,
    añada <code>AP_DECLARE_MODULE</code> (definido en los
    archivos de cabecera de httpd) a la definición del registro de módulo de su módulo.
    Por ejemplo, si su módulo tiene:</p>

<example>
    module foo_module;
</example>

    <p>Sustitúyalo por:</p>
<example>
    AP_DECLARE_MODULE(foo);
</example>

    <p>Tenga en cuenta que esto solo se activará en Windows, de modo que el
    módulo puede seguir usándose, sin cambios, en Unix si es necesario.
    Además, si está familiarizado con los archivos <code>.DEF</code>, puede
    exportar el registro del módulo con ese método en su lugar.</p>

    <p>Ahora, cree una DLL que contenga su módulo. Necesitará
    enlazarla con la biblioteca de exportación libhttpd.lib que se
    crea al compilar la biblioteca compartida libhttpd.dll. Puede
    que también tenga que cambiar la configuración del compilador para asegurarse de que
    los archivos de cabecera de httpd se localicen correctamente. Puede encontrar
    esta biblioteca en el directorio de módulos de la raíz de su servidor. Es
    recomendable tomar un archivo .dsp de un módulo existente del árbol para
    asegurarse de que el entorno de compilación está configurado correctamente, o
    como alternativa, comparar las opciones de compilador y enlazado con su
    .dsp.</p>

    <p>Esto debería crear una versión DLL de su módulo. Ahora simplemente
    colóquela en el directorio <code>modules</code> de la raíz de su
    servidor, y use la directiva <directive>LoadModule</directive>
    para cargarla.</p>

</section>

<directivesynopsis>
<name>LoadFile</name>
<description>Enlaza el archivo de objeto o la biblioteca indicados</description>
<syntax>LoadFile <em>filename</em> [<em>filename</em>] ...</syntax>
<contextlist>
<context>server config</context>
<context>virtual host</context>
</contextlist>

<usage>

    <p>La directiva <directive>LoadFile</directive> enlaza los archivos de objeto o las
    bibliotecas indicados cuando se inicia o reinicia el servidor; esto se usa
    para cargar código adicional que puede ser necesario para que algún módulo
    funcione. <em>Filename</em> es una ruta absoluta o
    relativa a <a href="core.html#serverroot">ServerRoot</a>.</p>

    <p>Por ejemplo:</p>

    <highlight language="config">
LoadFile "libexec/libxmlparse.so"
    </highlight>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>LoadModule</name>
<description>Enlaza el archivo de objeto o la biblioteca, y lo añade a la lista
de módulos activos</description>
<syntax>LoadModule <em>module filename</em></syntax>
<contextlist>
<context>server config</context>
<context>virtual host</context>
</contextlist>

<usage>
    <p>La directiva <directive>LoadModule</directive> enlaza el archivo de objeto o la biblioteca
    <em>filename</em> y añade la estructura de módulo llamada
    <em>module</em> a la lista de módulos activos. <em>Module</em>
    es el nombre de la variable externa de tipo
    <code>module</code> en el archivo, y aparece listado como el <a
    href="module-dict.html#ModuleIdentifier">identificador de módulo</a>
    en la documentación del módulo.</p>

    <p>Por ejemplo:</p>

    <highlight language="config">
LoadModule status_module "modules/mod_status.so"
    </highlight>

    <p>carga el módulo indicado desde el subdirectorio modules de
    ServerRoot.</p>
</usage>

</directivesynopsis>
</modulesynopsis>
