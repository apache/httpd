<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1793934 -->
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

<modulesynopsis metafile="mod_example_hooks.xml.meta">

<name>mod_example_hooks</name>
<description>Ilustra la API de módulos de Apache</description>
<status>Experimental</status>
<sourcefile>mod_example_hooks.c</sourcefile>
<identifier>example_hooks_module</identifier>

<summary>
    <p>Los archivos del directorio <code>modules/examples</code>
    del árbol de directorios de la distribución de Apache se proporcionan como
    ejemplo para quienes deseen escribir módulos que usen la API de
    Apache.</p>

    <p>El archivo principal es <code>mod_example_hooks.c</code>, que
    ilustra todos los mecanismos de callback y sintaxis de llamada
    diferentes. Un módulo adicional no tiene por qué incluir, ni mucho
    menos, rutinas para todos los callbacks.</p>

    <p>El módulo de ejemplo es un módulo que funciona realmente. Si lo
    enlaza en su servidor, activa el handler "example-hooks-handler" para una
    ubicación, y luego navega a esa ubicación, verá una
    muestra de parte del seguimiento que hizo el módulo de ejemplo mientras
    se realizaban las distintas llamadas.</p>
</summary>

<section id="compiling"><title>Compilar el módulo example_hooks</title>

    <p>Para incluir el módulo example_hooks en su servidor, siga los
    pasos siguientes:</p>

    <ol>
      <li>
        Ejecute <program>configure</program> con la opción
        <code>--enable-example-hooks</code>.</li>

      <li>Compile el servidor (ejecute "<code>make</code>").</li>
    </ol>

    <p>Para añadir otro módulo propio:</p>

    <ol type="A">
      <li><code>cp modules/examples/mod_example_hooks.c
      modules/new_module/<em>mod_myexample.c</em></code></li>

      <li>Modifique el archivo.</li>

      <li>Cree <code>modules/new_module/config.m4</code>.
        <ol>
          <li>Añada <code>APACHE_MODPATH_INIT(new_module)</code>.</li>
          <li>Copie la línea APACHE_MODULE con "example_hooks" de
            <code>modules/examples/config.m4</code>.</li>
          <li>Sustituya el primer argumento "example_hooks" por <em>myexample</em>.</li>
          <li>Sustituya el segundo argumento por una breve descripción de su módulo.
            Se usará en <code>configure --help</code>.</li>
          <li>Si su módulo necesita opciones adicionales del compilador C, del enlazador o
            bibliotecas adicionales, añádalas a CFLAGS, LDFLAGS y LIBS según corresponda.
            Consulte otros archivos <code>config.m4</code> del directorio de módulos para
            ver ejemplos.</li>
          <li>Añada <code>APACHE_MODPATH_FINISH</code>.</li>
        </ol>
      </li>

      <li>Cree <code>module/new_module/Makefile.in</code>.
      Si su módulo no necesita instrucciones de compilación especiales,
      todo lo que necesita tener en ese archivo es
      <code>include $(top_srcdir)/build/special.mk</code>.</li>

      <li>Ejecute ./buildconf desde el directorio de nivel superior.</li>

      <li>Compile el servidor con --enable-myexample</li>

    </ol>
</section>

<section id="using"><title>Usar el módulo <code>mod_example_hooks</code></title>

    <p>Para activar el módulo example_hooks, incluya un bloque similar
    al siguiente en su archivo <code>httpd.conf</code>:</p>
<highlight language="config">
&lt;Location "/example-hooks-info"&gt;
   SetHandler example-hooks-handler
&lt;/Location&gt;
</highlight>

    <p>Como alternativa, puede poner lo siguiente en un archivo <a
    href="core.html#accessfilename"><code>.htaccess</code></a>
    y luego solicitar el archivo "test.example" desde esa ubicación:</p>
<highlight language="config">
   AddHandler example-hooks-handler .example
</highlight>

    <p>Tras recargar/reiniciar su servidor, debería poder
    navegar a esa ubicación y ver la breve muestra mencionada
    anteriormente.</p>
</section>

<directivesynopsis>
<name>Example</name>
<description>Directiva de demostración para ilustrar la API de módulos de
Apache</description>
<syntax>Example</syntax>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<override>Options</override>

<usage>
    <p>La directiva <directive>Example</directive> simplemente activa una
    marca de demostración que muestra el manejador de contenido del módulo de ejemplo. No
    admite argumentos. Si navega a una URL a la que se aplica el
    manejador de contenido example-hooks, obtendrá una muestra de las
    rutinas del módulo y cómo y en qué orden se llamaron
    para atender la petición del documento. El efecto de esta
    directiva se puede observar en el punto "<code>Example
    directive declared here: YES/NO</code>".</p>
</usage>
</directivesynopsis>

</modulesynopsis>
