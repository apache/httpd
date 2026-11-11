<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1330994 -->
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

<modulesynopsis metafile="mod_file_cache.xml.meta">

<name>mod_file_cache</name>
<description>Cachea en memoria una lista estática de archivos</description>
<status>Experimental</status>
<sourcefile>mod_file_cache.c</sourcefile>
<identifier>file_cache_module</identifier>

<summary>

    <note type="warning">
      Este módulo debe usarse con cuidado. Puede romper fácilmente un
      sitio usando <module>mod_file_cache</module>, así que lea este
      documento con atención.
    </note>

    <p><em>Cachear</em> los archivos solicitados con frecuencia que
    cambian muy poco es una técnica para reducir la carga del servidor.
    <module>mod_file_cache</module> proporciona dos técnicas para cachear
    archivos <em>estáticos</em> solicitados con frecuencia. Mediante
    directivas de configuración, puede indicar a
    <module>mod_file_cache</module> que abra y haga <code>mmap()</code>
    de un archivo, o que abra previamente un archivo y guarde su
    <em>handle de archivo</em> abierto. Ambas técnicas reducen la carga
    del servidor al procesar peticiones de estos archivos, haciendo parte
    del trabajo (en concreto, la E/S de archivos) necesario para servir
    el archivo cuando se arranca el servidor en lugar de en cada
    petición.</p>

    <p>Aviso: no puede usar esto para acelerar programas CGI u otros
    archivos que se sirvan mediante manejadores de contenido especiales.
    Solo puede usarse con archivos regulares, que normalmente son
    servidos por el manejador de contenido del núcleo de Apache.</p>

    <p>Este módulo es una extensión que toma prestado gran parte de su
    diseño del módulo <code>mod_mmap_static</code> de Apache 1.3.</p>
</summary>

<section id="using"><title>Uso de mod_file_cache</title>

    <p><module>mod_file_cache</module> cachea una lista de archivos
    configurados estáticamente mediante las directivas <directive
    module="mod_file_cache">MMapFile</directive> o <directive
    module="mod_file_cache">CacheFile</directive> en la configuración
    principal del servidor.</p>

    <p>No todas las plataformas soportan ambas directivas. Recibirá un
    mensaje de error en el log de errores del servidor si intenta usar
    una directiva no soportada. Si se indica una directiva no soportada,
    el servidor arrancará, pero el archivo no se cacheará. En las
    plataformas que soportan ambas directivas, debería probar con las dos
    para ver cuál le funciona mejor.</p>

    <section><title>Directiva MMapFile</title>

      <p>La directiva <directive module="mod_file_cache"
      >MMapFile</directive> de <module>mod_file_cache</module> mapea en
      memoria una lista de archivos configurados estáticamente mediante
      la llamada al sistema <code>mmap()</code>. Esta llamada al sistema
      está disponible en la mayoría de los derivados modernos de Unix,
      pero no en todos. A veces hay límites específicos del sistema sobre
      el tamaño y el número de archivos que se pueden mapear con
      <code>mmap()</code>; probablemente, experimentar sea la forma más
      sencilla de averiguarlo.</p>

      <p>Este mapeo con <code>mmap()</code> se realiza una sola vez, al
      arrancar o reiniciar el servidor. Así que, siempre que uno de los
      archivos mapeados cambie en el sistema de archivos, <em>tiene</em>
      que reiniciar el servidor (consulte la documentación sobre <a
      href="../stopping.html">Detener y reiniciar</a>). Para insistir en
      este punto: si los archivos se modifican <em>en el propio
      lugar</em> sin reiniciar el servidor, puede terminar sirviendo
      peticiones completamente erróneas. Debería actualizar los archivos
      eliminando la copia antigua y poniendo una copia nueva en su lugar.
      La mayoría de las herramientas, como <code>rdist</code> y
      <code>mv</code>, hacen esto. La razón por la que este módulo no se
      encarga de los cambios en los archivos es que esa comprobación
      necesitaría un <code>stat()</code> adicional cada vez, lo cual es
      un desperdicio y va en contra del objetivo de reducir la E/S.</p>
    </section>

    <section><title>Directiva CacheFile</title>

      <p>La directiva <directive module="mod_file_cache"
      >CacheFile</directive> de <module>mod_file_cache</module> abre un
      <em>handle</em> o <em>descriptor de archivo</em> activo para el
      archivo (o archivos) listados en la directiva de configuración, y
      coloca estos handles de archivo abiertos en la caché. Cuando se
      solicita el archivo, el servidor recupera el handle de la caché y
      lo pasa a la API de sockets <code>sendfile()</code> (o
      <code>TransmitFile()</code> en Windows).</p>

      <!-- XXX
      <p>Insert more details about sendfile API...</p>
      -->

      <p>Este cacheo de handles de archivo se realiza una sola vez, al
      arrancar o reiniciar el servidor. Así que, siempre que uno de los
      archivos cacheados cambie en el sistema de archivos, <em>tiene</em>
      que reiniciar el servidor (consulte la documentación sobre <a
      href="../stopping.html">Detener y reiniciar</a>). Para insistir en
      este punto: si los archivos se modifican <em>en el propio
      lugar</em> sin reiniciar el servidor, puede terminar sirviendo
      peticiones completamente erróneas. Debería actualizar los archivos
      eliminando la copia antigua y poniendo una copia nueva en su lugar.
      La mayoría de las herramientas, como <code>rdist</code> y
      <code>mv</code>, hacen esto.</p>
    </section>

    <note><title>Nota</title>
      <p>No se moleste en pedir una directiva que cachee recursivamente
      todos los archivos de un directorio. En su lugar, pruebe esto...
      Consulte la directiva <directive module="core">Include</directive>,
      y considere este comando:</p>

      <example>
        find /www/htdocs -type f -print \<br />
        | sed -e 's/.*/mmapfile &amp;/' &gt; /www/conf/mmap.conf
      </example>
    </note>
</section>

<directivesynopsis>
<name>MMapFile</name>
<description>Mapea en memoria una lista de archivos al arrancar el servidor</description>
<syntax>MMapFile <var>file-path</var> [<var>file-path</var>] ...</syntax>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>La directiva <directive>MMapFile</directive> mapea en memoria uno
    o más archivos (indicados como argumentos separados por espacios) al
    arrancar el servidor. Se desmapean automáticamente al apagar el
    servidor. Cuando los archivos hayan cambiado en el sistema de
    archivos, debe enviarse al menos una señal <code>HUP</code> o
    <code>USR1</code> al servidor para volver a hacerles
    <code>mmap()</code>.</p>

    <p>Tenga cuidado con los argumentos <var>file-path</var>: deben
    coincidir literalmente con la ruta del sistema de archivos que
    generan los manejadores de traducción de URL a nombre de archivo de
    Apache. No podemos comparar inodos ni otros datos para hacer
    coincidir rutas a través de enlaces simbólicos, <em>etc.</em>, porque
    eso de nuevo supondría llamadas <code>stat()</code> adicionales, lo
    cual no es aceptable. Este módulo puede funcionar o no con nombres de
    archivo reescritos por <module>mod_alias</module> o
    <module>mod_rewrite</module>.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      MMapFile /usr/local/apache/htdocs/index.html
      </highlight>
    </example>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CacheFile</name>
<description>Cachea una lista de handles de archivo al arrancar el servidor</description>
<syntax>CacheFile <var>file-path</var> [<var>file-path</var>] ...</syntax>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>La directiva <directive>CacheFile</directive> abre handles para
    uno o más archivos (indicados como argumentos separados por
    espacios) y coloca estos handles en la caché al arrancar el
    servidor. Los handles de los archivos cacheados se cierran
    automáticamente al apagar el servidor. Cuando los archivos hayan
    cambiado en el sistema de archivos, el servidor debería reiniciarse
    para volver a cachearlos.</p>

    <p>Tenga cuidado con los argumentos <var>file-path</var>: deben
    coincidir literalmente con la ruta del sistema de archivos que
    generan los manejadores de traducción de URL a nombre de archivo de
    Apache. No podemos comparar inodos ni otros datos para hacer
    coincidir rutas a través de enlaces simbólicos, <em>etc.</em>, porque
    eso de nuevo supondría llamadas <code>stat()</code> adicionales, lo
    cual no es aceptable. Este módulo puede funcionar o no con nombres de
    archivo reescritos por <module>mod_alias</module> o
    <module>mod_rewrite</module>.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      CacheFile /usr/local/apache/htdocs/index.html
      </highlight>
    </example>
</usage>
</directivesynopsis>

</modulesynopsis>
