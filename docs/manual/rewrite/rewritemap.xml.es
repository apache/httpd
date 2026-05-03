<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1932819:1933728 (outdated) -->
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
<manualpage metafile="rewritemap.xml.meta">
  <parentdocument href="./">Rewrite</parentdocument>
  <title>Uso de RewriteMap</title>
  <summary>

    <p>Este documento complementa la <module>mod_rewrite</module>
<a href="../mod/mod_rewrite.html">documentación de referencia</a>. Describe
el uso de la directiva <directive module="mod_rewrite">RewriteMap</directive>,
y proporciona ejemplos de cada uno de los diversos tipos de <directive module="mod_rewrite"
>RewriteMap</directive>.</p>

    <note type="warning">Tenga en cuenta que muchos de estos ejemplos no funcionarán sin cambios en su
configuración particular del servidor, por lo que es importante que los
entienda, en lugar de simplemente copiar y pegar los ejemplos en su
configuración.</note>

  </summary>
  <seealso><a href="../mod/mod_rewrite.html">Documentación del módulo</a></seealso>
  <seealso><a href="intro.html">Introducción a mod_rewrite</a></seealso>
  <seealso><a href="remapping.html">Redirección y remapeo</a></seealso>
  <seealso><a href="access.html">Control de acceso</a></seealso>
  <seealso><a href="vhosts.html">Hosts virtuales</a></seealso>
  <seealso><a href="proxy.html">Proxy</a></seealso>
  <seealso><a href="advanced.html">Técnicas avanzadas</a></seealso>
  <seealso><a href="avoid.html">Cuándo no usar mod_rewrite</a></seealso>

  <section id="introduction">
    <title>Introducción</title>

   <p>
   La directiva <directive module="mod_rewrite">RewriteMap</directive>
   define una función externa que puede ser llamada en el contexto de
   directivas <directive module="mod_rewrite">RewriteRule</directive> o
   <directive module="mod_rewrite">RewriteCond</directive> para
   realizar reescrituras que son demasiado complicadas, o demasiado especializadas para ser
   realizadas solo con expresiones regulares. La fuente de esta búsqueda puede
   ser cualquiera de los tipos listados en las secciones siguientes, y enumerados en
   la documentación de referencia de <directive module="mod_rewrite">RewriteMap</directive>.</p>

   <p>La sintaxis de la directiva <directive module="mod_rewrite">RewriteMap</directive>
   es la siguiente:</p>

<highlight language="config">
RewriteMap <em>MapName</em> <em>MapType</em>:<em>MapSource</em>
</highlight>

    <p>El <a id="mapfunc" name="mapfunc"><em>MapName</em></a> es un
    nombre arbitrario que asigna al mapa, y que usará en
    directivas más adelante. Los argumentos se pasan al mapa a través de la
    siguiente sintaxis:</p>

    <p class="indent">
      <strong>
        <code>${</code> <em>MapName</em> <code>:</code> <em>LookupKey</em>
        <code>}</code> <br/> <code>${</code> <em>MapName</em> <code>:</code>
        <em>LookupKey</em> <code>|</code> <em>DefaultValue</em> <code>}</code>
      </strong>
    </p>

    <p>Cuando se encuentra tal construcción, se consulta el mapa <em>MapName</em>
      y se busca la clave <em>LookupKey</em>. Si la
      clave se encuentra, la construcción de función de mapa se sustituye por
      <em>SubstValue</em>. Si la clave no se encuentra entonces se
      sustituye por <em>DefaultValue</em> o por la cadena vacía
      si no se especificó <em>DefaultValue</em>.</p>

    <p>Por ejemplo, puede definir un
      <directive module="mod_rewrite">RewriteMap</directive> como:</p>
    <highlight language="config">
RewriteMap examplemap "txt:/path/to/file/map.txt"
    </highlight>
    <p>Entonces podrá usar este mapa en una
      <directive module="mod_rewrite">RewriteRule</directive> de la siguiente manera:</p>
      <highlight language="config">
RewriteRule "^/ex/(.*)" "${examplemap:$1}"
      </highlight>

<p>Se puede especificar un valor predeterminado en caso de que no se encuentre nada
en el mapa:</p>

<highlight language="config">
RewriteRule "^/ex/(.*)" "${examplemap:$1|/not_found.html}"
</highlight>

<note><title>Contexto per-directorio y .htaccess</title>
<p>
La directiva <directive module="mod_rewrite">RewriteMap</directive> no puede usarse
en secciones <directive module="core" type="section">Directory</directive> ni en
archivos <code>.htaccess</code>. Debe
declarar el mapa en contexto de servidor o virtualhost. Puede usar el mapa,
una vez creado, en sus directivas <directive module="mod_rewrite">RewriteRule</directive> y
<directive module="mod_rewrite">RewriteCond</directive> en esos
ámbitos. Simplemente no puede <strong>declararlo</strong> en esos ámbitos.</p>
</note>

<p>Las secciones siguientes describen los diversos <em>MapType</em>s que
pueden usarse, y dan ejemplos de cada uno.</p>
  </section>

  <section id="int">
    <title>int: Función Interna</title>

    <p>Cuando se usa un MapType de <code>int</code>, el MapSource es una
    de las funciones internas disponibles de <directive module="mod_rewrite">RewriteMap</directive>.
    Los autores de módulos pueden proporcionar
    funciones internas adicionales registrándolas con la
    API <code>ap_register_rewrite_mapfunc</code>.
    Las funciones que se proporcionan por defecto son:
    </p>

    <ul>
      <li><strong>toupper</strong>:<br/>
             Convierte la clave a todo mayúsculas.</li>
      <li><strong>tolower</strong>:<br/>
             Convierte la clave a todo minúsculas.</li>
      <li><strong>escape</strong>:<br/>
             Traduce caracteres especiales en la clave a
            codificaciones hexadecimales.</li>
      <li><strong>unescape</strong>:<br/>
             Traduce codificaciones hexadecimales en la clave de vuelta a
            caracteres especiales.</li>
    </ul>

    <p>
    Para usar una de estas funciones, cree un <directive module="mod_rewrite"
    >RewriteMap</directive> que referencie
    la función int, y luego úselo en su <directive module="mod_rewrite"
    >RewriteRule</directive>:
    </p>

   <p><strong>Redirigir una URI a una versión toda en minúsculas de sí misma</strong></p>
    <highlight language="config">
RewriteMap lc int:tolower
RewriteRule "(.*)" "${lc:$1}" [R]
    </highlight>

    <note>
    <p>Por favor tenga en cuenta que el ejemplo ofrecido aquí es para
    fines ilustrativos únicamente, y no es una recomendación. Si desea
    hacer URLs insensibles a mayúsculas/minúsculas, considere usar
    <module>mod_speling</module> en su lugar.
    </p>
    </note>

  </section>

  <section id="txt">
    <title>txt: Mapas de texto plano</title>

    <p>Cuando se usa un MapType de <code>txt</code>, el MapSource es una ruta del sistema de archivos a un
    archivo de mapeo de texto plano, que contiene un par clave/valor separado por espacios
    por línea. Opcionalmente, una línea puede contener un comentario, comenzando con
    un carácter '#'.</p>

    <p>Un archivo de mapa de reescritura de texto válido tendrá la siguiente sintaxis:</p>

    <example>
      # Línea de comentario<br />
      <strong><em>MatchingKey</em> <em>SubstValue</em></strong><br />
      <strong><em>MatchingKey</em> <em>SubstValue</em></strong> # comentario<br />
    </example>

    <p>Cuando se invoca el <directive module="mod_rewrite">RewriteMap</directive>,
    el argumento se busca en el
    primer argumento de una línea, y, si se encuentra, se devuelve el valor de
    sustitución.</p>

    <p>Por ejemplo, podemos usar un archivo de mapa para traducir nombres de productos a
    IDs de productos para URLs más fáciles de recordar, usando la siguiente
    receta:</p>
<p><strong>Configuración de Producto a ID</strong></p>
    <highlight language="config">
RewriteMap product2id "txt:/etc/apache2/productmap.txt"
RewriteRule "^/product/(.*)" "/prods.php?id=${product2id:$1|NOTFOUND}" [PT]
    </highlight>

    <p>Asumimos aquí que el script <code>prods.php</code> sabe qué
    hacer cuando recibe un argumento de <code>id=NOTFOUND</code> cuando
    un producto no se encuentra en el mapa de búsqueda.</p>

    <p>El archivo <code>/etc/apache2/productmap.txt</code> entonces contiene
    lo siguiente:</p>

    <example><title>Mapa de Producto a ID</title>
##<br />
##  productmap.txt - Archivo de mapa de Producto a ID<br />
##<br />
<br />
television 993<br />
stereo     198<br />
fishingrod 043<br />
basketball 418<br />
telephone  328
    </example>

    <p>Así, cuando se solicita <code>http://example.com/product/television</code>,
    se aplica la <directive module="mod_rewrite">RewriteRule</directive>,
    y la solicitud
    se mapea internamente a <code>/prods.php?id=993</code>.</p>

    <note><title>Nota: archivos .htaccess</title>
    El ejemplo dado está diseñado para usarse en contexto de servidor o virtualhost.
    Si planea usarlo en un archivo <code>.htaccess</code>,
    necesitará eliminar la barra inicial del patrón de
    reescritura para que coincida con algo:
    <highlight language="config">
RewriteRule "^product/(.*)" "/prods.php?id=${product2id:$1|NOTFOUND}" [PT]
    </highlight>
    </note>

    <note><title>Búsquedas en caché</title>
    <p>
    Las claves buscadas son almacenadas en caché por httpd hasta que el <code>mtime</code>
    (tiempo de modificación) del archivo de mapa cambia, o el servidor httpd se
    reinicia. Esto asegura un mejor rendimiento en mapas que son llamados
    por muchas solicitudes.
    </p>
    </note>

  </section>
  <section id="rnd">
    <title>rnd: Texto Plano Aleatorizado</title>

    <p>Cuando se usa un MapType de <code>rnd</code>, el MapSource es una
    ruta del sistema de archivos a un archivo de mapeo de texto plano, cada línea del cual
    contiene una clave, y uno o más valores separados por <code>|</code>.
    Uno de estos valores se elegirá al azar si la clave
    coincide.</p>

    <p>Por ejemplo, puede usar el siguiente archivo de mapa
    y directivas para proporcionar un balanceo de carga aleatorio entre
    varios servidores backend, a través de un proxy inverso. Las imágenes se envían
    a uno de los servidores en el grupo 'static', mientras que todo
    lo demás se envía a uno del grupo 'dynamic'.</p>

    <example><title>Archivo de mapa de reescritura</title>
##<br />
##  map.txt -- mapa de reescritura<br />
##<br />
<br />
static   www1|www2|www3|www4<br />
dynamic  www5|www6
    </example>
<p><strong>Directivas de configuración</strong></p>
    <highlight language="config">
RewriteMap servers "rnd:/path/to/file/map.txt"

RewriteRule "^/(.*\.(png|gif|jpg))" "http://${servers:static}/$1"  [NC,P,L]
RewriteRule "^/(.*)"                "http://${servers:dynamic}/$1" [P,L]
    </highlight>

    <p>Así, cuando se solicita una imagen y la primera de estas reglas
    coincide, <directive module="mod_rewrite">RewriteMap</directive> busca la cadena
    <code>static</code> en el archivo de mapa, que devuelve uno de los
    nombres de host especificados al azar, que luego se usa en el
    destino de la <directive module="mod_rewrite">RewriteRule</directive>.</p>

    <p>Si quisiera que uno de los servidores sea más probable de ser elegido
    (por ejemplo, si uno de los servidores tiene más memoria que los otros,
    y por lo tanto puede manejar más solicitudes) simplemente listelo más veces en el
    archivo de mapa.</p>

    <example>
static   www1|www1|www2|www3|www4
    </example>

  </section>

  <section id="dbm">
    <title>dbm: Archivo Hash DBM</title>

    <p>Cuando se usa un MapType de <code>dbm</code>, el MapSource es una
    ruta del sistema de archivos a un archivo de base de datos DBM que contiene pares clave/valor para
    ser usados en el mapeo. Esto funciona exactamente igual que el
    mapa <code>txt</code>, pero es mucho más rápido, porque un DBM está indexado,
    mientras que un archivo de texto no. Esto permite un acceso más rápido a la
    clave deseada.</p>

    <p>Opcionalmente puede especificar un tipo particular de dbm:</p>

 <highlight language="config">
RewriteMap examplemap "dbm=sdbm:/etc/apache/mapfile.dbm"
 </highlight>

    <p>El tipo puede ser <code>sdbm</code>, <code>gdbm</code>, <code>ndbm</code>
    o <code>db</code>.
    Sin embargo, se recomienda que simplemente use la utilidad <a
    href="../programs/httxt2dbm.html">httxt2dbm</a> que se
    proporciona con Apache HTTP Server, ya que usará la biblioteca DBM correcta,
    que coincida con la que se usó cuando se compiló httpd mismo.</p>

    <p>Para crear un archivo dbm, primero cree un archivo de mapa de texto como se describe
    en la sección <a href="#txt">txt</a>. Luego ejecute
    <code>httxt2dbm</code>:</p>

<example>
$ httxt2dbm -i mapfile.txt -o mapfile.map
</example>

<p>Luego puede referenciar el archivo resultante en su
directiva <directive module="mod_rewrite">RewriteMap</directive>:</p>

<highlight language="config">
RewriteMap mapname "dbm:/etc/apache/mapfile.map"
</highlight>

<note>
<p>Tenga en cuenta que con algunos tipos de dbm, se genera más de un archivo, con
un nombre base común. Por ejemplo, puede tener dos archivos llamados
<code>mapfile.map.dir</code> y <code>mapfile.map.pag</code>. Esto es
normal, y solo necesita usar el nombre base <code>mapfile.map</code> en
su directiva <directive module="mod_rewrite">RewriteMap</directive>.</p>
</note>

<note><title>Búsquedas en caché</title>
<p>
Las claves buscadas son almacenadas en caché por httpd hasta que el <code>mtime</code>
(tiempo de modificación) del archivo de mapa cambia, o el servidor httpd se
reinicia. Esto asegura un mejor rendimiento en mapas que son llamados
por muchas solicitudes.
</p>
</note>

  </section>

  <section id="prg"><title>prg: Programa de Reescritura Externo</title>

    <p>Cuando se usa un MapType de <code>prg</code>, el MapSource es una
    ruta del sistema de archivos a un programa ejecutable que proporcionará el
    comportamiento de mapeo. Puede ser un archivo binario compilado, o un programa
    en un lenguaje interpretado como Python o Perl.</p>

    <p>Este programa se inicia una vez, cuando se inicia Apache HTTP Server,
    y luego se comunica con el motor de reescritura a través de
    <code>STDIN</code> y <code>STDOUT</code>. Para cada búsqueda de función de mapa,
    la clave se escribe en el <code>STDIN</code> del programa,
    seguida de un carácter de nueva línea. El programa debería leer una línea
    de <code>STDIN</code> (hasta e incluyendo la nueva línea), y
    escribir su respuesta como una única línea terminada en nueva línea en
    <code>STDOUT</code>. Las claves nunca contendrán caracteres de nueva línea;
    si se encuentra una clave que contenga una nueva línea, la búsqueda
    fallará.</p>

    <p>Si no hay un valor de búsqueda correspondiente, el programa de mapa
    debería devolver la cadena de cuatro caracteres "<code>NULL</code>" para
    indicar esto. Tenga en cuenta que esta comparación no distingue entre mayúsculas y minúsculas, así que
    "null", "Null", etc. también se tratan como una búsqueda fallida. Como
    consecuencia, no es posible que un programa de mapeo devuelva
    la cadena literal "NULL" como valor mapeado.</p>

    <p>El <code>STDERR</code> del programa se hereda del
    proceso padre de httpd, por lo que cualquier cosa que el programa escriba en
    <code>STDERR</code> terminará en el mismo lugar que la propia
    salida de errores de httpd (típicamente el <directive
    module="core">ErrorLog</directive>).</p>

    <p>Los programas de reescritura externos no se inician si están definidos en
    un contexto que no tiene <directive
    module="mod_rewrite">RewriteEngine</directive> establecido a
    <code>on</code>.</p>

    <p>Por defecto, los programas de reescritura externos se ejecutan como el
    usuario:grupo que inició httpd. Esto puede cambiarse en sistemas UNIX
    pasando nombre de usuario y nombre de grupo como tercer argumento a
    <directive module="mod_rewrite">RewriteMap</directive> en el
    formato <code>username:groupname</code>.</p>

    <p>Esta característica utiliza el mutex <code>rewrite-map</code>,
    que es necesario para una comunicación fiable con el programa.
    El mecanismo de mutex y el archivo de bloqueo pueden configurarse con la
    directiva <directive module="core">Mutex</directive>.</p>

    <p>Aquí se muestra un ejemplo simple que reemplazará todos los guiones con
    guiones bajos en una URI de solicitud.</p>

    <p><strong>Configuración de reescritura</strong></p>
    <highlight language="config">
RewriteMap d2u "prg:/www/bin/dash2under.py" apache:apache
RewriteRule "-" "${d2u:%{REQUEST_URI}}"
    </highlight>

    <p><strong>dash2under.py</strong></p>
    <highlight language="python">
#!/usr/bin/env python3
import sys

for line in sys.stdin:
    print(line.strip().replace('-', '_'), flush=True)
    </highlight>

<note><title>¡Precaución!</title>
<ul>
<li>Mantenga su programa de mapa de reescritura lo más simple posible. Si el programa
se cuelga, causará que httpd espere indefinidamente por una respuesta del
mapa, lo que a su vez causará que httpd deje de responder a
solicitudes.</li>
<li>Asegúrese de desactivar el buffering en su programa. En el ejemplo de Python
anterior, esto se hace pasando <code>flush=True</code> a
<code>print()</code>. La E/S con buffer causará que httpd espere la
salida, y por lo tanto se colgará.</li>
<li>Recuerde que solo hay una copia del programa, iniciada al
arrancar el servidor. Todas las solicitudes necesitarán pasar por este único cuello de botella.
Esto puede causar ralentizaciones significativas si muchas solicitudes deben pasar por
este proceso, o si el script en sí es muy lento.</li>
<li>Si el programa de mapeo termina, no se reiniciará automáticamente.
Las búsquedas posteriores fallarán hasta que el servidor sea
reiniciado.</li>
<li>El programa de mapeo siempre se mata y reinicia en cualquier
reinicio del servidor (graceful o de otro tipo), independientemente de si las
directivas de configuración relacionadas han cambiado. Al apagar, se envía
<code>SIGTERM</code> al programa; si no sale dentro de 3 segundos, se
le envía <code>SIGKILL</code>.</li>
</ul>
</note>

</section>


  <section id="dbd">
    <title>dbd o fastdbd: Consulta SQL</title>

    <p>Cuando se usa un MapType de <code>dbd</code> o <code>fastdbd</code>,
    el MapSource es una sentencia SQL SELECT que toma un solo
    argumento y devuelve un solo valor.</p>

    <p><module>mod_dbd</module> necesitará estar configurado para apuntar a
    la base de datos correcta para que esta sentencia se ejecute.</p>

    <p>Hay dos formas de este MapType.
    Usar un MapType de <code>dbd</code> causa que la consulta se
    ejecute con cada solicitud de mapa, mientras que usar <code>fastdbd</code>
    almacena en caché las búsquedas de base de datos internamente. Así, mientras que
    <code>fastdbd</code> es más eficiente, y por lo tanto más rápido, no
    reflejará los cambios en la base de datos hasta que el servidor sea
    reiniciado.</p>

    <p>Si una consulta devuelve más de una fila, se usa una fila aleatoria del
    conjunto de resultados.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
RewriteMap myquery "fastdbd:SELECT destination FROM rewrite WHERE source = %s"
    </highlight>
    </example>

    <note><title>Nota</title>
    <p>El nombre de la consulta se pasa al controlador de base de datos como una etiqueta para
    una sentencia SQL preparada, y por lo tanto necesitará seguir cualquier regla
    (como sensibilidad a mayúsculas/minúsculas) requerida por su base de datos.</p></note>

  </section>
  <section id="summary">
    <title>Resumen</title>

    <p>La directiva <directive module="mod_rewrite">RewriteMap</directive> puede
    aparecer más de una vez. Para cada función de mapeo use una
    directiva <directive module="mod_rewrite">RewriteMap</directive> para declarar
    su archivo de mapa de reescritura.</p>

    <p>Aunque no puede <strong>declarar</strong> un mapa en
    contexto per-directorio (archivos <code>.htaccess</code> o
    bloques <directive module="core" type="section">Directory</directive>) es
    posible <strong>usar</strong> este mapa en contexto per-directorio.</p>

  </section>
</manualpage>
