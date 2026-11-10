<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933179 -->
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

<modulesynopsis metafile="mod_substitute.xml.meta">

<name>mod_substitute</name>
<description>Realiza operaciones de búsqueda y reemplazo en los cuerpos de las respuestas</description>
<status>Extension</status>
<sourcefile>mod_substitute.c</sourcefile>
<identifier>substitute_module</identifier>

<summary>
    <p><module>mod_substitute</module> proporciona un mecanismo para realizar
    sustituciones, tanto con expresiones regulares como con cadenas fijas, en
    los cuerpos de las respuestas.</p>
</summary>

<directivesynopsis>
<name>Substitute</name>
<description>Patrón para filtrar el contenido de la respuesta</description>
<syntax>Substitute <var>s/pattern/substitution/[infq]</var></syntax>
<contextlist><context>directory</context>
<context>.htaccess</context></contextlist>
<override>FileInfo</override>
<compatibility>Los valores de sustitución "expr=" se añadieron en la versión 2.5.1</compatibility>

<usage>
    <p>La directiva <directive>Substitute</directive> especifica un
    patrón de búsqueda y reemplazo que se aplica al cuerpo de la respuesta.</p>

    <p>El significado del patrón se puede modificar usando cualquier
    combinación de estos indicadores:</p>

    <dl>
        <dt><code>i</code></dt>
        <dd>Realiza una coincidencia que no distingue mayúsculas y minúsculas.</dd>
        <dt><code>n</code></dt>
        <dd>Por defecto, el patrón se trata como una expresión regular.
        Usar el indicador <code>n</code> fuerza a que el patrón se trate
        como una cadena fija.</dd>
        <dt><code>f</code></dt>
        <dd>El indicador <code>f</code> hace que <code>mod_substitute</code> aplane el
        resultado de una sustitución, permitiendo que sustituciones posteriores
        tengan lugar en el límite de esta. Este es el valor por defecto.</dd>
        <dt><code>q</code></dt>
        <dd>El indicador <code>q</code> hace que <code>mod_substitute</code> no
        aplane los buckets después de cada sustitución. Esto puede
        dar lugar a una respuesta mucho más rápida y a una reducción en el uso
        de memoria, pero solo debe usarse si no existe la posibilidad
        de que el resultado de una sustitución llegue a coincidir con un patrón
        o expresión regular de una posterior.</dd>
    </dl>

    <p>La <var>substitution</var> puede contener texto literal y
    referencias a grupos capturados de la expresión regular. Si la sustitución comienza con el texto
    <code>expr=</code>, se interpreta como una <a href="../expr.html">
    expresión</a> que permite acceder a variables de entorno y
    valores de cabecera. </p>

    <example><title>Ejemplo</title>
    <highlight language="config">
&lt;Location "/"&gt;
    AddOutputFilterByType SUBSTITUTE text/html
    Substitute "s/foo/bar/ni"
&lt;/Location&gt;
        </highlight>
    </example>

    <p>El carácter que se usa para separar (o "delimitar") las
    distintas partes de la cadena de sustitución se denomina
    "delimitador", y lo más habitual es usar una barra para este
    propósito.</p>

    <p>Si el patrón o la sustitución contienen un carácter de barra,
    se puede usar un delimitador alternativo para que la
    directiva sea más legible:</p>

    <example><title>Ejemplo de uso de un delimitador alternativo</title>
    <highlight language="config">
&lt;Location "/"&gt;
    AddOutputFilterByType SUBSTITUTE text/html
    Substitute "s|&lt;BR */?&gt;|&lt;br /&gt;|i"
&lt;/Location&gt;
        </highlight>
    </example>

    <p>Se pueden usar referencias a grupos capturados tanto en la comparación como en la sustitución,
    cuando se usan expresiones regulares, como se ilustra en el siguiente ejemplo: </p>
    <example><title>Ejemplo de uso de referencias a grupos capturados</title>
    <highlight language="config">
&lt;Location "/"&gt;
    AddOutputFilterByType SUBSTITUTE text/html
    # "foo=k,bar=k" -> "foo/bar=k"
    Substitute "s|foo=(\w+),bar=\1|foo/bar=$1|"
&lt;/Location&gt;
    </highlight>
    </example>

    <p> Cuando se usa una <a href="../expr.html">expresión</a> para la
    <var>substitution</var>, las referencias a grupos capturados de la expresión regular deben
    escaparse con una barra invertida ('\') como se ilustra en el siguiente ejemplo:</p>
    <example><title>Ejemplo de expresión</title>
    <highlight language="config">
&lt;Location "/"&gt;
    AddOutputFilterByType SUBSTITUTE text/html
    Substitute "s/example.com/expr=%{HTTP:HOST}/i"
    Substitute "s/Hello, (\S+)/expr=Hello from %{REQUEST_URI}, \$1/i"
&lt;/Location&gt;
        </highlight>
    </example>

    <note type="warning"><title>Expresiones y caché</title>
    <p>Debe tenerse precaución al realizar sustituciones que referencien
    cabeceras de petición HTTP. Debido a que este módulo opera después de que las cabeceras de respuesta
    se hayan enviado, el <a href="../expr.html">analizador de expresiones</a> no puede añadir
    las cabeceras de petición HTTP referenciadas a la cabecera Vary de salida. </p>
    </note>

    <p>Un escenario de uso habitual de <code>mod_substitute</code> es la
    situación en la que un servidor front-end reenvía peticiones a un servidor
    back-end que devuelve HTML con URLs incrustadas codificadas de forma fija que hacen referencia
    al servidor back-end. Estas URLs no funcionan para el usuario final,
    ya que el servidor back-end no es accesible.</p>

    <p>En este caso, <code>mod_substitute</code> se puede usar para reescribir
    esas URLs de forma que funcionen desde el front-end:</p>

    <example><title>Reescritura de URLs incrustadas en contenido proxificado</title>
    <highlight language="config">
ProxyPass        "/blog/" "http://internal.blog.example.com/"
ProxyPassReverse "/blog/" "http://internal.blog.example.com/"

Substitute "s|http://internal.blog.example.com/|http://www.example.com/blog/|i"
    </highlight>
    </example>

    <p><directive module="mod_proxy">ProxyPassReverse</directive>
    modifica cualquier cabecera <code>Location</code> (de redirección) enviada
    por el servidor back-end, y, en este ejemplo,
    <directive>Substitute</directive> se encarga del resto del problema
    corrigiendo también la respuesta HTML.</p>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SubstituteMaxLineLength</name>
<description>Establece el tamaño máximo de línea</description>
<syntax>SubstituteMaxLineLength <var>bytes</var>(b|B|k|K|m|M|g|G)</syntax>
<default>SubstituteMaxLineLength 1m</default>
<contextlist><context>directory</context>
<context>.htaccess</context></contextlist>
<override>FileInfo</override>
<compatibility>Disponible en httpd 2.4.11 y posteriores</compatibility>

<usage>
    <p>El tamaño máximo de línea gestionado por <module>mod_substitute</module>
    está limitado para restringir el uso de memoria. El límite se puede configurar
    usando <directive>SubstituteMaxLineLength</directive>.
    El valor se puede indicar como un número de bytes y se puede sufijar
    con una única letra <code>b</code>, <code>B</code>, <code>k</code>,
    <code>K</code>, <code>m</code>, <code>M</code>, <code>g</code>,
    <code>G</code> para indicar el tamaño en bytes, kilobytes, megabytes
    o gigabytes respectivamente.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
&lt;Location "/"&gt;
    AddOutputFilterByType SUBSTITUTE text/html
    SubstituteMaxLineLength 10m
    Substitute "s/foo/bar/ni"
&lt;/Location&gt;
        </highlight>
    </example>

</usage>
</directivesynopsis>

<directivesynopsis>
<name>SubstituteInheritBefore</name>
<description>Cambia el orden de fusión de los patrones heredados</description>
<syntax>SubstituteInheritBefore on|off</syntax>
<default>SubstituteInheritBefore on</default>
<contextlist><context>directory</context>
<context>.htaccess</context></contextlist>
<override>FileInfo</override>
<compatibility>Disponible en httpd 2.4.17 y posteriores</compatibility>

<usage>
    <p>Indica si se deben aplicar primero los patrones <directive module="mod_substitute">Substitute</directive>
    heredados (<code>on</code>), o después de los del contexto
    actual (<code>off</code>).
    Esta última opción era el valor por defecto en las versiones 2.4 y anteriores, pero cambió
    a partir de la versión 2.5, por lo que establecer <directive>SubstituteInheritBefore</directive>
    en <code>off</code> permite restaurar el comportamiento heredado.
    <directive>SubstituteInheritBefore</directive> es a su vez heredable,
    por lo que los contextos que lo heredan (los que no especifican su propio
    valor de <directive>SubstituteInheritBefore</directive>) aplicarán el
    orden de fusión definido más cercano.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
