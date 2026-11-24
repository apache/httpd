<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933506 -->
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

<modulesynopsis metafile="mod_data.xml.meta">

<name>mod_data</name>
<description>Convierte el cuerpo de la respuesta en una URL de datos conforme a RFC2397</description>
<status>Extension</status>
<sourcefile>mod_data.c</sourcefile>
<identifier>data_module</identifier>
<compatibility>Disponible en Apache 2.3 y posteriores</compatibility>

<summary>
    <p>Este módulo proporciona la capacidad de convertir una respuesta en
    una URL de datos conforme a <rfc>2397</rfc>.
    </p>

    <p>Las URLs de datos pueden incrustarse en línea dentro de páginas web usando algo
    como el módulo <module>mod_include</module>, para eliminar la necesidad de
    que los clientes hagan conexiones separadas para obtener lo que podrían ser
    muchas imágenes pequeñas. Las URLs de datos también pueden incluirse en páginas generadas
    por lenguajes de scripting como PHP.</p>

    <example><title>Un ejemplo de URL de datos</title>
        data:image/gif;base64,R0lGODdhMAAwAPAAAAAAAP///ywAAAAAMAAw<br />
        AAAC8IyPqcvt3wCcDkiLc7C0qwyGHhSWpjQu5yqmCYsapyuvUUlvONmOZtfzgFz<br />
        ByTB10QgxOR0TqBQejhRNzOfkVJ+5YiUqrXF5Y5lKh/DeuNcP5yLWGsEbtLiOSp<br />
        a/TPg7JpJHxyendzWTBfX0cxOnKPjgBzi4diinWGdkF8kjdfnycQZXZeYGejmJl<br />
        ZeGl9i2icVqaNVailT6F5iJ90m6mvuTS4OK05M0vDk0Q4XUtwvKOzrcd3iq9uis<br />
        F81M1OIcR7lEewwcLp7tuNNkM3uNna3F2JQFo97Vriy/Xl4/f1cf5VWzXyym7PH<br />
        hhx4dbgYKAAA7<br />
    </example>

    <p>El filtro no toma parámetros, y puede añadirse a la pila de filtros
    usando la directiva <directive module="core">SetOutputFilter</directive>,
    o cualquiera de las directivas admitidas por el módulo
    <module>mod_filter</module>.</p>

    <example><title>Configurar el filtro</title>
    <highlight language="config">
&lt;Location "/data/images"&gt;
    SetOutputFilter DATA
&lt;/Location&gt;
        </highlight>
    </example>

</summary>
<seealso><a href="../filter.html">Filtros</a></seealso>

</modulesynopsis>
