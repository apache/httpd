<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1893733 -->
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

<modulesynopsis metafile="mod_speling.xml.meta">

<name>mod_speling</name>
<description>Intenta corregir URLs mal escritas ignorando
mayúsculas y minúsculas, o intentando corregir diversos pequeños
errores ortográficos.</description>
<status>Extension</status>
<sourcefile>mod_speling.c</sourcefile>
<identifier>speling_module</identifier>



<summary>

    <p>A veces, las peticiones de documentos no pueden ser atendidas por el núcleo
    del servidor apache porque la petición contenía una falta de ortografía o un
    error de mayúsculas/minúsculas. Este módulo aborda este problema intentando
    encontrar un documento que coincida, incluso después de que todos los demás
    módulos lo hayan dado por imposible. Realiza su trabajo comparando cada nombre
    de documento del directorio solicitado con el nombre de documento
    pedido <strong>sin distinguir mayúsculas/minúsculas</strong>, y permitiendo
    <strong>hasta un error ortográfico</strong> (inserción, omisión o
    transposición de un carácter, o un carácter incorrecto). Se construye una
    lista con todos los nombres de documentos que coinciden mediante esta
    estrategia. Este módulo también puede corregir una <strong>extensión
    errónea</strong>.</p>

    <p>Si, tras examinar el directorio,</p>

    <ul>
      <li>no se encuentra ningún documento coincidente, Apache seguirá
      actuando como de costumbre y devolverá un error (<code>404 - documento no encontrado</code>).</li>

      <li>solo se encuentra un documento que "casi" coincide con la
      petición, se devolverá en forma de respuesta de redirección
      (<code>301 - Moved Permanently</code>).</li>

      <li>se encuentra más de un documento con una coincidencia cercana,
      la lista de coincidencias se devuelve al cliente, que puede
      seleccionar el candidato correcto (<code>300 - Multiple
      Choices</code>).</li>
    </ul>

</summary>


<directivesynopsis>
<name>CheckSpelling</name>
<description>Activa el módulo de
corrección ortográfica</description>
<syntax>CheckSpelling on|off</syntax>
<default>CheckSpelling Off</default>
<contextlist>
<context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>Options</override>

<usage>
    <p>Esta directiva activa o desactiva el módulo de corrección ortográfica. Cuando
    está activado, tenga en cuenta que</p>

    <ul>
      <li>el examen del directorio necesario para la corrección
      ortográfica repercutirá en el rendimiento del servidor
      cuando haya que realizar muchas correcciones ortográficas al
      mismo tiempo.</li>

      <li>los árboles de documentos no deberían contener archivos sensibles
      que pudieran coincidir accidentalmente con una "corrección"
      ortográfica.</li>

      <li>el módulo no es capaz de corregir nombres de usuario mal escritos (como
      en <code>http://my.host/~apahce/</code>), solo nombres de archivos o
      de directorios.</li>

      <li>las correcciones ortográficas se aplican estrictamente a archivos existentes, por lo que
      una petición a <code>&lt;Location /status&gt;</code> podría
      tratarse incorrectamente como el archivo negociado
      "<code>/stats.html</code>".</li>
    </ul>

    <!-- XXX: is that really true?! -nd -->
    <p><module>mod_speling</module> no debería activarse en directorios con <a href="mod_dav.html">DAV</a>
    activado, porque intentará "corregir ortográficamente" los nombres de los recursos
    recién creados comparándolos con nombres de archivo ya existentes; por ejemplo, al intentar subir
    un nuevo documento <code>doc43.html</code> podría redirigir a un
    documento existente <code>doc34.html</code>, lo cual no es lo que se pretendía.
    </p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CheckCaseOnly</name>
<description>Limita la acción del módulo speling a correcciones de mayúsculas/minúsculas</description>
<syntax>CheckCaseOnly on|off</syntax>
<default>CheckCaseOnly Off</default>
<contextlist>
<context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>Options</override>

<usage>
    <p>Cuando se establece, esta directiva limita la acción de la corrección ortográfica
    a cambios de mayúsculas/minúsculas. No se realizan otras correcciones potenciales,
    excepto cuando también se establece <directive module="mod_speling">CheckBasenameMatch</directive>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>CheckBasenameMatch</name>
<description>Hace coincidir también archivos con distinta extensión de nombre de archivo.</description>
<syntax>CheckBasenameMatch on|off</syntax>
<default>CheckBasenameMatch On</default>
<contextlist>
<context>server config</context>
<context>virtual host</context>
<context>directory</context>
<context>.htaccess</context>
</contextlist>
<override>Options</override>
<compatibility>Disponible en httpd 2.5.0 y posteriores</compatibility>

<usage>
    <p>Cuando se establece, esta directiva extiende la acción de la corrección ortográfica
    a la extensión del nombre de archivo. Por ejemplo, un archivo <code>foo.gif</code>
    coincidirá con una petición de <code>foo</code> o <code>foo.jpg</code>. Esto puede ser
    especialmente útil junto con
    <a href="../content-negotiation.html">MultiViews</a>.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
