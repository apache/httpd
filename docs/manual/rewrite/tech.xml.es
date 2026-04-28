<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933438 -->

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

<manualpage metafile="tech.xml.meta">
<parentdocument href="./">Rewrite</parentdocument>

  <title>Detalles Técnicos de Apache mod_rewrite</title>

<summary>
<p>Este documento discute algunos de los detalles técnicos de <module>mod_rewrite</module>
y la coincidencia de URLs.</p>
</summary>
<seealso><a href="../mod/mod_rewrite.html">Documentación del módulo</a></seealso>
<seealso><a href="intro.html">Introducción a mod_rewrite</a></seealso>
<seealso><a href="remapping.html">Redirección y remapeo</a></seealso>
<seealso><a href="access.html">Control de acceso</a></seealso>
<seealso><a href="vhosts.html">Hosts virtuales</a></seealso>
<seealso><a href="proxy.html">Proxy</a></seealso>
<seealso><a href="rewritemap.html">Uso de RewriteMap</a></seealso>
<seealso><a href="advanced.html">Técnicas avanzadas</a></seealso>
<seealso><a href="avoid.html">Cuándo no usar mod_rewrite</a></seealso>

<section id="InternalAPI"><title>Fases de la API</title>

    <p>Apache HTTP Server maneja las solicitudes en varias fases. En
    cada una de estas fases, uno o más módulos pueden ser llamados para
    manejar esa porción del ciclo de vida de la solicitud. Las fases incluyen cosas
    como traducción de URL a nombre de archivo, autenticación, autorización,
    contenido, y registro. (Esta no es una lista exhaustiva.)</p>

    <p><module>mod_rewrite</module> actúa en dos de estas fases (o "hooks", como se les
    suele llamar) para influir en cómo las URLs pueden ser reescritas.</p>

    <p>Primero, usa el hook de traducción de URL a nombre de archivo, que ocurre
    después de que la solicitud HTTP ha sido leída, pero antes de que cualquier autorización
    comience. Segundo, usa el hook de Fixup, que es después de las
    fases de autorización, y después de que los archivos de configuración per-directorio
    (archivos <code>.htaccess</code>) han sido leídos, pero antes de que el
    manejador de contenido sea llamado.</p>

    <p>Después de que una solicitud llega y se ha determinado un servidor o
    host virtual correspondiente, el motor de reescritura comienza a
    procesar cualquier directiva de <module>mod_rewrite</module> que aparezca en la
    configuración per-servidor. (es decir, en el archivo de configuración principal del servidor
    y secciones <directive module="core" type="section">Virtualhost</directive>.)
    Esto sucede en la fase de traducción de URL a nombre de archivo.</p>

    <p>Unos pasos más tarde, una vez que se han encontrado los directorios de datos finales,
    se aplican las directivas de configuración per-directorio (archivos <code>.htaccess</code>
    y bloques <directive module="core"
    type="section">Directory</directive>). Esto
    sucede en la fase de Fixup.</p>

    <p>En cada uno de estos casos, <module>mod_rewrite</module> reescribe el
    <code>REQUEST_URI</code> ya sea a una nueva URL, o a un nombre de archivo.</p>

    <p>En contexto per-directorio (es decir, dentro de archivos <code>.htaccess</code>
    y bloques <code>Directory</code>), estas reglas se están aplicando
    después de que una URL ya ha sido traducida a un nombre de archivo. Debido a
    esto, la ruta URL contra la que <module>mod_rewrite</module> inicialmente compara las directivas
    <directive module="mod_rewrite">RewriteRule</directive>
    es la ruta completa del sistema de archivos al nombre de archivo traducido con la ruta del
    directorio actual (incluyendo una barra final) eliminada del frente.</p>

    <p>Para ilustrar: Si las reglas están en /var/www/foo/.htaccess y se está procesando una solicitud
    para /foo/bar/baz, una expresión como ^bar/baz$ coincidiría.</p>

    <p>Si se hace una sustitución en contexto per-directorio, se emite una nueva
    sub-solicitud interna con la nueva URL, que reinicia el procesamiento de las
    fases de la solicitud. Si la sustitución es una ruta relativa, la directiva <directive
    module="mod_rewrite">RewriteBase</directive>
    determina el prefijo de ruta URL que se antepone a la sustitución.
    En contexto per-directorio, se debe tener cuidado de
    crear reglas que eventualmente (en alguna "ronda" futura de procesamiento de reescritura
    per-directorio) no realicen una sustitución para evitar bucles.
    (Vea <a href="https://cwiki.apache.org/confluence/display/httpd/RewriteLooping">RewriteLooping</a>
    para más discusión de este problema.)</p>

    <p>Debido a esta manipulación adicional de la URL en contexto per-directorio,
    necesitará tener cuidado de crear sus reglas de reescritura
    de manera diferente en ese contexto. En particular, recuerde que la
    ruta de directorio principal se eliminará de la URL que sus
    reglas de reescritura verán. Considere los ejemplos siguientes para más
    clarificación.</p>

    <table border="1">

        <tr>
            <th>Ubicación de la regla</th>
            <th>Regla</th>
        </tr>

        <tr>
            <td>Sección VirtualHost</td>
            <td>RewriteRule "^/images/(.+)\.jpg" "/images/$1.gif"</td>
        </tr>

        <tr>
            <td>Archivo .htaccess en la raíz del documento</td>
            <td>RewriteRule "^images/(.+)\.jpg" "images/$1.gif"</td>
        </tr>

        <tr>
            <td>Archivo .htaccess en el directorio images</td>
            <td>RewriteRule "^(.+)\.jpg" "$1.gif"</td>
        </tr>

    </table>

    <p>Para aún más información sobre cómo <module>mod_rewrite</module> manipula URLs en
    diferentes contextos, debería consultar las <a
    href="../mod/mod_rewrite.html#logging">entradas del log</a> realizadas durante
    la reescritura.</p>

</section>

<section id="InternalRuleset"><title>Procesamiento del Conjunto de Reglas</title>

      <p>Ahora cuando <module>mod_rewrite</module> se activa en estas dos fases de la API, lee
      los conjuntos de reglas configurados desde su estructura de
      configuración (que a su vez fue creada al inicio para
      contexto per-servidor o durante el recorrido de directorios del
      núcleo de Apache para contexto per-directorio). Entonces el motor de reescritura
      de URLs se inicia con el conjunto de reglas contenido (una o más
      reglas junto con sus condiciones). La operación del
      motor de reescritura de URLs es exactamente la misma para ambos
      contextos de configuración. Solo el procesamiento del resultado final es
      diferente.</p>

      <p>El orden de las reglas en el conjunto de reglas es importante porque el
      motor de reescritura las procesa en un orden especial (y no muy
      obvio). La regla es esta: El motor de reescritura recorre
      el conjunto de reglas regla por regla (directivas
      <directive module="mod_rewrite">RewriteRule</directive>) y
      cuando una regla particular coincide, opcionalmente recorre
      las condiciones correspondientes existentes (directivas <code>RewriteCond</code>).
      Por razones históricas las condiciones se dan
      primero, y por lo tanto el flujo de control es un poco
      enrevesado. Vea la Figura 1 para más detalles.</p>
<p class="figure">
      <img src="../images/rewrite_process_uri.png"
          alt="Flujo de coincidencia de RewriteRule y RewriteCond" /><br />
      <dfn>Figura 1:</dfn>El flujo de control a través del conjunto de reglas de reescritura
</p>
      <p>Primero la URL se compara contra el
      <em>Pattern</em> de cada regla. Si falla, <module>mod_rewrite</module>
      inmediatamente deja de procesar esta regla, y continúa con la
      siguiente regla. Si el <em>Pattern</em> coincide, <module>mod_rewrite</module> busca
      las condiciones de regla correspondientes (directivas RewriteCond,
      que aparecen inmediatamente encima de la RewriteRule en la configuración).
      Si no hay ninguna, sustituye la URL con un nuevo valor, que se
      construye a partir de la cadena <em>Substitution</em>, y continúa
      con su bucle de reglas. Pero si existen condiciones, inicia un
      bucle interno para procesarlas en el orden en que están
      listadas. Para las condiciones, la lógica es diferente: no comparamos
      un patrón contra la URL actual. En su lugar, primero creamos una
      cadena <em>TestString</em> expandiendo variables,
      referencias inversas, búsquedas en mapas, <em>etc.</em> y luego intentamos
      comparar <em>CondPattern</em> contra ella. Si el patrón
      no coincide, el conjunto completo de condiciones y la
      regla correspondiente fallan. Si el patrón coincide, entonces se
      procesa la siguiente condición hasta que no haya más condiciones
      disponibles. Si todas las condiciones coinciden, el procesamiento continúa
      con la sustitución de la URL con
      <em>Substitution</em>.</p>

</section>


</manualpage>
