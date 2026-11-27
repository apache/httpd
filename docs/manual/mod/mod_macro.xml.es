<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933497 -->
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

<modulesynopsis metafile="mod_macro.xml.meta">

<name>mod_macro</name>
<description>Proporciona macros dentro de los archivos de configuración en tiempo de ejecución de apache httpd</description>
<status>Base</status>
<sourcefile>mod_macro.c</sourcefile>
<identifier>macro_module</identifier>
<compatibility>Disponible en httpd 2.4.5 y posteriores</compatibility>

<summary>

    <p>Proporciona macros dentro de los archivos de configuración en tiempo de
    ejecución de Apache httpd, para facilitar el proceso de crear numerosos
    bloques de configuración similares. Cuando el servidor arranca, las
    macros se expanden usando los parámetros proporcionados, y el resultado
    se procesa junto con el resto del archivo de configuración.</p>

</summary>

<section id="usage"><title>Uso</title>

<p>Las macros se definen usando bloques <directive module="mod_macro"
type="section">Macro</directive>, que contienen la parte de su
configuración que necesita repetirse, junto con variables para las partes
que necesitarán sustituirse.</p>

<p>Por ejemplo, podría usar una macro para definir un bloque <directive module="core"
type="section">VirtualHost</directive>, con el fin de definir
varios hosts virtuales similares:</p>

<highlight language="config">
&lt;Macro VHost $name $domain&gt;
&lt;VirtualHost *:80&gt;
    ServerName $domain
    ServerAlias www.$domain

    DocumentRoot "/var/www/vhosts/$name"
    ErrorLog "/var/log/httpd/$name.error_log"
    CustomLog "/var/log/httpd/$name.access_log" combined
&lt;/VirtualHost&gt;
&lt;/Macro&gt;
</highlight>

<p>Los nombres de macro no distinguen mayúsculas y minúsculas, como las
directivas de configuración de httpd. Sin embargo, los nombres de variable
sí distinguen mayúsculas y minúsculas.</p>

<p>Después invocaría esta macro varias veces para crear hosts
virtuales:</p>

<highlight language="config">
Use VHost example example.com
Use VHost myhost hostname.org
Use VHost apache apache.org

UndefMacro VHost
</highlight>

<p>En el arranque del servidor, cada una de estas invocaciones de <directive module="mod_macro">Use</directive>
se expandiría en un host virtual completo, tal y
como lo describe la definición de <directive module="mod_macro" type="section">Macro</directive>.</p>

<p>La directiva <directive module="mod_macro">UndefMacro</directive> se
usa para que macros posteriores que usen los mismos nombres de variable no
den lugar a definiciones en conflicto.</p>

<p>Más abajo, en la sección de Ejemplos, puede verse una versión más
elaborada de este ejemplo.</p>

</section>

<section id="tips"><title>Consejos</title>

<p>Los nombres de parámetro deberían empezar con un símbolo como <code>$</code>,
<code>%</code>, o <code>@</code>, para que sean claramente
identificables, y también para ayudar a evitar interacciones con
otras directivas, como la directiva <directive
module="core">Define</directive> del core. No hacerlo así
provocará una advertencia. No obstante, se recomienda tener un buen
conocimiento de toda la configuración de su servidor para evitar reutilizar
las mismas variables en ámbitos distintos, lo cual puede causar confusión.</p>

<p>Los parámetros prefijados con <code>$</code> o <code>%</code> no se
escapan. Los parámetros prefijados con <code>@</code> se escapan entre
comillas.</p>

<p>Evite usar un parámetro que contenga otro parámetro como prefijo
(por ejemplo, <code>$win</code> y <code>$winter</code>), ya que esto puede
causar confusión en el momento de evaluar la expresión. En caso de tal
confusión, se usa el nombre de parámetro más largo posible.</p>

<p>Si quiere usar un valor dentro de otra cadena, es útil rodear el
parámetro con paréntesis, para evitar confusión. Debería usarse la
sintaxis <code>$(...)</code> en lugar de
<code>${...}</code>, ya que esta última entra en conflicto con la
sintaxis de variable de <directive module="core">Define</directive>:</p>

<highlight language="config">
&lt;Macro DocRoot $(docroot)&gt;
    DocumentRoot "/var/www/$(docroot)/htdocs"
&lt;/Macro&gt;
</highlight>

</section>

<section id="examples">
<title>Ejemplos</title>

<section>
<title>Definición de host virtual</title>

<p>Un uso habitual de <module>mod_macro</module> es la creación de
hosts virtuales generados dinámicamente.</p>

<highlight language="config">
## Definir una macro VHost para configuraciones repetitivas

&lt;Macro VHost $host $port $dir&gt;
  Listen $port
  &lt;VirtualHost *:$port&gt;

    ServerName $host
    DocumentRoot "$dir"

    # Raíz de documentos pública
    &lt;Directory "$dir"&gt;
        Require all granted
    &lt;/Directory&gt;

    # limitar el acceso al subdirectorio de intranet.
    &lt;Directory "$dir/intranet"&gt;
      Require ip 10.0.0.0/8
    &lt;/Directory&gt;
  &lt;/VirtualHost&gt;
&lt;/Macro&gt;

## Uso de VHost con diferentes argumentos.

Use VHost www.apache.org 80 /vhosts/apache/htdocs
Use VHost example.org 8080 /vhosts/example/htdocs
Use VHost www.example.fr 1234 /vhosts/example.fr/htdocs
</highlight>
</section> <!-- Vhosts -->

<section>
<title>Eliminación de una definición de macro</title>

<p>Se recomienda que elimine la definición de una macro una vez que la haya
usado. Esto evita confusiones en un archivo de configuración complejo
donde puede haber conflictos en los nombres de variable.</p>

<highlight language="config">
&lt;Macro DirGroup $dir $group&gt;
  &lt;Directory "$dir"&gt;
    Require group $group
  &lt;/Directory&gt;
&lt;/Macro&gt;

Use DirGroup /www/apache/private private
Use DirGroup /www/apache/server  admin

UndefMacro DirGroup
</highlight>

</section> <!-- UndefMacro -->

</section> <!-- Example -->

<!-- Macro -->
<directivesynopsis type="section">
<name>Macro</name>
<description>Define una macro de archivo de configuración</description>
<syntax>
&lt;Macro <var>name</var> [<var>par1</var> .. <var>parN</var>]&gt;
... &lt;/Macro&gt;</syntax>
<contextlist>
<context>server config</context>
<context>virtual host</context>
<context>directory</context>
</contextlist>

<usage>
    <p>La directiva <directive type="section">Macro</directive> controla la
    definición de una macro dentro de los archivos de configuración en
    tiempo de ejecución del servidor.
    El primer argumento es el nombre de la macro.
    Los demás argumentos son parámetros de la macro. Es buena práctica
    prefijar los nombres de parámetro con alguno de '<code>$%@</code>', y no
    prefijar los nombres de macro con tales caracteres.
    </p>

    <highlight language="config">
&lt;Macro LocalAccessPolicy&gt;
    Require ip 10.2.16.0/24
&lt;/Macro&gt;

&lt;Macro RestrictedAccessPolicy $ipnumbers&gt;
    Require ip $ipnumbers
&lt;/Macro&gt;
    </highlight>
</usage>
</directivesynopsis>

<!-- Use -->
<directivesynopsis>
<name>Use</name>
<description>Usa una macro</description>
<syntax>Use <var>name</var> [<var>value1</var> ... <var>valueN</var>]
</syntax>
<contextlist>
<context>server config</context>
<context>virtual host</context>
<context>directory</context>
</contextlist>

<usage>
    <p>La directiva <directive>Use</directive> controla el uso de una macro.
    La macro especificada se expande. Debe recibir el mismo número de
    argumentos que en la definición de la macro. Los valores proporcionados
    se asocian a sus parámetros iniciales correspondientes y se sustituyen
    antes de procesarse.</p>

    <highlight language="config">
Use LocalAccessPolicy
...
Use RestrictedAccessPolicy "192.54.172.0/24 192.54.148.0/24"
    </highlight>

    <p>es equivalente, con las macros definidas más arriba, a:</p>

    <highlight language="config">
Require ip 10.2.16.0/24
...
Require ip 192.54.172.0/24 192.54.148.0/24
    </highlight>
</usage>

</directivesynopsis>

<!-- UndefMacro -->
<directivesynopsis>
<name>UndefMacro</name>
<description>Elimina la definición de una macro</description>

<syntax>UndefMacro <var>name</var></syntax>
<contextlist>
<context>server config</context>
<context>virtual host</context>
<context>directory</context>
</contextlist>

<usage>
    <p>La directiva <directive>UndefMacro</directive> elimina la definición
    de una macro que se había definido anteriormente.</p>

    <highlight language="config">
UndefMacro LocalAccessPolicy
UndefMacro RestrictedAccessPolicy
    </highlight>
</usage>
</directivesynopsis>
</modulesynopsis>
