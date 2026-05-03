<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933071:1933718 (outdated) -->

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

<manualpage metafile="vhosts.xml.meta">
  <parentdocument href="./">Rewrite</parentdocument>

<title>Hosts virtuales masivos dinámicos con mod_rewrite</title>

<summary>

<p>Este documento complementa la <module>mod_rewrite</module>
<a href="../mod/mod_rewrite.html">documentación de referencia</a>. Describe
cómo puede usar <module>mod_rewrite</module> para crear hosts virtuales
configurados dinámicamente.</p>

<note type="warning"><module>mod_rewrite</module> generalmente no es la mejor forma de configurar
hosts virtuales. Debería considerar primero las <a
href="../vhosts/mass.html">alternativas</a> antes de recurrir a
mod_rewrite. Vea también el documento "<a href="avoid.html#vhosts">cómo evitar
mod_rewrite</a>".</note>

</summary>
<seealso><a href="../mod/mod_rewrite.html">Documentación del módulo</a></seealso>
<seealso><a href="intro.html">Introducción a mod_rewrite</a></seealso>
<seealso><a href="remapping.html">Redirección y remapeo</a></seealso>
<seealso><a href="access.html">Control de acceso</a></seealso>
<!--<seealso><a href="vhosts.html">Hosts virtuales</a></seealso>-->
<seealso><a href="proxy.html">Proxy</a></seealso>
<seealso><a href="rewritemap.html">RewriteMap</a></seealso>
<seealso><a href="advanced.html">Técnicas avanzadas</a></seealso>
<seealso><a href="avoid.html">Cuándo no usar mod_rewrite</a></seealso>

<section id="per-hostname">

  <title>Hosts Virtuales para Nombres de Host Arbitrarios</title>

  <dl>
    <dt>Descripción:</dt>

    <dd>
    <p>Queremos crear automáticamente un host virtual para cada nombre de host
    que resuelva en nuestro dominio, sin tener que crear
    nuevas secciones VirtualHost.</p>

    <p>En esta receta, asumimos que usaremos el nombre de host
    <code><strong>SITIO</strong>.example.com</code> para cada
    usuario, y serviremos su contenido desde
    <code>/home/<strong>SITIO</strong>/www</code>. Sin embargo, queremos
    que <code>www.example.com</code> sea omitido de este mapeo.</p>
    </dd>

    <dt>Solución:</dt>

    <dd>

<highlight language="config">
RewriteEngine on

RewriteMap    lowercase int:tolower

RewriteCond   %{HTTP_HOST} !^www\.
RewriteCond   ${lowercase:%{<strong>HTTP_HOST</strong>}}   ^<strong>([^.]+)</strong>\.example\.com$
RewriteRule   ^(.*)    /home/<strong>%1</strong>/www$1
</highlight></dd>

<dt>Discusión</dt>
    <dd>

    <note type="warning">Necesitará encargarse de la resolución DNS
    - Apache no maneja la resolución de nombres. Necesitará crear registros CNAME
    para cada nombre de host, o un registro DNS comodín. La creación de registros DNS
    está fuera del alcance de este documento.</note>

<p>La directiva interna <code>tolower</code> de RewriteMap se usa para
asegurar que los nombres de host que se usen estén todos en minúsculas, de modo que no haya
ambigüedad en la estructura de directorios que debe crearse.</p>

<p>Los paréntesis usados en una <directive
module="mod_rewrite">RewriteCond</directive> se capturan en las
referencias inversas <code>%1</code>, <code>%2</code>, etc, mientras que los paréntesis
usados en <directive module="mod_rewrite">RewriteRule</directive> se
capturan en las referencias inversas <code>$1</code>, <code>$2</code>,
etc.</p>

<p>La primera <code>RewriteCond</code> verifica si el nombre de host
comienza con <code>www.</code>, y si es así, la reescritura se
omite.</p>

<p>
Como con muchas técnicas discutidas en este documento, <module>mod_rewrite</module> realmente
no es la mejor forma de lograr esta tarea. Debería, en su lugar,
considerar usar <module>mod_vhost_alias</module>, ya que manejará
mucho más elegantemente cualquier cosa más allá de servir archivos estáticos, como cualquier
contenido dinámico, y resolución de Alias.
</p>
    </dd>
  </dl>

</section>

<section id="simple.rewrite"><title>Hosts Virtuales
    Dinámicos Usando <module>mod_rewrite</module></title>

    <p>Este extracto de <code>httpd.conf</code> hace lo mismo
    que <a href="#per-hostname">el primer ejemplo</a>. La primera
    mitad es muy similar a la parte correspondiente anterior, excepto por
    algunos cambios, necesarios para compatibilidad hacia atrás y para hacer que la
    parte de <module>mod_rewrite</module> funcione correctamente; la segunda mitad
    configura <module>mod_rewrite</module> para hacer el trabajo real.</p>

    <p>Debido a que <module>mod_rewrite</module> se ejecuta antes que otros módulos de traducción
    de URI (por ejemplo, <module>mod_alias</module>), se le debe decir a <module>mod_rewrite</module>
    que ignore explícitamente cualquier URL que hubiera sido manejada
    por esos módulos. Y, debido a que estas reglas de lo contrario evitarían
    cualquier directiva <code>ScriptAlias</code>, debemos hacer que
    <module>mod_rewrite</module> ejecute explícitamente esos mapeos.</p>

<highlight language="config">
# get the server name from the Host: header
UseCanonicalName Off

# splittable logs
LogFormat "%{Host}i %h %l %u %t \"%r\" %s %b" vcommon
CustomLog "logs/access_log" vcommon

&lt;Directory "/www/hosts"&gt;
    # ExecCGI is needed here because we can't force
    # CGI execution in the way that ScriptAlias does
    Options FollowSymLinks ExecCGI
&lt;/Directory&gt;

RewriteEngine On

# a ServerName derived from a Host: header may be any case at all
RewriteMap  lowercase  "int:tolower"

## deal with normal documents first:
# allow Alias /icons/ to work - repeat for other aliases
RewriteCond  "%{REQUEST_URI}"  "!^/icons/"
# allow CGIs to work
RewriteCond  "%{REQUEST_URI}"  "!^/cgi-bin/"
# do the magic
RewriteRule  "^/(.*)$"         "/www/hosts/${lowercase:%{SERVER_NAME}}/docs/$1"

## and now deal with CGIs - we have to force a handler
RewriteCond  "%{REQUEST_URI}"  "^/cgi-bin/"
RewriteRule  "^/(.*)$"         "/www/hosts/${lowercase:%{SERVER_NAME}}/cgi-bin/$1"  [H=cgi-script]
</highlight>

</section>

<section id="xtra-conf"><title>Usando un Archivo de Configuración de Host Virtual Separado</title>

    <p>Este arreglo usa características más avanzadas de <module>mod_rewrite</module>
    para determinar la traducción de host virtual a raíz de documento,
    desde un archivo de configuración separado. Esto proporciona más
    flexibilidad, pero requiere una configuración más complicada.</p>

    <p>El archivo <code>vhost.map</code> debería verse algo como
    esto:</p>

<example>
customer-1.example.com  /www/customers/1<br />
customer-2.example.com  /www/customers/2<br />
# ...<br />
customer-N.example.com  /www/customers/N<br />
</example>

    <p>El <code>httpd.conf</code> debería contener lo siguiente:</p>

<highlight language="config">
RewriteEngine on

RewriteMap   lowercase  "int:tolower"

# define the map file
RewriteMap   vhost      "txt:/www/conf/vhost.map"

# deal with aliases as above
RewriteCond  "%{REQUEST_URI}"               "!^/icons/"
RewriteCond  "%{REQUEST_URI}"               "!^/cgi-bin/"
RewriteCond  "${lowercase:%{SERVER_NAME}}"  "^(.+)$"
# this does the file-based remap
RewriteCond  "${vhost:%1}"                  "^(/.*)$"
RewriteRule  "^/(.*)$"                      "%1/docs/$1"

RewriteCond  "%{REQUEST_URI}"               "^/cgi-bin/"
RewriteCond  "${lowercase:%{SERVER_NAME}}"  "^(.+)$"
RewriteCond  "${vhost:%1}"                  "^(/.*)$"
RewriteRule  "^/cgi-bin/(.*)$"                      "%1/cgi-bin/$1" [H=cgi-script]
</highlight>

</section>

</manualpage>
