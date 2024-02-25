<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 1690343 $ -->
<!-- Spanish translation : Daniel Ferradal Márquez -->

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

<manualpage metafile="getting-started.xml.meta">

  <title>Getting Started</title>

<summary>
<p>Si es tu primera vez con el servidor Apache HTTTP, o incluso para llevar 
un sitio web, puede que no sepas por dónde empezar, o qué preguntas hacer.
hacer. Este documento le guiará a través de los conceptos básicos.</p>
</summary>

<section id="clientserver">
<title>Clientes, Servidores y URLs</title>

<p>
Las direcciones en la Web se expresan con URLs - Uniform Resource Locators
- que especifican un protocolo (p.ej. <code>http</code>), un nombre de servidor (e.g.
<code>www.apache.org</code>), una URL-path (p.ej.
<code>/docs/current/getting-started.html</code>), y posiblemente una query
string (p.ej. <code>?arg=value</code>) utilizada para pasar parámetros adicionales
al servidor.
</p>

<p>Un cliente (p.ej., un navegador web) conecta al servidor (p.ej., tu Servidor Apache HTTP),
con el protocolo especificado, y hace una <strong>petición</strong> de un recurso utilizando 
una URL-path.</p>

<p>La URL-path puede representar varias cosas en el servidor. Podría ser un fichero 
(como <code>getting-started.html</code>) un handler (como <a
href="mod/mod_status.html">server-status</a>) or algún tipo de fichero de programa
(como <code>index.php</code>). Revisaremos esto más adelante en la sección 
<a href="#content">Contenido de Sitio Web</a>.</p>

<p>
El servidor enviará una <strong>respuesta</strong> que consiste en un código de estado
y, opcionalmente, un cuerpo del mensaje.
El código de estado indica si una petición tuvo éxito, y si no, qué tipo de condición
de error se ha dado. Esto le dice al cliente qué debe hacer con la respuesta. Puedes
leer sobre los códigos de respuesta posibles en
<a href="http://wiki.apache.org/httpd/CommonHTTPStatusCodes">La Wiki del Seridor
Apache</a>.</p>

<p>Detalles de la transacción, y cualquier condición de error, se escriben en los ficheros
de log. Esto se comenta en mayor detalle más abajo en la sección <a
href="#logs">Ficheros de Log y Solución de Problemas</a>.</p>

</section>

<section id="dns">
<title>Nombres de Host y DNS</title>

<p>Para conectar con un servidor, el cliente debe primero resolver
el nombre del servidor a una dirección IP - la ubicación en Internet donde reside el
servidor. Así, para que tu servidor sea accesible, es necesario que el nombre del
servidor está en DNS.</p>

<p>Si no sabes cómo hacer esto, necesitarás contactar con el administrador de tu red,
o proveedor de Internet, para realizar este paso por tí.</p>

<p>Más de un nombre de host puede apuntar a la misma dirección IP, y más de una
dirección IP puede apuntar al mismo servidor físico. Así puedes gestionar más
de un sitio web en el mismo servidor físico, usando una característica llamada
<a href="vhosts/">hosts virtuales</a>.</p>

<p>Si está haciendo pruebas con un servidor que no está accesible desde Internet,
puedes usar nombres de host en tu fichero hosts para hacer resolución de nombres
local. Por ejemplo, podrías querer poner en tu registro en tu fichero de hosts
para apuntar una petición hacia <code>www.example.com</code> en tu sistema local, 
para hacer pruebas. Esta entrada sería parecida a esto:</p>

<example>
127.0.0.1 www.example.com
</example>

<p>Un fichero de hosts probablemente esté ubicado en <code>/etc/hosts</code> or
<code>C:\Windows\system32\drivers\etc\hosts</code>.</p>

<p>Puedes leer más sobre ficheros de hosts en <a
href="http://en.wikipedia.org/wiki/Hosts_(file)">Wikipedia.org/wiki/Hosts_(file)</a>, 
y más sobre DNS en <a
href="http://en.wikipedia.org/wiki/Domain_Name_System">Wikipedia.org/wiki/Domain_Name_System</a>.</p>
</section>

<section id="configuration">
<title>Ficheros de Configuración y Directivas</title>

<p>El Servidor Apache HTTP se configura con ficheros de texto.
Estos ficheros pueden estar ubicados en distintos sitios, dependiendo de 
cómo se haya instalado exactamente tu servidor. Las ubicaciones comunes
para estos ficheros pueden encontrarse en <a href="http://wiki.apache.org/httpd/DistrosDefaultLayout">
la wiki de httpd</a>. Is instalaste httpd desde el código fuente, la
ubicación por defecto para estos ficheros se encuentra en
<code>/usr/local/apache2/conf</code>. El fichero de configuración por
defecto se llama generalmente <code>httpd.conf</code>. Esto también, puede
variar en distribuciones de terceros del servidor.</p>

<p>La configuración a menudo se separa en distintos ficheros más pequeños
para facilitar la gestión. Estos ficheros se cargan con la directiva <directive
module="core">Include</directive>. Los nombres o las ubicaciones de estos
sub-ficheros no es mágica, puede variar en gran manera de una instalación
a otra. Ordena y subdivide estos ficheros de la manera que tenga más sentido
para <strong>tí</strong>. Si la organicación de los ficheros por defecto
no tiene sentido para tí, siéntete libre de reorganizarla.</p>

<p>El servidor se configura colocando <a
href="mod/quickreference.html">directivas de configuración</a> en estos
ficheros de configuración. Una directiva es una palabra clave seguida de
uno o más parámetros para definir su valor.</p>

<p>La pregunta "<em>¿Dónde debo poner esta directiva?</em>" se contesta 
generalmente considerando dónde una directiva es efectiva. Si es una configuración
global, debería aparecer en el fichero de configuración, fuera de cualquier
sección <directive
type="section" module="core">Directory</directive>, <directive
type="section" module="core">Location</directive>, <directive
type="section" module="core">VirtualHost</directive>, u otra sección. Si es para
aplicar una configuración a un directorio en particular, debería ir dentro
de una sección 
<directive type="section" module="core">Directory</directive> haciendo referencia
a ese directorio, y así con todas. Vea el documento de <a href="sections.html">Secciones 
de Configuración</a> para obtener más detalle sobre estas secciones.</p>

<p>Además de los ficheros de configuración principales, ciertas directivas podría 
information en ficheros <code>.htaccess</code> ubicados en directorios de contenido.
Los ficheros <code>.htaccess</code> son principalmente para personas que no tienen
acceso a lo fichero(s) de configuración del servidor. Puedes leer más sobre los
ficheros <code>.htaccess</code> en el <a
href="howto/htaccess.html"><code>.htaccess</code> howto</a>.</p>

</section>

<section id="content">
<title>Contenido del Sitio Web</title>

<p>El contenido del sitio web puede tener distintas formas, pero puede dividirse
generalmente entre contenido estático y dinámico.</p>

<p>Contenido estático son cosas como ficheros HTML, ficheros de imágenes, ficheros CSS,
y otros ficheros que residen en el sistema de ficheros. La directiva <directive
module="core">DocumentRoot</directive> especifica dónde en el filesystem deberías
ubicar estos ficheros. Esta directiva está o bien configurada globalmente, o por
host virtual. Mira en tus ficheros de configuración para determinar como está esto
configurado en tu servidor.</p>

<p>Típicamente, un documento llamado <code>index.html</code> será servidor cuando
se solicita un directorio sin especificar un fichero. Por ejemplo si 
<code>DocumentRoot</code> se especifica con
<code>/var/www/html</code> y se hace una petición a 
<code>http://www.example.com/work/</code>, el fichero
<code>/var/www/html/work/index.html</code> será servido al cliente.</p>

<p>El contenido dinámico es cualquier cosa que se genera en tiempo de petición,
y puede cambiar de una petición a otra. Hay muchas formas de generar contenido
podría generarse. Varios <a
href="handler.html">handlers</a> están disponibles para generar contenido. <a
href="howto/cgi.html">programas CGI</a> podrían escribirse para generar contenido
para su sitio web.</p>

<p>Módulos de terceros como mod_php podrían usarse para escribir este código
que puede hacer variedad de cosas. Muchas aplicaciones de terceros, escritas
usanndo distintos lenguajes y herramientas, están disponibles para descarga e
instalación en su Servidor Apache HTTP. El soporte para estos elementos de
terceros está fuera el ámbito de esta documentación, y deberías encontrarse
su documentación en otros foros de soporte para responder a preguntas sobre
ellas.</p>
</section>

<section id="logs">
<title>Ficheros de Log y Solución de Problemas</title>
<p>Como administrador de un Servidor Apache HTTP, tus activos más valiosos
son los ficheros de log, y en el particular, el log de errores. Intentar hacer
Solución de Problemas sin el log de errores es como conducir con los ojos
cerrados.</p>

<p>La ubicación del log de errores se define con la directiva <directive
module="core">ErrorLog</directive> directive, que puede configurarse 
globalmnente o por host virtual. Entradas en el log de errores te indican
qué fue mal, y cuando. A menudo también te indican cómo corregirlo. Cada 
mensaje de error contiene un código de error, que puedes buscar en línea
para obtener descripciones aún más detalladas sobre cómo resolver el 
problema. También puedes configurar el log de errores para que incluya
un id de LOG que luego puedes correlacionar a una entrada en el 
log de accesos, y así poder determinar qué petición causó la condición 
de error.</p>

<p>Puedes leer más sobre el registro de logs en la <a href="logs.html">
documentación de logs</a>.</p>
</section>

<section id="other">
<title>¿Qué viene a continuación?</title>

<p>Una vez que cumples los pre-requisitos es hora de avanzar.</p>

<p>Esto documento sólo cubre cómo el mínimo básico. Esperamos que esto
te ayude a comenzar, pero hay muchas otras cosas que podrías necesitar
aprender.</p>

<ul>
<li><a href="http://httpd.apache.org/download.cgi">Descargar</a></li>
<li><a href="install.html">Instalar</a></li>
<li><a href="configuring.html">Configurar</a></li>
<li><a href="invoking.html">Arrancar</a></li>
<li><a href="http://wiki.apache.org/httpd/FAQ">Preguntas Realizadas a menudo</a></li>
</ul>

</section>

</manualpage>
