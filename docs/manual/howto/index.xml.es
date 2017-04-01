<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1786687 -->
<!-- Spanish translation : Daniel Ferradal -->
<!-- Reviewed by : Luis Gil de Bernabé Pfeiffer lgilbernabe [AT] apache.org -->
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

<manualpage metafile="index.xml.meta">
  <parentdocument href="../"/>

  <title>How-To / Tutoriales</title>

  <section id="howto">

    <title>How-To / Tutoriales</title>

    <dl>
      <dt>Autenticación y Autorización</dt>
      <dd>
        <p>Autenticación es un proceso en el cual se verifica 
		que alguien es quien afirma ser. Autorización es cualquier
		proceso en el que se permite a alguien acceder donde quiere ir,
        o a obtener la información que desea tener.</p>

        <p>Ver: <a href="auth.html">Autenticación, Autorización</a></p>
      </dd>
    </dl>

    <dl>
      <dt>Control de Acceso</dt>
      <dd>
        <p>Control de acceso hace referencia al proceso de restringir, o 
		garantizar el acceso a un recurso en base a un criterio arbitrario.
		Esto se puede conseguir de distintas formas.</p>

        <p>Ver: <a href="access.html">Control de Acceso</a></p>
      </dd>
    </dl>

   <dl>
      <dt>Contenido Dinámico con CGI</dt>
      <dd>
        <p>El CGI (Common Gateway Interface) es un método por el cual
		un servidor web puede interactuar con programas externos de 
		generación de contenido, a ellos nos referimos comúnmente como 
		programas CGI o scripts CGI. Es un método sencillo para mostrar
		contenido dinámico en tu sitio web. Este documento es una 
		introducción para configurar CGI en tu servidor web Apache, y de
		inicio para escribir programas CGI.</p>

        <p>Ver: <a href="cgi.html">CGI: Contenido Dinámico</a></p>
      </dd>
    </dl>

    <dl>
      <dt>Ficheros <code>.htaccess</code></dt>
      <dd>
        <p>Los ficheros <code>.htaccess</code> facilitan una forma de 
		hacer configuraciones por-directorio. Un archivo, que 
		contiene una o más directivas de configuración, se coloca en un
		directorio específico y las directivas especificadas solo aplican
		sobre ese directorio y los subdirectorios del mismo.</p>

        <p>Ver: <a href="htaccess.html"><code>.htaccess</code> files</a></p>
      </dd>
    </dl>

    <dl>
      <dt>HTTP/2 con httpd</dt>
      <dd>
      <p>HTTP/2 es la evolución del protocolo de capa de aplicación más conocido, HTTP. 
        Se centra en hacer un uso más eficiente de los recursos de red sin cambiar la
		semántica de HTTP. Esta guía explica como se implementa HTTP/2 en httpd,
		mostrando buenas prácticas y consejos de configuración básica.
      </p>

        <p>Ver: <a href="http2.html">Guía HTTP/2</a></p>
      </dd>
    </dl>


    <dl>
      <dt>Introducción a los SSI</dt>
      <dd>
        <p>Los SSI (Server Side Includes) son directivas que se colocan
		en las páginas HTML, y son evaluadas por el servidor mientras 
		éste las sirve. Le permiten añadir contenido generado 
		dinámicamente a una página HTML existente, sin tener que servir
		la página entera a través de un programa CGI u otro método 
		dinámico.</p>

        <p>Ver: <a href="ssi.html">Server Side Includes (SSI)</a></p>
      </dd>
    </dl>

    <dl>
      <dt>Directorios web Por-usuario</dt>
      <dd>
        <p>En sistemas con múltiples usuarios, cada usuario puede tener
		su directorio "home" compartido usando la directiva
		<directive module="mod_userdir">UserDir</directive>. Aquellos
		que visiten la URL <code>http://example.com/~username/</code>
		obtendrán contenido del directorio del usuario "<code>username</code>"
		que se encuentra en el directorio "home" del sistema.</p>

        <p>Ver: <a href="public_html.html">
		Directorios Web de Usuario (<code>public_html</code>)</a></p>
      </dd>
    </dl>

    <dl>
      <dt>Guía de Proxy Inverso</dt>
      <dd>
        <p>Apache httpd ofrece muchas posibilidades como proxy inverso. Usando la
		directiva <directive module="mod_proxy">ProxyPass</directive> así como
		<directive module="mod_proxy">BalancerMember</directive> puede crear
		sofisticadas configuraciones de proxy inverso que proveen de alta 
		disponibilidad, balanceo de carga, clustering basado en la nube y 
		reconfiguración dinámica en caliente.</p>

        <p>Ver: <a href="reverse_proxy.html">Guía de Proxy Inverso</a></p>
      </dd>
    </dl>

  </section>

</manualpage>


