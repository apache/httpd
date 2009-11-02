<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE sitemap SYSTEM "./style/sitemap.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 151408:832042 (outdated) -->

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

<sitemap metafile="sitemap.xml.meta">

  <title>Mapa de este sitio web</title>

<summary>
<p>Esta p&#225;gina contiene la lista con los documentos actualmente
disponibles de la <a href="./">Versi&#243;n &httpd.major;.&httpd.minor; de la
Documentaci&#243;n del Servidor HTTP Apache</a>.</p>
</summary>

<category id="release">
<title>Notas de la Versi&#243;n</title>
<page href="upgrading.html">Pasar a usar Apache 2.0 desde Apache 1.3</page>
<page href="new_features_2_0.html">Nuevas funcionalidades de Apache 2.0</page>
<page href="license.html">Licencia Apache</page>
</category>

<category id="using">
<title>Funcionamiento del Servidor HTTP Apache</title>
<page href="install.html">Compilaci&#243;n e Instalaci&#243;n de Apache</page>
<page href="invoking.html">Iniciar Apache</page>
<page href="stopping.html">Parar y reiniciar Apache</page>
<page href="configuring.html">Ficheros de Configuraci&#243;n</page>
<page href="sections.html">Funcionamiento de las secciones Directory, Location y Files</page>
<page href="server-wide.html">Configuraci&#243;n B&#225;sica de Apache</page>
<page href="logs.html">Archivos Log</page>
<page href="urlmapping.html">Mapear URLs a ubicaciones de un sistema de ficheros</page>
<page href="misc/security_tips.html">Consejos de Seguridad</page>
<page href="dso.html">Soporte de Objetos Din&#225;micos Compartidos (DSO)</page>
<page href="content-negotiation.html">Negociaci&#243;n de Contenido</page>
<page href="custom-error.html">Mensajes de Error Personalizados</page>
<page href="bind.html">Fijar las direcciones y los puertos que usa Apache</page>
<page href="mpm.html">M&#243;dulos de Multiproceso (MPMs)</page>
<page href="env.html">Variables de entorno en Apache</page>
<page href="handler.html">El uso de Handlers en Apache</page>
<page href="filter.html">Filtros</page>
<page href="suexec.html">Soporte de suEXEC</page>
<page href="misc/perf-tuning.html">Rendimiento del servidor</page>
<page href="misc/rewriteguide.html">Documentaci&#243;n adicional sobre mod_rewrite</page>
</category>

<category id="vhosts">
<title>Documuentaci&#243;n sobre Hosting Virtual en Apache</title>
<page separate="yes" href="vhosts/">Visi&#243;n General</page>
<page href="vhosts/name-based.html">Hosting Virtual basado en nombres</page>
<page href="vhosts/ip-based.html">Soporte de Hosting Virtual Basado en IPs</page>
<page href="vhosts/mass.html">Configurar de forma Din&#225;mica el Hosting Virtual masivo en Apache</page>
<page href="vhosts/examples.html">Ejemplos de Hosting Virtual</page>
<page href="vhosts/details.html">Discusi&#243;n en profundidad sobre los tipos de Hosting Virtual</page>
<page href="vhosts/fd-limits.html">Limitaciones de los descriptores de ficheros</page>
<page href="dns-caveats.html">Asuntos relacionados con DNS y Apache</page>
</category>

<category id="faq">
<title>Preguntas M&#225;s Frecuentes sobre Apache</title>
<page href="faq/">Visi&#243;n General</page>
<page href="faq/support.html">Soporte</page>
<page href="faq/error.html">Mensajes de error</page>
</category>

<category id="ssl">
<title>Encriptado SSL/TLS con Apache</title>
<page separate="yes" href="ssl/">Visi&#243;n General</page>
<page href="ssl/ssl_intro.html">Encriptado SSL/TLS: Introducci&#243;n</page>
<page href="ssl/ssl_compat.html">Encriptado SSL/TLS: Compatibilidad</page>
<page href="ssl/ssl_howto.html">Encriptado SSL/TLS: How-To</page>
<page href="ssl/ssl_faq.html">Encriptado SSL/TLS: Preguntas Frecuentes</page>
</category>

<category id="howto">
<title>Gu&#237;as, Tutoriales, y HowTos</title>
<page separate="yes" href="howto/">Visi&#243;n General</page>
<page href="howto/auth.html">Autentificaci&#243;n</page>
<page href="howto/cgi.html">Contenido Din&#225;mico con CGIs</page>
<page href="howto/ssi.html">Introducci&#243;n a Server Side Includes</page>
<page href="howto/htaccess.html">Archivos .htaccess</page>
<page href="howto/public_html.html">Directorios web para cada usuario</page>
</category>

<category id="platform">
<title>Notas espec&#237;ficas sobre plataformas</title> <page separate="yes"
href="platform/">Visi&#243;n General</page> <page
href="platform/windows.html">Usar Apache con Microsoft Windows</page>
<page href="platform/win_compiling.html">Compilar Apache para
Microsoft Windows</page> <page href="platform/netware.html">Usar
Apache con Novell NetWare</page> <page
href="platform/perf-hp.html">Servidor Web de alto rendimiento con
HPUX</page> <page href="platform/ebcdic.html">La versi&#243;n EBCDIC de
Apache</page>
</category>

<category id="programs">
<title>Programas de soporte y el Servidor HTTP Apache</title>
<page separate="yes" href="programs/">Visi&#243;n General</page>
<page href="programs/httpd.html">P&#225;gina de Ayuda: httpd</page>
<page href="programs/ab.html">P&#225;gina de Ayuda: ab</page>
<page href="programs/apachectl.html">P&#225;gina de Ayuda: apachectl</page>
<page href="programs/apxs.html">P&#225;gina de Ayuda: apxs</page>
<page href="programs/configure.html">P&#225;gina de Ayuda: configure</page>
<page href="programs/dbmmanage.html">P&#225;gina de Ayuda: dbmmanage</page>
<page href="programs/htcacheclean.html">P&#225;gina de Ayuda: htcacheclean</page>
<page href="programs/htdigest.html">P&#225;gina de Ayuda: htdigest</page>
<page href="programs/htpasswd.html">P&#225;gina de Ayuda: htpasswd</page>
<page href="programs/logresolve.html">P&#225;gina de Ayuda: logresolve</page>
<page href="programs/rotatelogs.html">P&#225;gina de Ayuda: rotatelogs</page>
<page href="programs/suexec.html">P&#225;gina de Ayuda: suexec</page>
<page href="programs/other.html">Otros Programas</page>
</category>

<category id="misc">
<title>Documentaci&#243;n adicional sobre Apache</title>
<page separate="yes" href="misc/">Visi&#243;n General</page>
<page href="misc/relevant_standards.html">Est&#225;ndares Importantes</page>
</category>

<category id="modules">
<title>M&#243;dulos de Apache</title>
<page href="mod/module-dict.html">Definiciones de t&#233;rminos usados
para describir los m&#243;dulos de Apache</page>
<page href="mod/directive-dict.html">Definiciones de t&#233;rminos
usados para describir las directivas de Apache</page>
</category>

<category id="developer">
<title>Documentaci&#243;n para desarrolladores</title>
<page separate="yes" href="developer/">Visi&#243;n General</page>
<page href="developer/API.html">Notas sobre la API de Apache</page>
<page href="developer/debugging.html">Debugging la Reserva de Memoria en APR</page>
<page href="developer/documenting.html">Documentando Apache 2.0</page>
<page href="developer/hooks.html">Funciones Hook de Apache 2.0</page>
<page href="developer/modules.html">Convertir M&#243;dulos de Apache 1.3 a Apache 2.0</page>
<page href="developer/request.html">Procesamiento de Peticiones en Apache 2.0</page>
<page href="developer/filters.html">Funcionamiento de los filtros en Apache 2.0</page>
</category>

<category id="index">
<title>Glosario e &#205;ndice</title>
<page href="glossary.html">Glosario</page>
<page href="mod/">&#205;ndice de M&#243;dulos</page>
<page href="mod/directives.html">&#205;ndice de Directivas</page>
<page href="mod/quickreference.html">Gu&#237;a R&#225;pida de
Referencia de Directivas</page>
</category>

</sitemap>

