<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE sitemap SYSTEM "./style/sitemap.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 1780358 -->
<!-- Reviewed by Luis Gil de Bernabé Pfeiffer-->
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
<p>Esta página contiene la lista con los documentos actualmente
disponibles de la <a href="./">Versión &httpd.major;.&httpd.minor; de la
Documentación del Servidor HTTP Apache</a>.</p>
</summary>

<category id="release">
<title>Notas de la Versión</title>
<page href="upgrading.html">Pasar a usar Apache 2.0 desde Apache 1.3</page>
<page href="new_features_2_0.html">Nuevas funcionalidades de Apache 2.0</page>
<page href="license.html">Licencia Apache</page>
</category>

<category id="using">
<title>Funcionamiento del Servidor HTTP Apache</title>
<page href="install.html">Compilación e Instalación de Apache</page>
<page href="invoking.html">Iniciar Apache</page>
<page href="stopping.html">Parar y reiniciar Apache</page>
<page href="configuring.html">Ficheros de Configuración</page>
<page href="sections.html">Funcionamiento de las secciones Directory, Location y Files</page>
<page href="server-wide.html">Configuración Básica de Apache</page>
<page href="logs.html">Archivos Log</page>
<page href="urlmapping.html">Mapear URLs a ubicaciones de un sistema de ficheros</page>
<page href="misc/security_tips.html">Consejos de Seguridad</page>
<page href="dso.html">Soporte de Objetos Dinámicos Compartidos (DSO)</page>
<page href="content-negotiation.html">Negociación de Contenido</page>
<page href="custom-error.html">Mensajes de Error Personalizados</page>
<page href="bind.html">Fijar las direcciones y los puertos que usa Apache</page>
<page href="mpm.html">Módulos de Multiproceso (MPMs)</page>
<page href="env.html">Variables de entorno en Apache</page>
<page href="handler.html">El uso de Handlers en Apache</page>
<page href="filter.html">Filtros</page>
<page href="suexec.html">Soporte de suEXEC</page>
<page href="misc/perf-tuning.html">Rendimiento del servidor</page>
<page href="misc/rewriteguide.html">Documentación adicional sobre mod_rewrite</page>
</category>

<category id="vhosts">
<title>Documentación sobre Hosting Virtual en Apache</title>
<page separate="yes" href="vhosts/">Visión General</page>
<page href="vhosts/name-based.html">Hosting Virtual basado en nombres</page>
<page href="vhosts/ip-based.html">Soporte de Hosting Virtual Basado en IPs</page>
<page href="vhosts/mass.html">Configurar de forma Dinámica el Hosting Virtual masivo en Apache</page>
<page href="vhosts/examples.html">Ejemplos de Hosting Virtual</page>
<page href="vhosts/details.html">Discusión en profundidad sobre los tipos de Hosting Virtual</page>
<page href="vhosts/fd-limits.html">Limitaciones de los descriptores de ficheros</page>
<page href="dns-caveats.html">Asuntos relacionados con DNS y Apache</page>
</category>

<category id="faq">
<title>Preguntas Más Frecuentes sobre Apache</title>
<page href="faq/">Visión General</page>
<page href="faq/support.html">Soporte</page>
<page href="faq/error.html">Mensajes de error</page>
</category>

<category id="ssl">
<title>Encriptado SSL/TLS con Apache</title>
<page separate="yes" href="ssl/">Visión General</page>
<page href="ssl/ssl_intro.html">Encriptado SSL/TLS: Introducción</page>
<page href="ssl/ssl_compat.html">Encriptado SSL/TLS: Compatibilidad</page>
<page href="ssl/ssl_howto.html">Encriptado SSL/TLS: How-To</page>
<page href="ssl/ssl_faq.html">Encriptado SSL/TLS: Preguntas Frecuentes</page>
</category>

<category id="howto">
<title>Guías, Tutoriales, y HowTos</title>
<page separate="yes" href="howto/">Visión General</page>
<page href="howto/auth.html">Autentificación</page>
<page href="howto/cgi.html">Contenido Dinámico con CGIs</page>
<page href="howto/ssi.html">Introducción a Server Side Includes</page>
<page href="howto/htaccess.html">Archivos .htaccess</page>
<page href="howto/public_html.html">Directorios web para cada usuario</page>
</category>

<category id="platform">
<title>Notas específicas sobre plataformas</title> <page separate="yes"
href="platform/">Visión General</page> <page
href="platform/windows.html">Usar Apache con Microsoft Windows</page>
<page href="platform/win_compiling.html">Compilar Apache para
Microsoft Windows</page> <page href="platform/netware.html">Usar
Apache con Novell NetWare</page> <page
href="platform/perf-hp.html">Servidor Web de alto rendimiento con
HPUX</page> <page href="platform/ebcdic.html">La versión EBCDIC de
Apache</page>
</category>

<category id="programs">
<title>Programas de soporte y el Servidor HTTP Apache</title>
<page separate="yes" href="programs/">Visión General</page>
<page href="programs/httpd.html">Página de Ayuda: httpd</page>
<page href="programs/ab.html">Página de Ayuda: ab</page>
<page href="programs/apachectl.html">Página de Ayuda: apachectl</page>
<page href="programs/apxs.html">Página de Ayuda: apxs</page>
<page href="programs/configure.html">Página de Ayuda: configure</page>
<page href="programs/dbmmanage.html">Página de Ayuda: dbmmanage</page>
<page href="programs/htcacheclean.html">Página de Ayuda: htcacheclean</page>
<page href="programs/htdigest.html">Página de Ayuda: htdigest</page>
<page href="programs/htpasswd.html">Página de Ayuda: htpasswd</page>
<page href="programs/logresolve.html">Página de Ayuda: logresolve</page>
<page href="programs/rotatelogs.html">Página de Ayuda: rotatelogs</page>
<page href="programs/suexec.html">Página de Ayuda: suexec</page>
<page href="programs/other.html">Otros Programas</page>
</category>

<category id="misc">
<title>Documentación adicional sobre Apache</title>
<page separate="yes" href="misc/">Visión General</page>
<page href="misc/relevant_standards.html">Estándares Importantes</page>
</category>

<category id="modules">
<title>Módulos de Apache</title>
<page href="mod/module-dict.html">Definiciones de términos usados
para describir los módulos de Apache</page>
<page href="mod/directive-dict.html">Definiciones de términos
usados para describir las directivas de Apache</page>
</category>

<category id="developer">
<title>Documentación para desarrolladores</title>
<page separate="yes" href="developer/">Visión General</page>
<page href="developer/API.html">Notas sobre la API de Apache</page>
<page href="developer/debugging.html">Debugear la Reserva de Memoria en APR</page>
<page href="developer/documenting.html">Documentando Apache 2.0</page>
<page href="developer/hooks.html">Funciones Hook de Apache 2.0</page>
<page href="developer/modules.html">Convertir Módulos de Apache 1.3 a Apache 2.0</page>
<page href="developer/request.html">Procesamiento de Peticiones en Apache 2.0</page>
<page href="developer/filters.html">Funcionamiento de los filtros en Apache 2.0</page>
</category>

<category id="index">
<title>Glosario e Índice</title>
<page href="glossary.html">Glosario</page>
<page href="mod/">Índice de Módulos</page>
<page href="mod/directives.html">Índice de Directivas</page>
<page href="mod/quickreference.html">Guía Rápida de
Referencia de Directivas</page>
</category>

</sitemap>

