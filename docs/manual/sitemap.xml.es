<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE sitemap SYSTEM "./style/sitemap.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 1780356 -->
<!-- Spanish Translator: Luis Gil de Bernabé -->
<!-- Reviewed by: Sergio Ramos -->

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
<page href="upgrading.html">Actualizar Apache de la versión 2.2 a la 2.4</page>
<page href="new_features_2_4.html">Nuevas funcionalidades en Apache 2.3/2.4</page>
<page href="new_features_2_2.html">Nuevas funcionalidades en Apache 2.1/2.2</page>
<page href="new_features_2_0.html">Nuevas funcionalidades en Apache 2.0</page>
<page href="license.html">Licencia Apache</page>
</category>

<category id="using">
<title>Utilización del Servidor HTTP Apache</title>
<page href="install.html">Compilación e Instalación de Apache</page>
<page href="invoking.html">Iniciar Apache</page>
<page href="stopping.html">Parar y reiniciar Apache</page>
<page href="configuring.html">Ficheros de Configuración</page>
<page href="sections.html">Funcionamiento de las secciones Directory, Location y Files</page>
<page href="caching.html">Caché de contenido</page>
<page href="server-wide.html">Configuración Básica de Apache</page>
<page href="logs.html">Archivos de Log</page>
<page href="urlmapping.html">Mapeo de URLs a ubicaciones en el sistema de ficheros</page>
<page href="dso.html">Soporte de Objetos Dinámicos Compartidos (DSO)</page>
<page href="compliance.html">Conformidad con el Protocolo HTTP</page>
<page href="content-negotiation.html">Negociación de Contenido</page>
<page href="custom-error.html">Mensajes de Error Personalizados</page>
<page href="bind.html">Configurar las direcciones y los puertos que usa Apache</page>
<page href="mpm.html">Módulos de Multiproceso (MPMs)</page>
<page href="env.html">Variables de entorno en Apache</page>
<page href="expr.html">Análisis de expresiones en Apache</page>
<page href="handler.html">El uso de Handlers en Apache</page>
<page href="filter.html">Filtros</page>
<page href="socache.html">Soporte de caché compartida de objetos</page>
<page href="suexec.html">Soporte de suEXEC</page>
<page href="dns-caveats.html">Problemas respecto de DNS y Apache</page>
<page href="http://wiki.apache.org/httpd/FAQ">Preguntas Más Frecuentes</page>


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
</category>

<category id="rewrite">
<title>Guía de Reescritura de URLs</title>
<page separate="yes" href="rewrite/">Visión General</page>
<page href="mod/mod_rewrite.html">Documentación de referencia de mod_rewrite</page>
<page href="rewrite/intro.html">Introducción a expresiones regulares y a mod_rewrite</page>
<page href="rewrite/remapping.html">Uso de mod_rewrite para redireccione y 
re-mapeo de URLs</page>
<page href="rewrite/access.html">Uso de mod_rewrite para control de acceso</page>
<page href="rewrite/vhosts.html">Hosts dinámicos virtuales con mod_rewrite</page>
<page href="rewrite/proxy.html">Proxy dinámico con mod_rewrite</page>
<page href="rewrite/rewritemap.html">Utilización de RewriteMap</page>
<page href="rewrite/advanced.html">Técnicas avanzadas</page>
<page href="rewrite/avoid.html">Cuando NO usar mod_rewrite</page>
<page href="rewrite/flags.html">parámetros de RewriteRule </page>
<page href="rewrite/tech.html">Detalles técnicos</page>
</category>

<category id="ssl">
<title>Cifrado SSL/TLS con Apache</title>
<page separate="yes" href="ssl/">Visión General</page>
<page href="ssl/ssl_intro.html">Cifrado SSL/TLS: Introducción</page>
<page href="ssl/ssl_compat.html">Cifrado SSL/TLS: Compatibilidad</page>
<page href="ssl/ssl_howto.html">Cifrado SSL/TLS: How-To</page>
<page href="ssl/ssl_faq.html">Cifrado SSL/TLS: Preguntas Frecuentes</page>
</category>

<category id="howto">
<title>Guías, Tutoriales y How-To´s</title>
<page separate="yes" href="howto/">Visión General</page>
<page href="howto/auth.html">Autenticación y Autorización</page>
<page href="howto/access.html">Control de Acceso</page>
<page href="howto/cgi.html">Contenido Dinámico con CGIs</page>
<page href="howto/ssi.html">Introducción a Inclusiones 
del lado del Servidor (Server Side Includes)</page>
<page href="howto/htaccess.html">Archivos .htaccess</page>
<page href="howto/public_html.html">Directorios web para cada usuario</page>
<page href="howto/reverse_proxy.html">Guía de montaje de proxy inverso</page>
<page href="howto/http2.html">Guía HTTP/2</page>

</category>

<category id="platform">
<title>Notas específicas sobre plataformas</title>
<page separate="yes" href="platform/">Visión General</page>
<page href="platform/windows.html">Usar Apache con Microsoft Windows</page>
<page href="platform/win_compiling.html">Compilar Apache para
Microsoft Windows</page>
<page href="platform/rpm.html">Usar Apache en Sistemas Basados en RPM</page>
<page href="platform/netware.html">Usar Apache con 
Novell NetWare</page> 
<page href="platform/perf-hp.html">Servidor Web de alto rendimiento con
HP-UX</page> 
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
<page href="programs/fcgistarter.html">Página de Ayuda: fcgistarter</page>
<page href="programs/firehose.html">Página de Ayuda: firehose</page>
<page href="programs/htcacheclean.html">Página de Ayuda: htcacheclean</page>
<page href="programs/htdbm.html">Página de Ayuda: htdbm</page>
<page href="programs/htdigest.html">Página de Ayuda: htdigest</page>
<page href="programs/htpasswd.html">Página de Ayuda: htpasswd</page>
<page href="programs/httxt2dbm.html">Página de Ayuda: httxt2dbm</page>
<page href="programs/logresolve.html">Página de Ayuda: logresolve</page>
<page href="programs/log_server_status.html">Página de Ayuda:
log_server_status</page>
<page href="programs/rotatelogs.html">Página de Ayuda: rotatelogs</page>
<page href="programs/split-logfile.html">Página de Ayuda: split-logfile</page>
<page href="programs/suexec.html">Página de Ayuda: suexec</page>
<page href="programs/other.html">Otros Programas</page>
</category>

<category id="misc">
<title>Documentación adicional sobre Apache</title>
<page separate="yes" href="misc/">Visión General</page>
<page href="misc/perf-tuning.html">Notas de Rendimiento - Tuning de Apache</page>
<page href="misc/perf-scaling.html">Escalado de Rendimiento</page>
<page href="misc/security_tips.html">Consejos de Seguridad</page>
<page href="misc/relevant_standards.html">Estándares Importantes</page>
<page href="misc/password_encryptions.html">Formatos de Cifrado de Contraseñas</page>
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
<page href="developer/new_api_2_4.html">Actualizaciones de la API en Apache HTTPD 2.4</page>
<page href="developer/modguide.html">Desarrollo de módulos para Apache HTTPD 2.4</page>
<page href="developer/documenting.html">Documentando Apache HTTPD</page>
<page href="developer/hooks.html">Funciones Hook de Apache 2.x</page>
<page href="developer/modules.html">Convertir Módulos de Apache 1.3 a Apache 2.x</page>
<page href="developer/request.html">Procesamiento de Peticiones en Apache 2.x</page>
<page href="developer/filters.html">Funcionamiento de los Filtros en Apache 2.x</page>
<page href="developer/output-filters.html">Guías para los Filtros de salida en versiones 2.x</page>
<page href="developer/thread_safety.html">Problemas de Seguridad con los 
	Procesos en versiones 2.x</page>
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

