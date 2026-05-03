<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933438:1933718 (outdated) -->

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

  <title>Apache mod_rewrite</title>

<summary>

    <p><module>mod_rewrite</module> proporciona una forma de modificar las
    solicitudes de URL entrantes, dinámicamente, basándose en reglas de <a href="intro.html#regex">expresiones
    regulares</a>. Esto le permite mapear URLs arbitrarias a
    su estructura interna de URLs de la forma que desee.</p>

      <p>Soporta un número ilimitado de reglas y un
      número ilimitado de condiciones de regla adjuntas para cada regla, para
      proporcionar un mecanismo de manipulación de URLs realmente flexible y potente.
      Las manipulaciones de URL pueden depender de varias pruebas:
      variables del servidor, variables de entorno, cabeceras HTTP,
      marcas de tiempo, consultas a bases de datos externas, y varios otros
      programas externos o manejadores, pueden usarse para lograr una coincidencia
      de URL granular.</p>

      <p>Las reglas de reescritura pueden operar sobre las URLs completas, incluyendo las partes
      de path-info y cadena de consulta, y pueden usarse en contexto per-servidor
      (<code>httpd.conf</code>), contexto per-virtualhost (bloques <directive
      type="section" module="core">VirtualHost</directive>), o
      contexto per-directorio (archivos <code>.htaccess</code> y bloques <directive
      type="section" module="core">Directory</directive>). El
      resultado reescrito puede llevar a más reglas, sub-procesamiento
      interno, redirección de solicitud externa, o paso a través de
      proxy, dependiendo de qué <a href="flags.html">banderas</a>
      adjunte a las reglas.</p>

      <p>Dado que <module>mod_rewrite</module> es tan potente, puede ser bastante
      complejo. Este documento complementa la <a
      href="../mod/mod_rewrite.html">documentación de referencia</a>, e
      intenta aliviar algo de esa complejidad, y proporcionar ejemplos altamente
      anotados de escenarios comunes que puede manejar con
      <module>mod_rewrite</module>. Pero también intentamos mostrarle cuándo no debería
      usar <module>mod_rewrite</module>, y usar otras características estándar de Apache en su lugar,
      evitando así esta complejidad innecesaria.</p>


<ul>
<li><a href="../mod/mod_rewrite.html">Documentación de referencia de
mod_rewrite</a></li>
<li><a href="intro.html">Introducción a las expresiones regulares y mod_rewrite</a></li>
<li><a href="flags.html">Banderas de RewriteRule</a></li>
<li><a href="rewritemap.html">Uso de RewriteMap</a></li>
<li><a href="avoid.html">Cuándo <strong>NO</strong> usar mod_rewrite</a></li>
<li><a href="remapping.html">Uso de mod_rewrite para redirección y remapeo de URLs</a></li>
<li><a href="access.html">Uso de mod_rewrite para control de acceso</a></li>
<li><a href="vhosts.html">Hosts virtuales dinámicos con mod_rewrite</a></li>
<li><a href="proxy.html">Proxy dinámico con mod_rewrite</a></li>
<li><a href="advanced.html">Técnicas avanzadas</a></li>
<li><a href="tech.html">Detalles técnicos</a></li>
</ul>
</summary>

<seealso><a href="../mod/mod_rewrite.html">Documentación de referencia de
mod_rewrite</a></seealso>
<seealso><a href="../urlmapping.html">Mapeo de URLs al sistema de archivos</a></seealso>
<seealso><a href="https://cwiki.apache.org/confluence/display/httpd/Rewrite">Wiki de
mod_rewrite</a></seealso>
<seealso><a href="../glossary.html">Glosario</a></seealso>


</manualpage>
