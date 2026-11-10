<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1936367 -->
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

<manualpage metafile="module-dict.xml.meta">

  <title>Términos usados para describir los módulos</title>

<summary>
   <p>Este documento describe los términos que se usan para describir
    cada <a href="./">módulo</a> de Apache.</p>
</summary>

<section id="Description"><title>Description (Descripción)</title>

<p>Una breve descripción del propósito del módulo.</p>
</section>

<section id="Status"><title>Status (Estado)</title>

    <p>Esto indica con qué grado de integración forma parte el módulo
    del servidor web Apache; en otras palabras, puede que necesite
    recompilar el servidor para tener acceso al módulo y a su
    funcionalidad. Los valores posibles para este atributo son:</p>

    <dl>
      <dt>MPM</dt>

      <dd>Un módulo con estado "MPM" es un <a
      href="../mpm.html">Módulo Multi-Proceso</a>. A diferencia de
      los otros tipos de módulos, Apache debe tener uno y solo un MPM
      en uso en todo momento. Este tipo de módulo es responsable de
      la gestión y el despacho básico de las peticiones.</dd>

      <dt>Base</dt>

      <dd>Un módulo etiquetado con estado "Base" se compila y
      se carga en el servidor por defecto, por lo que normalmente
      está disponible a menos que haya tomado medidas para eliminar el módulo
      de su configuración.</dd>

      <dt>Extension</dt>

      <dd>Un módulo con estado "Extension" normalmente no se compila
      ni se carga en el servidor. Para activar el módulo y su
      funcionalidad, puede que necesite modificar los archivos de configuración
      de compilación del servidor y volver a compilar Apache.</dd>

      <dt>Experimental</dt>

      <dd>El estado "Experimental" indica que el módulo está
      disponible como parte del paquete de Apache, pero usarlo es
      responsabilidad exclusiva del usuario. El módulo se documenta por
      completitud, pero no necesariamente se ofrece soporte para él.</dd>

      <dt>Deprecated</dt>

      <dd>Un módulo con estado "Deprecated" sigue estando disponible y
      es funcional, pero se desaconseja su uso. El módulo puede
      eliminarse en la siguiente versión menor. Consulte la documentación del módulo para
      conocer los posibles reemplazos o vías de migración.</dd>

      <dt>External</dt>

      <dd>Los módulos que no se incluyen con la distribución base de Apache
      ("módulos de terceros") pueden usar el estado "External". No somos
      responsables de dichos módulos, ni les ofrecemos soporte.</dd>
    </dl>
</section>

<section id="SourceFile"><title>Source File (Archivo fuente)</title>

    <p>Esto simplemente indica el nombre del archivo fuente que
    contiene el código del módulo. Este es también el nombre que usa la
    directiva <directive module="core" type="section">IfModule</directive>.</p>
</section>

<section id="ModuleIdentifier"><title>Module Identifier (Identificador de módulo)</title>

    <p>Esta es una cadena que identifica el módulo para su uso en la
    directiva <directive module="mod_so">LoadModule</directive> al
    cargar módulos de forma dinámica. En concreto, es el nombre de
    la variable externa de tipo module en el archivo fuente.</p>
</section>

<section id="Compatibility"><title>Compatibility (Compatibilidad)</title>

    <p>Si el módulo no formaba parte de la distribución original de Apache
    versión 2, aquí se indicará la versión en la que se introdujo. Además,
    si el módulo está limitado a determinadas plataformas, aquí se
    detallará esa información.</p>
</section>

</manualpage>
