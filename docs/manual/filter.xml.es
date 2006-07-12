<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 151408:421100 (outdated) -->

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

<manualpage metafile="filter.xml.meta">

  <title>Filtros</title>

  <summary>
    <p>Este documento describe c&#243;mo usar filtros en Apache.</p>
  </summary>

  <section id="filters">
    <title>Filtros</title>
    <related>
      <modulelist>
        <module>mod_deflate</module>
        <module>mod_ext_filter</module>
        <module>mod_include</module>
      </modulelist>
      <directivelist>
        <directive module="mod_mime">AddInputFilter</directive>
        <directive module="mod_mime">AddOutputFilter</directive>
        <directive module="mod_mime">RemoveInputFilter</directive>
        <directive module="mod_mime">RemoveOutputFilter</directive>
        <directive module="mod_ext_filter">ExtFilterDefine</directive>
        <directive module="mod_ext_filter">ExtFilterOptions</directive>
        <directive module="core">SetInputFilter</directive>
        <directive module="core">SetOutputFilter</directive>
      </directivelist>
    </related>

    <p>Un <em>filtro</em> es un proceso que se aplica a los datos que
    se reciben o se env&#237;an por el servidor. Los datos enviados
    por los clientes al servidor son procesados por <em>filtros de
    entrada</em> mientras que los datos enviados por el servidor se
    procesan por los <em>filtros de salida</em>. A los datos se les
    pueden aplicar varios filtros, y el orden en que se aplica cada
    filtro puede especificarse explícitamente.</p>

    <p>Los filtros se usan internamente por Apache para llevar a cabo
    funciones tales como chunking y servir peticiones de
    byte-range. Además, los m&#243;dulos contienen filtros que se
    pueden seleccionar usando directivas de configuraci&#243;n al
    iniciar el servidor. El conjunto de filtros que se aplica a los
    datos puede manipularse con las directivas <directive
    module="core">SetInputFilter</directive>, <directive
    module="core">SetOutputFilter</directive>, <directive
    module="mod_mime">AddInputFilter</directive>, <directive
    module="mod_mime">AddOutputFilter</directive>, <directive
    module="mod_mime">RemoveInputFilter</directive>, y <directive
    module="mod_mime">RemoveOutputFilter</directive>.</p>

    <p>Actualmente, vienen con la distribuci&#243;n de Apache los
    siguientes filtros seleccionables por el usuario.</p>

    <dl>
      <dt>INCLUDES</dt> 
      <dd>Server-Side Includes procesado por
      <module>mod_include</module></dd> 
      <dt>DEFLATE</dt> 
      <dd>Comprime los datos de salida antes de enviarlos al cliente
      usando el m&#243;dulo
      <module>mod_deflate</module>
      </dd>
    </dl>

    <p>Adem&#225;s, el m&#243;dulo <module>mod_ext_filter</module>
    permite definir programas externos como filtros.</p>
  </section>
</manualpage>

