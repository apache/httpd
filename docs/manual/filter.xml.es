<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 1562488 -->
<!-- Updated by Luis Gil de Bernabé Pfeiffer lgilbernabe[AT]apache.org -->
<!-- Reviewed by Sergio Ramos-->
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
      <p>Este documento describe cómo usar filtros en Apache.</p>
    </summary>

    <section id="intro">
      <title>Filtros en Apache 2</title>
      <related>
        <modulelist>
          <module>mod_filter</module>
          <module>mod_deflate</module>
          <module>mod_ext_filter</module>
          <module>mod_include</module>
          <module>mod_charset_lite</module>
          <module>mod_reflector</module>
          <module>mod_buffer</module>
          <module>mod_data</module>
          <module>mod_ratelimit</module>
          <module>mod_reqtimeout</module>
          <module>mod_request</module>
          <module>mod_sed</module>
          <module>mod_substitute</module>
          <module>mod_xml2enc</module>
          <module>mod_proxy_html</module>
          <module>mod_policy</module>
        </modulelist>
        <directivelist>
           <directive module="mod_filter">FilterChain</directive>
          <directive module="mod_filter">FilterDeclare</directive>
          <directive module="mod_filter">FilterProtocol</directive>
          <directive module="mod_filter">FilterProvider</directive>
          <directive module="mod_mime">AddInputFilter</directive>
          <directive module="mod_mime">AddOutputFilter</directive>
          <directive module="mod_mime">RemoveInputFilter</directive>
          <directive module="mod_mime">RemoveOutputFilter</directive>
          <directive module="mod_reflector">ReflectorHeader</directive>
          <directive module="mod_ext_filter">ExtFilterDefine</directive>
          <directive module="mod_ext_filter">ExtFilterOptions</directive>
          <directive module="core">SetInputFilter</directive>
          <directive module="core">SetOutputFilter</directive>
        </directivelist>
      </related>

        <p>La cadena de filtrado está disponible en Apache 2.0 y superiores.
        Un <em>filtro</em> es un proceso que se aplica a los datos que
        se reciben o se envían por el servidor. Los datos enviados
        por los clientes al servidor son procesados por <em>filtros de
        entrada</em> mientras que los datos enviados por el servidor se
        procesan por los <em>filtros de salida</em>. A los datos se les
        pueden aplicar varios filtros, y el orden en que se aplica cada
        filtro puede especificarse explícitamente.
        Todo este proceso es independiente de las tradicionales fase de
        peticiones</p>
        <p class="figure">
      <img src="images/filter_arch.png" width="569" height="392" alt=
      "Filters can be chained, in a Data Axis orthogonal to request processing"/>
      </p>
      <p>Algunos ejemplos de filtrado en la distribución estándar de Apache son:</p>
      <ul>
      <li><module>mod_include</module>, implementa  server-side includes (SSI).</li>
      <li><module>mod_ssl</module>, implementa cifrado SSL (https).</li>
      <li><module>mod_deflate</module>, implementa compresión y descompresión en el acto.</li>
      <li><module>mod_charset_lite</module>, transcodificación entre diferentes juegos de caracteres.</li>
      <li><module>mod_ext_filter</module>, ejecuta un programa externo como filtro.</li>
      </ul>
        <p>Los filtros se usan internamente por Apache para llevar a cabo
        funciones tales como chunking y servir peticiones de
        byte-range. Además, los módulos contienen filtros que se
        pueden seleccionar usando directivas de configuración al
        iniciar el servidor.</p>

        <p>Una mayor amplitud de aplicaciones son implementadas con módulos de 
        filtros de terceros que estan disponibles en <a
        href="http://modules.apache.org/">modules.apache.org</a> y en otros lados.
        algunos de ellos son:</p>

        <ul>
      <li>Procesamiento y reescritura de HTML y XML.</li>
      <li>Transformaciones de XSLT y XIncludes.</li>
      <li>Soporte de espacios de nombres en XML.</li>
      <li>Manipulación de carga de archivos y decodificación de los 
        formularios HTML.</li>
      <li>Procesamiento de imágenes.</li>
      <li>Protección de aplicaciones vulnerables, tales como scripts PHP</li>
      <li>Edición de texto de búsqueda y remplazo.</li>
      </ul>
    </section>
    <section id="smart">
      <title>Filtrado Inteligente</title>
        <p class="figure">
        <img src="images/mod_filter_new.png" width="423" height="331"
        alt="Smart filtering applies different filter providers according to the state of request processing"/>
        </p>
        <p><module>mod_filter</module>, incluido en Apache 2.1 y posterior,
        habilita la cadena de filtrado para ser configurada dinámicamente en
        tiempo de ejecución. Así, por ejemplo, usted puede configurar un 
        proxy para que reescriba HTML con un filtro de HTML y imágenes JPEG
        con filtros completos por separado, a pesar de que el proxy no tiene 
        información previa sobre lo que enviará al servidor de origen.
        Esto funciona usando un engranaje filtros, que envía a diferentes 
        proveedores dependiendo del contenido en tiempo de ejecución.
        Cualquier filtro puede ser, ya sea insertado directamente en la
        cadena y ejecutado incondicionalmente, o usado como proveedor y
        añadido dinámicamente
        Por ejemplo:</p>
        <ul>
        <li>Un filtro de procesamiento de HTML sólo se ejecuta si el 
          contenido es text/html o application/xhtml + xml.</li>
        <li>Un filtro de compresión sólo se ejecuta si la entrada es un tipo 
          compresible y no está ya comprimida.</li>
        <li>Se insertará un filtro de conversión de juego de caracteres,
          si un documento de texto no está ya en el juego de caracteres 
          deseado.</li>
      </ul>
    </section>

    <section id="service">

    <title>Filtros expuestos como un servicio HTTP</title>
    <p>Los filtros pueden ser usados para procesar contenido originado 
    desde el cliente además de usarse para procesar el contenido originado
    desde el propio servidor usando el módulo <module>mod_reflector</module>.</p>

    <p><module>mod_reflector</module> acepta peticiones POST de los clientes, y
    refleja el cuerpo de la petición POST recibida, dentro del contenido de la 
    respuesta de la petición, pasa a través de la pila del filtro de salida en 
    el camino de vuelta al cliente.</p>

    <p>Esta técnica se puede utilizar como una alternativa a un servicio web
    que se ejecuta en una pila de de aplicaciones dentro del servidor,
    en donde el filtro de salida proporciona la transformación requerida en el
    cuerpo de la petición. Por ejemplo, el módulo <module>mod_deflate</module>
    puede ser usado para proporcionar un servicio de compresión general,
    o un filtro de transformación de imagen, puede ser convertido en un
    servicio de conversión de imágenes.
    </p>

    </section>

    <section id="using">
    <title>Usando los Filtros</title>
    <p>Hay dos formas de usar el filtrado: de forma Simple y Dinámica.
    Generalmente, deberá usar una forma u otra; ya que mezclarlas puede
    causar consecuencias inesperadas (a pesar de que reglas de Entrada de 
    tipo simple pueden ser combinadas libremente con reglas de filtrado 
    de Salidas de tipo simple o dinámico).</p>
    <p>La forma más sencilla es la única manera de configurar filtros de 
    Entrada, y es suficiente para filtros de Salida donde se necesita una
    cadena de filtros estática.
    Las directivas más relevantes son:
        <directive module="core">SetInputFilter</directive>,
        <directive module="core">SetOutputFilter</directive>,
        <directive module="mod_mime">AddInputFilter</directive>,
        <directive module="mod_mime">AddOutputFilter</directive>,
        <directive module="mod_mime">RemoveInputFilter</directive>, and
        <directive module="mod_mime">RemoveOutputFilter</directive>.</p>

    <p>La forma Dinámica habilita ambas configuraciones estática, y dinámica, para los filtros de Salida, como se plantea en la página <module>mod_filter</module>.
    Las directivas más relevantes son:
        <directive module="mod_filter">FilterChain</directive>,
        <directive module="mod_filter">FilterDeclare</directive>, and
        <directive module="mod_filter">FilterProvider</directive>.</p>

    <p>Una directiva más como es <directive
    module="mod_filter">AddOutputFilterByType</directive> sigue siendo 
    soportada pero esta obsoleta. Usa en cambio la configuración dinámica.</p>

    </section>
</manualpage>