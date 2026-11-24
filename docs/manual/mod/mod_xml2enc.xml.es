<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
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

<modulesynopsis metafile="mod_xml2enc.xml.meta">

<name>mod_xml2enc</name>
<description>Soporte mejorado de juego de caracteres/internacionalización para
módulos de filtro basados en libxml2</description>
<status>Base</status>
<sourcefile>mod_xml2enc.c</sourcefile>
<identifier>xml2enc_module</identifier>
<compatibility>Versión 2.4 y posteriores. Disponible como módulo de terceros
para las versiones 2.2.x</compatibility>

<summary>
    <p>Este módulo proporciona soporte de internacionalización mejorado para
    módulos de filtro compatibles con marcado, como <module>mod_proxy_html</module>.
    Puede detectar automáticamente la codificación de los datos de entrada y asegurarse
    de que el analizador <a href="http://xmlsoft.org/"
    >libxml2</a> los procese correctamente, incluida la conversión a Unicode (UTF-8) cuando
    sea necesario. También puede convertir los datos a una codificación a elegir
    después del procesamiento del marcado, y se asegurará de que se establece el valor
    de <var>charset</var> correcto en la cabecera HTTP <var>Content-Type</var>.</p>
</summary>

<section id="usage"><title>Uso</title>
    <p>Hay dos escenarios de uso: con módulos programados para funcionar
    con mod_xml2enc, y con aquellos que no son conscientes de él:</p>
    <dl>
    <dt>Módulos de filtro habilitados para mod_xml2enc</dt><dd>
    <p>Módulos como <module>mod_proxy_html</module> versión 3.1
    en adelante usan la función opcional <code>xml2enc_charset</code> para obtener
    el argumento de charset que pasar al analizador libxml2, y pueden usar la
    función opcional <code>xml2enc_filter</code> para posprocesar a otra
    codificación. Al usar mod_xml2enc con un módulo habilitado, no es necesaria
    ninguna configuración: el otro módulo configurará mod_xml2enc por usted
    (aunque puede que aún desee personalizarlo usando las directivas de
    configuración siguientes).</p>
    </dd>
    <dt>Módulos no habilitados</dt><dd>
    <p>Para usarlo con un módulo basado en libxml2 que no esté explícitamente habilitado
    para mod_xml2enc, tendrá que configurar usted mismo la cadena de filtros. Así que para
    usarlo con un filtro <strong>foo</strong> proporcionado por un módulo
    <strong>mod_foo</strong> para mejorar el soporte de i18n de este último con HTML y
    XML, podría usar</p>
    <pre><code>
    FilterProvider iconv    xml2enc Content-Type $text/html
    FilterProvider iconv    xml2enc Content-Type $xml
    FilterProvider markup   foo Content-Type $text/html
    FilterProvider markup   foo Content-Type $xml
    FilterChain     iconv markup
    </code></pre>
    <p><strong>mod_foo</strong> ahora admitirá cualquier juego de caracteres admitido por
    libxml2 o por apr_xlate/iconv (o por ambos).</p>
    </dd></dl>
</section>

<section id="api"><title>API de programación</title>
    <p>Se recomienda a los programadores que escriban módulos de filtro basados en libxml2
    habilitarlos para mod_xml2enc, para ofrecer un soporte de i18n sólido a sus
    usuarios sin reinventar la rueda. La API de programación se expone en
    <var>mod_xml2enc.h</var>, y un ejemplo de uso es
    <module>mod_proxy_html</module>.</p>
</section>

<section id="sniffing"><title>Detección de una codificación</title>
    <p>A diferencia de <module>mod_charset_lite</module>, mod_xml2enc está diseñado
    para trabajar con datos cuya codificación no se puede conocer de antemano y por
    tanto no se puede configurar. Por ello usa técnicas de "sniffing" para detectar la
    codificación de los datos HTTP de la siguiente manera:</p>
    <ol>
        <li>Si la cabecera HTTP <var>Content-Type</var> incluye un
        parámetro <var>charset</var>, se usa ese.</li>
        <li>Si los datos comienzan con una marca de orden de bytes (BOM) XML o una
        declaración de codificación XML, se usa esa.</li>
        <li>Si se declara una codificación en un elemento <code>&lt;META&gt;</code>
        de HTML, se usa esa.</li>
        <li>Si no coincide nada de lo anterior, se usa el valor por defecto establecido por
        <directive>xml2EncDefault</directive>.</li>
    </ol>
    <p>Las reglas se aplican en orden. En cuanto se encuentra una coincidencia,
    se usa y se detiene la detección.</p>
</section>

<section id="output"><title>Codificación de salida</title>
<p><a href="http://xmlsoft.org/">libxml2</a> siempre usa UTF-8 (Unicode)
internamente, y los módulos de filtro basados en libxml2 generarán esa salida por defecto.
mod_xml2enc puede cambiar la codificación de salida a través de la API, pero actualmente
no hay forma de configurar eso directamente.</p>
<p>Cambiar la codificación de salida no debería (en teoría, al menos) ser nunca
necesario, y no se recomienda debido a la carga de procesamiento adicional que supone
para el servidor una conversión innecesaria.</p>
</section>

<section id="alias"><title>Codificaciones no admitidas</title>
<p>Si trabaja con codificaciones que no admite ninguno de los métodos de
conversión disponibles en su plataforma, aún puede asociarlas (alias)
a una codificación admitida usando <directive>xml2EncAlias</directive>.</p>
</section>

<directivesynopsis>
<name>xml2EncDefault</name>
<description>Establece una codificación por defecto que asumir cuando no se pueda
<a href="#sniffing">detectar automáticamente</a> absolutamente ninguna información</description>
<syntax>xml2EncDefault <var>name</var></syntax>
<contextlist><context>server config</context>
<context>virtual host</context><context>directory</context>
<context>.htaccess</context></contextlist>
<override>All</override>

<usage>
    <p>Si está procesando datos con una codificación conocida pero sin información
    de codificación, puede establecer este valor por defecto para ayudar a mod_xml2enc a procesar
    los datos correctamente. Por ejemplo, para trabajar con el valor por defecto
    de Latin1 (<var>iso-8859-1</var>) especificado en HTTP/1.0, use:</p>
    <highlight language="config">
xml2EncDefault iso-8859-1
    </highlight>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>xml2EncAlias</name>
<description>Reconoce alias para valores de codificación</description>
<syntax>xml2EncAlias <var>charset alias [alias ...]</var></syntax>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Esta directiva, de ámbito para todo el servidor, asocia (alias) una o más codificaciones a otra
    codificación. Esto permite que codificaciones no reconocidas por libxml2 se gestionen
    internamente mediante el soporte de codificación de libxml2 usando la tabla de traducción
    de una codificación reconocida. Esto tiene dos propósitos: admitir juegos de caracteres
    (o nombres) no reconocidos ni por libxml2 ni por iconv, y omitir la
    conversión en una codificación donde se sabe que es innecesaria.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>xml2StartParse</name>
<description>Indica al analizador que omita la basura inicial.</description>
<syntax>xml2StartParse <var>element [element ...]</var></syntax>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context><context>.htaccess</context></contextlist>
<override>All</override>

<usage>
    <p>Especifica que el analizador de marcado debe comenzar en la primera instancia
    de cualquiera de los elementos especificados. Esto puede usarse como solución temporal
    cuando un backend defectuoso inserta basura inicial que estropea el analizador (<a
    href="http://bahumbug.wordpress.com/2006/10/12/mod_proxy_html-revisited/"
    >ejemplo aquí</a>).</p>
    <p>Nunca debe usarse para XML, ni para HTML bien formado.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
