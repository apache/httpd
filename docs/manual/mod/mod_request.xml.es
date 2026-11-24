<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933850 -->
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

<modulesynopsis metafile="mod_request.xml.meta">

<name>mod_request</name>
<description>Filtros para gestionar y poner a disposición los cuerpos de las peticiones HTTP</description>
<status>Base</status>
<sourcefile>mod_request.c</sourcefile>
<identifier>request_module</identifier>
<compatibility>Disponible en Apache 2.3 y posteriores</compatibility>

<directivesynopsis>
<name>KeptBodySize</name>
<description>Conserva el cuerpo de la petición en lugar de descartarlo hasta
el tamaño máximo especificado, para su posible uso por filtros como
mod_include.</description>
<syntax>KeptBodySize <var>maximum size in bytes</var></syntax>
<default>KeptBodySize 0</default>
<contextlist><context>directory</context>
</contextlist>

<usage>
    <p>En circunstancias normales, los manejadores de peticiones, como el
    manejador por defecto para archivos estáticos, descartan el cuerpo de la
    petición cuando el manejador de la petición no lo necesita. Como resultado,
    filtros como mod_include se limitan a realizar peticiones <code>GET</code>
    únicamente al incluir otras URLs como subpeticiones, incluso si la
    petición original era una petición <code>POST</code>, ya que el cuerpo de
    la petición descartado ya no está disponible una vez que se está
    procesando el filtro.</p>

    <p>Cuando esta directiva tiene un valor mayor que cero, los manejadores de
    peticiones que de otro modo descartarían los cuerpos de las peticiones
    los reservarán en su lugar para su uso por los filtros, hasta
    el tamaño máximo especificado. En el caso del filtro mod_include,
    un intento de hacer un <code>POST</code> a un archivo shtml estático
    hará que cualquier subpetición sea una petición <code>POST</code>,
    en lugar de una petición <code>GET</code> como antes.</p>

    <p>Esta funcionalidad permite dividir páginas web y aplicaciones web
    complejas en pequeños componentes individuales, y combinar
    esos componentes junto con la estructura de la página web que los rodea
    usando <module>mod_include</module>. Los componentes pueden tomar la
    forma de programas CGI, lenguajes de script, o URLs redirigidas mediante
    proxy inverso al espacio de URLs desde otro servidor usando
    <module>mod_proxy</module>.</p>

    <note>Cada petición reservada tiene que
    guardarse temporalmente en RAM hasta que la petición se complete. Como
    resultado, debe tenerse cuidado de asegurar que haya suficiente RAM
    disponible en el servidor para soportar la carga prevista. El uso de esta
    directiva debería limitarse a las partes concretas de su espacio de
    URLs donde sea necesario, y con el valor más bajo posible que siga siendo
    suficientemente grande para contener el cuerpo de una petición.</note>

    <p>Si el tamaño de la petición enviada por el cliente excede el tamaño
    máximo asignado por esta directiva, el servidor devolverá
    <code>413 Request Entity Too Large</code>.</p>

</usage>

<seealso><a href="mod_include.html">la documentación de mod_include</a></seealso>
<seealso><a href="mod_auth_form.html">la documentación de mod_auth_form</a></seealso>
</directivesynopsis>

</modulesynopsis>
