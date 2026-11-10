<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1174747 -->
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

<modulesynopsis metafile="mod_nw_ssl.xml.meta">

<name>mod_nw_ssl</name>
<description>Activa el cifrado SSL para NetWare</description>
<status>Base</status>
<sourcefile>mod_nw_ssl.c</sourcefile>
<identifier>nwssl_module</identifier>
<compatibility>Solo NetWare</compatibility>

<summary>
    <p>Este módulo activa el cifrado SSL para un puerto especificado. Aprovecha
    la funcionalidad de cifrado SSL que está integrada en el
    sistema operativo NetWare.</p>
</summary>

<directivesynopsis>
<name>SecureListen</name>
<description>Activa el cifrado SSL para el puerto especificado</description>
<syntax>SecureListen [<var>IP-address</var>:]<var>portnumber</var>
<var>Certificate-Name</var> [MUTUAL]</syntax>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Especifica el puerto y el nombre del certificado basado en eDirectory
    que se usará para activar el cifrado SSL. Un tercer parámetro
    opcional activa además la autenticación mutua.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>NWSSLTrustedCerts</name>
<description>Lista de certificados de cliente adicionales</description>
<syntax>NWSSLTrustedCerts <var>filename</var> [<var>filename</var>] ...</syntax>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Especifica una lista de archivos de certificado de cliente (en formato DER)
    que se usan al crear una conexión SSL mediante proxy. Cada
    certificado de cliente usado por un servidor debe figurar por separado
    en su propio archivo <code>.der</code>.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>NWSSLUpgradeable</name>
<description>Permite actualizar una conexión a una conexión SSL cuando se solicite</description>
<syntax>NWSSLUpgradeable [<var>IP-address</var>:]<var>portnumber</var></syntax>
<contextlist><context>server config</context></contextlist>

<usage>
    <p>Permite que una conexión creada en la dirección y/o puerto
    especificados pueda actualizarse a una conexión SSL cuando el
    cliente lo solicite. La dirección y/o el puerto deben haberse
    definido previamente con una directiva
    <directive module="mpm_common">Listen</directive>.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
