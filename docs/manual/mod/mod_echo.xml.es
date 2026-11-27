<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1421892 -->
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

<modulesynopsis metafile="mod_echo.xml.meta">

<name>mod_echo</name>
<description>Un sencillo servidor de eco para ilustrar los módulos de
protocolo</description>
<status>Experimental</status>
<sourcefile>mod_echo.c</sourcefile>
<identifier>echo_module</identifier>

<summary>
    <p>Este módulo proporciona un módulo de protocolo de ejemplo para ilustrar el
    concepto. Proporciona un sencillo servidor de eco. Conéctese mediante telnet y escriba
    cosas, y se las devolverá.</p>
</summary>

<directivesynopsis>

<name>ProtocolEcho</name>
<description>Activa o desactiva el servidor de eco</description>
<syntax>ProtocolEcho On|Off</syntax>
<default>ProtocolEcho Off</default>
<contextlist><context>server config</context>
<context>virtual host</context></contextlist>

<usage>
    <p>La directiva <directive>ProtocolEcho</directive> activa o
    desactiva el servidor de eco.</p>

    <example><title>Ejemplo</title>
    <highlight language="config">
      ProtocolEcho On
    </highlight>
    </example>
</usage>

</directivesynopsis>
</modulesynopsis>

