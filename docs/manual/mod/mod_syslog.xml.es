<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1673945 -->
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

<modulesynopsis metafile="mod_syslog.xml.meta">

<name>mod_syslog</name>
<description>Proporciona el proveedor de ErrorLog "syslog"</description>
<status>Extension</status>
<sourcefile>mod_syslog.c</sourcefile>
<identifier>syslog_module</identifier>

<summary>

    <p>Este módulo proporciona el proveedor de ErrorLog "syslog". Permite
    registrar mensajes de error mediante syslogd(8).</p>
</summary>

<section id="examples">
    <title>Ejemplos</title>

    <p>Usar <code>syslog</code> en la directiva ErrorLog (vea <module>core</module>)
    en lugar de un nombre de archivo activa el registro mediante syslogd(8) si el sistema lo admite.
    Por defecto se usa la facility de syslog <code>local7</code>,
    pero puede cambiarla usando la sintaxis <code>syslog:<var>facility</var></code>,
    donde <var>facility</var> puede ser uno de los nombres documentados habitualmente en
    syslog(1). La facility es, en la práctica, global, y si se cambia
    en hosts virtuales concretos, la última facility especificada afecta a
    todo el servidor.</p>

    <highlight language="config">
ErrorLog syslog:user
    </highlight>

</section>


</modulesynopsis>
