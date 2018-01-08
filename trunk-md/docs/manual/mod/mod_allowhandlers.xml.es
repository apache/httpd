<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1673892 -->
<!-- Spanish Translation: Daniel Ferradal <dferradal@apache.org> -->

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

<modulesynopsis metafile="mod_allowhandlers.xml.meta">
<name>mod_allowhandlers</name>
<description>Restringir fácilmente qué handlers HTTP pueden ser usados en el servidor</description>
<status>Experimental</status>
<sourcefile>mod_allowhandlers.c</sourcefile>
<identifier>allowhandlers_module</identifier>


<summary>
<p>Éste módulo hace que sea fácil restringir qué handlers podrían usarse para una petición. Una posible configuración sería:</p>

<highlight language="config">
&lt;Location "/"&gt;
  AllowHandlers not server-info server-status balancer-manager ldap-status
&lt;/Location&gt;
</highlight>

<p>También registra un handler llamado <code>forbidden</code> que sencillamente devuelve 403 FORBIDDEN al cliente. Esto se puede usar con directivas como
<directive module="mod_mime">AddHandler</directive>.</p>

</summary>

<seealso><directive module="core">SetHandler</directive></seealso>
<seealso><directive module="mod_mime">AddHandler</directive></seealso>

<directivesynopsis>
<name>AllowHandlers</name>
<description>Restringe acceso a los handlers listados</description>
<syntax>AllowHandlers [not] none|<em>handler-name</em>
[none|<em>handler-name</em>]...</syntax>
<default>AllowHandlers all</default>
<contextlist><context>directory</context></contextlist>
<status>Experimental</status>

<usage>

<p>Los nombres de handler son sensibles a mayúsculas. El nombre especial
<code>none</code> puede usarse para hacer coincidir mayúsculas donde no se ha configurado ningún handler. El valor especial <code>all</code> puede usarse para permitir todos los handlers otra vez en una sección de configuración posterior, incluso si algunas cabeceras fueron denegadas previamente en el orden de fusión de la configuración:</p>

<highlight language="config">
&lt;Location "/server-status"&gt;
  AllowHandlers all
  SetHandler server-status
&lt;/Location&gt;
</highlight>

</usage>
</directivesynopsis>

</modulesynopsis>
