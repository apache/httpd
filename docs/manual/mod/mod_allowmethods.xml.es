<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1717786:1883203 (outdated) -->
<!-- Spanish Translation: Daniel Ferradal <dferradal@apache.org> -->

<!--
Upon adding a new module XML doc, you will need to:

svn ps svn:eol-style native <alltextfiles>
svn ps svn:keywords LastChangedRevision mod_allowmethods.xml

in order for it to rebuild correctly.

-->

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

<modulesynopsis metafile="mod_allowmethods.xml.meta">
<name>mod_allowmethods</name>
<description>Restringe fácilmente qué métodos HTTP pueden ser usados en el servidor</description>
<status>Experimental</status>
<sourcefile>mod_allowmethods.c</sourcefile>
<identifier>allowmethods_module</identifier>


<summary>
<p>Éste módulo hace fácil restringir qué métodos pueden ser usados en el servidor. 
	La configuración más común sería:</p>

<highlight language="config">
&lt;Location "/"&gt;
   AllowMethods GET POST OPTIONS
&lt;/Location&gt;
</highlight>

</summary>

<directivesynopsis>
<name>AllowMethods</name>
<description>Restringe acceso a los métodos HTTP indicados</description>
<syntax>AllowMethods reset|<em>HTTP-method</em>
[<em>HTTP-method</em>]...</syntax>
<default>AllowMethods reset</default>
<contextlist><context>directory</context></contextlist>
<status>Experimental</status>

<usage>

<p>Los métodos HTTP son sensibles a mayúsculas y son generalmente, según RFC, indicados en mayúsculas. Los métodos GET y HEAD se tratan como equivalentes. La palabra clave <code>reset</code> puede ser usada para desactivar
 <module>mod_allowmethods</module> en un contexto anidado más profundo:</p>

<highlight language="config">
&lt;Location "/svn"&gt;
   AllowMethods reset
&lt;/Location&gt;
</highlight>

<note><title>Precaución</title>
  <p>No se puede restringir el método TRACE con este módulo;
  use <directive module="core">TraceEnable</directive> en su lugar.</p>
</note>

<p><module>mod_allowmethods</module> fue escrito para reemplazar la implementación más engorrosa de
<directive module="core">Limit</directive> y
<directive module="core">LimitExcept</directive>.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
