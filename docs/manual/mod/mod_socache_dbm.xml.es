<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1673947 -->
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

<modulesynopsis metafile="mod_socache_dbm.xml.meta">

<name>mod_socache_dbm</name>
<description>Proveedor de caché de objetos compartidos basado en DBM.</description>
<status>Extension</status>
<sourcefile>mod_socache_dbm.c</sourcefile>
<identifier>socache_dbm_module</identifier>

<summary>
    <p><code>mod_socache_dbm</code> es un proveedor de caché de objetos compartidos
    que permite crear y acceder a una caché respaldada por una
    base de datos DBM.
    </p>

    <example>
    dbm:/path/to/datafile
    </example>

    <p>Si la ruta no es absoluta, se asume que es relativa a
    <directive module="core">DefaultRuntimeDir</directive>.</p>

    <p>Puede encontrar los detalles de otros proveedores de caché de objetos compartidos
    <a href="../socache.html">aquí</a>.
    </p>

</summary>

</modulesynopsis>
