<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933687 -->
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

<modulesynopsis metafile="mod_authz_user.xml.meta">

<name>mod_authz_user</name>
<description>Autorización de usuario</description>
<status>Base</status>
<sourcefile>mod_authz_user.c</sourcefile>
<identifier>authz_user_module</identifier>

<summary>
    <p>Este módulo proporciona funcionalidades de autorización para que los
    usuarios autenticados puedan ser admitidos o rechazados en el acceso a partes
    del sitio web. <module>mod_authz_user</module> concede
    acceso si el usuario autenticado figura en una directiva <code>Require user</code>.
    Alternativamente, puede usarse <code>Require valid-user</code> para
    conceder acceso a todos los usuarios autenticados correctamente.</p>
</summary>
<seealso><directive module="mod_authz_core">Require</directive></seealso>
<seealso><a href="mod_authz_core.html#authzresults">Estados de resultado de autorización</a></seealso>

<section id="requiredirectives"><title>Las directivas Require</title>

    <p>Las directivas <directive module="mod_authz_core">Require</directive>
    de Apache se usan durante la fase de autorización para garantizar que
    un usuario tiene permitido el acceso a un recurso. mod_authz_user extiende
    los tipos de autorización con <code>user</code> y <code>valid-user</code>.
    </p>

    <p>Desde la versión 2.4.8, se admiten <a href="../expr.html">expresiones</a>
    dentro de las directivas require de usuario.</p>

<section id="requser"><title>Require user</title>

    <p>Esta directiva especifica una lista de usuarios a los que se permite
    el acceso.</p>

    <highlight language="config">
      Require user john paul george ringo
    </highlight>

</section>

<section id="reqvaliduser"><title>Require valid-user</title>

    <p>Cuando se especifica esta directiva, se permite el acceso a cualquier
    usuario autenticado correctamente.</p>

    <highlight language="config">
      Require valid-user
    </highlight>

</section>

</section>

</modulesynopsis>
