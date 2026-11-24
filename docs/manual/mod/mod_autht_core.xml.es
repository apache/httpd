<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1909411 -->
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

<modulesynopsis metafile="mod_autht_core.xml.meta">

<name>mod_autht_core</name>
<description>Gestión básica de tokens</description>
<status>Base</status>
<sourcefile>mod_autht_core.c</sourcefile>
<identifier>autht_core_module</identifier>
<compatibility>Disponible en Apache 2.5 y posteriores</compatibility>

<summary>
    <p>Este módulo proporciona capacidades básicas de gestión de tokens para
    permitir o denegar el acceso a partes del sitio web.
    <module>mod_autht_core</module> proporciona directivas comunes
    a todos los proveedores de tokens.</p>
</summary>

<section id="authtalias"><title>Creación de alias de proveedores de tokens</title>

    <p>Se pueden crear proveedores de tokens extendidos dentro del archivo
    de configuración y asignarles un nombre de alias. Los proveedores con alias se pueden
    referenciar entonces mediante la directiva
    <directive module="mod_auth_bearer">AuthBearerProvider</directive>
    del mismo modo que un proveedor de tokens básico. Además de la
    posibilidad de crear y asignar un alias a un proveedor extendido, también permite
    que el mismo proveedor de tokens extendido se referencie desde varias
    ubicaciones.</p>

    <section id="example"><title>Ejemplos</title>

        <p>Este ejemplo comprueba las firmas de tokens JWT en dos archivos
        secretos distintos.</p>

        <example><title>Comprobar varias fuentes de tokens JWT</title>
        <highlight language="config">
# Comprobar primero aquí
&lt;AuthtProviderAlias jwt jwt1&gt;
    AuthtJwtVerify hs256 file "/www/conf/realm1.secret"
&lt;/AuthtProviderAlias&gt;

# Luego comprobar aquí
&lt;AuthtProviderAlias jwt jwt2&gt;
    AuthtJwtVerify hs256 file "/www/conf/realm2.secret"
&lt;/AuthtProviderAlias&gt;

&lt;Directory "/var/web/pages/secure"&gt;
    AuthBearerProvider jwt1 jwt2

    AuthType Basic
    AuthName "Protected Area"
    Require valid-user
&lt;/Directory&gt;
        </highlight>
        </example>

    </section>

</section>

<directivesynopsis type="section">
<name>AuthtProviderAlias</name>
<description>Engloba un grupo de directivas que representan una
extensión de un proveedor de tokens básico y se referencian mediante el
alias especificado</description>
<syntax>&lt;AuthtProviderAlias <var>baseProvider Alias</var>&gt;
... &lt;/AuthtProviderAlias&gt;</syntax>
<contextlist><context>server config</context>
</contextlist>

<usage>
    <p><code>&lt;AuthtProviderAlias&gt;</code> y
    <code>&lt;/AuthtProviderAlias&gt;</code> se usan para englobar un grupo de
    directivas de autenticación que se pueden referenciar mediante el nombre de alias
    usando
    <directive module="mod_auth_bearer">AuthBearerProvider</directive>.</p>

    <note>Esta directiva no afecta a la autenticación ni a la autorización,
    incluso en los módulos que proporcionan autenticación y autorización
    además de la gestión de tokens.</note>
</usage>
</directivesynopsis>

</modulesynopsis>
