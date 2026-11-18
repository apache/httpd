<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933503 -->
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

<modulesynopsis metafile="mod_ident.xml.meta">

<name>mod_ident</name>
<description>Consultas ident según RFC 1413</description>
<status>Extension</status>
<sourcefile>mod_ident.c</sourcefile>
<identifier>ident_module</identifier>
<compatibility>Disponible en Apache 2.1 y posteriores</compatibility>

<summary>
    <p>Este módulo consulta un demonio compatible con <rfc>1413</rfc> en un host remoto para averiguar el propietario de
    una conexión.</p>
</summary>
<seealso><module>mod_log_config</module></seealso>

<directivesynopsis>
<name>IdentityCheck</name>
<description>Activa el registro de la identidad RFC 1413 del usuario
remoto</description>
<syntax>IdentityCheck On|Off</syntax>
<default>IdentityCheck Off</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<compatibility>Movida fuera del núcleo en Apache 2.1</compatibility>

<usage>
    <p>Esta directiva activa el registro conforme a <rfc>1413</rfc> del nombre de usuario remoto para cada
    conexión, cuando la máquina cliente ejecuta identd o algo similar.
    Esta información se registra en el log de acceso usando la cadena de formato
    <code>%...l</code> <a href="mod_log_config.html#formats">correspondiente</a>.</p>

    <note>
      Esta información no debe considerarse fiable, salvo para un
      seguimiento rudimentario de uso.
    </note>

    <p>Tenga en cuenta que esto puede causar graves problemas de latencia al
    acceder a su servidor, ya que cada petición requiere realizar una de estas
    consultas. Cuando hay cortafuegos o servidores proxy de por medio,
    cada consulta puede fallar y añadir una duración de latencia tal como
    la define la directiva <directive module="mod_ident"
    >IdentityCheckTimeout</directive> a cada petición. Por eso, en
    general esto no resulta muy útil en servidores públicos accesibles desde
    Internet.</p>
</usage>
</directivesynopsis>

<directivesynopsis>
<name>IdentityCheckTimeout</name>
<description>Determina la duración del tiempo de espera para las peticiones ident</description>
<syntax>IdentityCheckTimeout <var>seconds</var></syntax>
<default>IdentityCheckTimeout 30</default>
<contextlist><context>server config</context><context>virtual host</context>
<context>directory</context></contextlist>
<usage>
    <p>Esta directiva especifica la duración del tiempo de espera de una petición
    ident. El valor por defecto de 30 segundos es el recomendado por <rfc>1413</rfc>, principalmente debido
    a la posible latencia de red. No obstante, puede que desee ajustar el
    valor del tiempo de espera según la velocidad de su red local.</p>
</usage>
</directivesynopsis>

</modulesynopsis>
