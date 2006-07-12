<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 421174 -->

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

<manualpage metafile="server-wide.xml.meta">

  <title>Configuraci&#243;n global del servidor</title>

<summary>
<p>Este documento explica algunas directivas del <module>core</module>
(n&#250;cleo) de Apache que se usan para configurar las operaciones
b&#225;sicas del servidor.</p>
</summary>

  <section id="identification">
    <title>Identificaci&#243;n del Servidor</title>

    <related>
      <directivelist>
        <directive module="core">ServerName</directive>
        <directive module="core">ServerAdmin</directive>
        <directive module="core">ServerSignature</directive>
        <directive module="core">ServerTokens</directive>
        <directive module="core">UseCanonicalName</directive>
      </directivelist>
    </related>

    <p>Las directivas <directive module="core">ServerAdmin</directive>
    y <directive module="core">ServerTokens</directive> controlan
    qu&#233; informaci&#243;n relativa al servidor que se est&#225;
    ejecutando ser&#225; incluida en los documentos generados por el
    servidor, por ejemplo en los mensajes de error. La directiva
    <directive module="core">ServerTokens</directive> especifica el
    valor del campo cabecera de las respuestas HTTP del servidor.</p>

    <p>Las directivas <directive module="core">ServerName</directive>
    y <directive module="core">UseCanonicalName</directive> las usa el
    servidor para determinar c&#243;mo construir URLs
    autorreferenciadas. Por ejemplo, cuando un cliente hace una
    petici&#243;n a un directorio, pero no incluye una barra final
    despu&#233;s del nombre del directorio, Apache debe redirigir al
    cliente a la ubicaci&#243;n que corresponda con el nombre completo
    del directorio incluyendo la barra que deber&#237;a haber puesto
    al final. De esta manera el cliente puede resolver correctamente
    las referencias relativas en el documento.</p>
  </section>

  <section id="locations">
    <title>Ubicaci&#243;n de ficheros</title>

    <related>
      <directivelist>
        <directive module="mpm_common">CoreDumpDirectory</directive>
        <directive module="core">DocumentRoot</directive>
        <directive module="core">ErrorLog</directive>
        <directive module="mpm_common">LockFile</directive>
        <directive module="mpm_common">PidFile</directive>
        <directive module="mpm_common">ScoreBoardFile</directive>
        <directive module="core">ServerRoot</directive>
      </directivelist>
    </related>

    <p>Estas directivas controlan las ubicaciones de varios ficheros
    que Apache necesita para funcionar correctamente. Cuando se
    especifica una ruta que no empieza por una barra (/), se asume que
    la ruta usada es relativa al directorio especificado en <directive
    module="core">ServerRoot</directive>. Tenga cuidado con poner
    ficheros en rutas en las que tengan permisos de escritura usuarios
    que no sean root.  Consulte la documentaci&#243;n sobre <a
    href="misc/security_tips.html#serverroot">consejos de
    seguridad</a> para obtener m&#225;s informaci&#243;n.</p>
  </section>

  <section id="resource">
    <title>L&#237;mite en el uso de recursos</title>

    <related>
      <directivelist>
        <directive module="core">LimitRequestBody</directive>
        <directive module="core">LimitRequestFields</directive>
        <directive module="core">LimitRequestFieldsize</directive>
        <directive module="core">LimitRequestLine</directive>
        <directive module="core">RLimitCPU</directive>
        <directive module="core">RLimitMEM</directive>
        <directive module="core">RLimitNPROC</directive>
        <directive module="mpm_netware">ThreadStackSize</directive>
      </directivelist>
    </related>

    <p>Las directivas <directive>LimitRequest</directive>* se usan
    para poner l&#237;mites en la cantidad de recursos que Apache
    utilizar&#225; leyendo peticiones de clientes. Limitando esos
    valores, se pueden evitar algunos tipos de ataque de
    denegaci&#243;n de servicio.</p>

    <p>Las directivas <directive>RLimit</directive>* se usan para
    limitar la cantidad de recursos que pueden utilizarse por procesos
    nacidos de la clonaci&#243;n de procesos hijo de Apache. En
    particular, esto controlar&#225; los recursos usados por los
    script CGI y por los comandos de ejecuci&#243;n SSI.</p>

    <p>La directiva <directive
    module="mpm_netware">ThreadStackSize</directive> se usa solamente
    en Netware para controlar el tama&#241;o de la pila de
    ejecuci&#243;n.</p>
  </section>
</manualpage>
