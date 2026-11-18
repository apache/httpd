<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1174718 -->
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

<modulesynopsis metafile="mod_lbmethod_bybusyness.xml.meta">

<name>mod_lbmethod_bybusyness</name>
<description>Algoritmo de balanceo de carga por conteo de peticiones pendientes para <module
>mod_proxy_balancer</module></description>
<status>Extension</status>
<sourcefile>mod_lbmethod_bybusyness.c</sourcefile>
<identifier>lbmethod_bybusyness_module</identifier>
<compatibility>Separado de <module>mod_proxy_balancer</module> en la versión 2.3</compatibility>

<summary>
<p>Este módulo no proporciona directivas de configuración propias.
Requiere los servicios de <module>mod_proxy_balancer</module>, y
proporciona el método de balanceo de carga <code>bybusyness</code>.</p>
</summary>
<seealso><module>mod_proxy</module></seealso>
<seealso><module>mod_proxy_balancer</module></seealso>

<section id="busyness">

    <title>Algoritmo de conteo de peticiones pendientes</title>

    <p>Activado mediante <code>lbmethod=bybusyness</code>, este planificador mantiene
    el control de cuántas peticiones tiene asignadas actualmente cada worker. Una nueva
    petición se asigna automáticamente al worker con el menor
    número de peticiones activas. Esto es útil en el caso de workers
    que encolan las peticiones entrantes de forma independiente de Apache, para garantizar que
    la longitud de la cola se mantenga equilibrada y que una petición se asigne siempre al worker
    con más probabilidades de atenderla más rápido y reducir la latencia.</p>

    <p>En el caso de que haya varios workers igualmente ocupados, se usan las estadísticas (y
    las ponderaciones) empleadas por el método de conteo de peticiones para deshacer el
    empate. Con el tiempo, la distribución del trabajo llegará a asemejarse a la
    característica de <code>byrequests</code> (tal como la implementa
    <module>mod_lbmethod_byrequests</module>).</p>

</section>

</modulesynopsis>
