<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1829613 -->
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

<modulesynopsis metafile="mod_lbmethod_bytraffic.xml.meta">

<name>mod_lbmethod_bytraffic</name>
<description>Algoritmo de planificación del balanceador de carga por conteo ponderado de tráfico para <module
>mod_proxy_balancer</module></description>
<status>Extension</status>
<sourcefile>mod_lbmethod_bytraffic.c</sourcefile>
<identifier>lbmethod_bytraffic_module</identifier>
<compatibility>Separado de <module>mod_proxy_balancer</module> en la versión 2.3</compatibility>

<summary>
<p>Este módulo no proporciona ninguna directiva de configuración propia.
Requiere los servicios de <module>mod_proxy_balancer</module>, y
proporciona el método de balanceo de carga <code>bytraffic</code>.</p>
</summary>
<seealso><module>mod_proxy</module></seealso>
<seealso><module>mod_proxy_balancer</module></seealso>

<section id="traffic">
    <title>Algoritmo de conteo ponderado de tráfico</title>
    <p>Activado mediante <code>lbmethod=bytraffic</code>, la idea detrás de este
    planificador es muy similar al método de conteo de peticiones, con
    los siguientes cambios:</p>

    <p><dfn>lbfactor</dfn> es <em>cuánto tráfico, en bytes, queremos
    que maneje este worker</em>. Este es también un valor normalizado
    que representa su "cuota" de la cantidad de trabajo a realizar,
    pero en lugar de simplemente contar el número de peticiones, se tiene
    en cuenta la cantidad de tráfico que este worker ha recibido
    o generado.</p>

    <p>Si un balanceador está configurado de la siguiente forma:</p>

    <table style="data">
    <tr><th>worker</th>
        <th>a</th>
        <th>b</th>
        <th>c</th></tr>
    <tr><th>lbfactor</th>
        <td>1</td>
        <td>2</td>
        <td>1</td></tr>
    </table>

    <p>Entonces queremos decir que deseamos que <var>b</var> procese el doble
    de bytes que <var>a</var> o <var>c</var>. Esto no significa
    necesariamente que <var>b</var> vaya a manejar el doble de
    peticiones, sino que procesará el doble de E/S. Así, el
    tamaño de la petición y de la respuesta se aplican al algoritmo
    de ponderación y selección.</p>

    <p>Nota: los bytes de entrada y de salida se ponderan igual.</p>

</section>

</modulesynopsis>
