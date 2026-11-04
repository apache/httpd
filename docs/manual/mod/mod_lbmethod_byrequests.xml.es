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

<modulesynopsis metafile="mod_lbmethod_byrequests.xml.meta">

<name>mod_lbmethod_byrequests</name>
<description>Algoritmo de planificación del balanceador de carga por conteo de peticiones para <module
>mod_proxy_balancer</module></description>
<status>Extension</status>
<sourcefile>mod_lbmethod_byrequests.c</sourcefile>
<identifier>lbmethod_byrequests_module</identifier>
<compatibility>Separado de <module>mod_proxy_balancer</module> en la versión 2.3</compatibility>

<summary>
<p>Este módulo no proporciona directivas de configuración propias.
Requiere los servicios de <module>mod_proxy_balancer</module>, y
proporciona el método de balanceo de carga <code>byrequests</code>.</p>
</summary>
<seealso><module>mod_proxy</module></seealso>
<seealso><module>mod_proxy_balancer</module></seealso>

<section id="requests">
    <title>Algoritmo de conteo de peticiones</title>
    <p>Activado mediante <code>lbmethod=byrequests</code>, la idea detrás de este
    planificador es distribuir las peticiones entre los
    distintos workers para garantizar que cada uno recibe la parte
    configurada del número de peticiones. Funciona de la siguiente manera:</p>

    <p><dfn>lbfactor</dfn> es <em>cuánto esperamos que trabaje este worker</em>,
    o <em>la cuota de trabajo del worker</em>. Es
    un valor normalizado que representa su "parte" de la cantidad de
    trabajo a realizar.</p>

    <p><dfn>lbstatus</dfn> es <em>con cuánta urgencia tiene que trabajar este worker
    para cumplir su cuota de trabajo</em>.</p>

    <p>El <dfn>worker</dfn> es un miembro del balanceador de carga,
    normalmente un host remoto que ofrece uno de los protocolos admitidos.</p>

    <p>Distribuimos la cuota de trabajo de cada worker al worker, y luego miramos
    cuál de ellos necesita trabajar más urgentemente (el lbstatus más alto). Este
    worker se selecciona entonces para trabajar, y su lbstatus se reduce en la
    cuota total de trabajo que distribuimos entre todos los workers. Así, la suma de todos
    los lbstatus no cambia(*) y distribuimos las peticiones
    según lo deseado.</p>

    <p>Si algunos workers están desactivados, los demás
    seguirán siendo planificados correctamente.</p>

    <example><pre><code>for each worker in workers
    worker lbstatus += worker lbfactor
    total factor    += worker lbfactor
    if worker lbstatus > candidate lbstatus
        candidate = worker

candidate lbstatus -= total factor</code></pre>
    </example>

    <p>Si un balanceador se configura de la siguiente manera:</p>

    <table style="data">
    <tr><th>worker</th>
        <th>a</th>
        <th>b</th>
        <th>c</th>
        <th>d</th></tr>
    <tr><th>lbfactor</th>
        <td>25</td>
        <td>25</td>
        <td>25</td>
        <td>25</td></tr>
    <tr><th>lbstatus</th>
        <td>0</td>
        <td>0</td>
        <td>0</td>
        <td>0</td></tr>
    </table>

    <p>Y <var>b</var> se desactiva, se produce la siguiente planificación:</p>

    <table style="data">
    <tr><th>worker</th>
        <th>a</th>
        <th>b</th>
        <th>c</th>
        <th>d</th></tr>
    <tr><th>lbstatus</th>
        <td><em>-50</em></td>
        <td>0</td>
        <td>25</td>
        <td>25</td></tr>
    <tr><th>lbstatus</th>
        <td>-25</td>
        <td>0</td>
        <td><em>-25</em></td>
        <td>50</td></tr>
    <tr><th>lbstatus</th>
        <td>0</td>
        <td>0</td>
        <td>0</td>
        <td><em>0</em></td></tr>
    <tr><td colspan="5">(se repite)</td></tr>
    </table>

    <p>Es decir, planifica: <var>a</var> <var>c</var> <var>d</var>
    <var>a</var> <var>c</var> <var>d</var> <var>a</var> <var>c</var>
    <var>d</var> ... Observe que:</p>

    <table style="data">
    <tr><th>worker</th>
        <th>a</th>
        <th>b</th>
        <th>c</th>
        <th>d</th></tr>
    <tr><th>lbfactor</th>
        <td>25</td>
        <td>25</td>
        <td>25</td>
        <td>25</td></tr>
    </table>

    <p>Tiene exactamente el mismo comportamiento que:</p>

    <table style="data">
    <tr><th>worker</th>
        <th>a</th>
        <th>b</th>
        <th>c</th>
        <th>d</th></tr>
    <tr><th>lbfactor</th>
        <td>1</td>
        <td>1</td>
        <td>1</td>
        <td>1</td></tr>
    </table>

    <p>Esto es porque todos los valores de <dfn>lbfactor</dfn> se normalizan
    con respecto a los demás. Para:</p>

    <table style="data">
    <tr><th>worker</th>
        <th>a</th>
        <th>b</th>
        <th>c</th></tr>
    <tr><th>lbfactor</th>
        <td>1</td>
        <td>4</td>
        <td>1</td></tr>
    </table>

    <p>el worker <var>b</var> recibirá, en promedio, 4 veces las peticiones
    que recibirán <var>a</var> y <var>c</var>.</p>

    <p>La siguiente configuración asimétrica funciona como se esperaría:</p>

    <table style="data">
    <tr><th>worker</th>
        <th>a</th>
        <th>b</th></tr>
    <tr><th>lbfactor</th>
        <td>70</td>
        <td>30</td></tr>
    <tr><td colspan="2">&nbsp;</td></tr>
    <tr><th>lbstatus</th>
        <td><em>-30</em></td>
        <td>30</td></tr>
    <tr><th>lbstatus</th>
        <td>40</td>
        <td><em>-40</em></td></tr>
    <tr><th>lbstatus</th>
        <td><em>10</em></td>
        <td>-10</td></tr>
    <tr><th>lbstatus</th>
        <td><em>-20</em></td>
        <td>20</td></tr>
    <tr><th>lbstatus</th>
        <td><em>-50</em></td>
        <td>50</td></tr>
    <tr><th>lbstatus</th>
        <td>20</td>
        <td><em>-20</em></td></tr>
    <tr><th>lbstatus</th>
        <td><em>-10</em></td>
        <td>10</td></tr>
    <tr><th>lbstatus</th>
        <td><em>-40</em></td>
        <td>40</td></tr>
    <tr><th>lbstatus</th>
        <td>30</td>
        <td><em>-30</em></td></tr>
    <tr><th>lbstatus</th>
        <td><em>0</em></td>
        <td>0</td></tr>
    <tr><td colspan="3">(se repite)</td></tr>
    </table>

    <p>Es decir, después de 10 planificaciones, la planificación se repite y se seleccionan 7 <var>a</var>
    con 3 <var>b</var> intercalados.</p>
</section>

</modulesynopsis>
