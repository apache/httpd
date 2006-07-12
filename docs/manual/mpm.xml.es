<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 105989:421100 (outdated) -->

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

<manualpage metafile="mpm.xml.meta">

  <title>M&#243;dulos de MultiProcesamiento (MPMs)</title>

<summary>
<p>Este documento describe que es un M&#243;dulo de Multiprocesamiento y
como los usa Apache.</p>
</summary>

<section id="introduction"><title>Introducci&#243;n</title>

    <p>Apache est&#225; dise&#241;ado para ser un servidor web potente
    y flexible que pueda funcionar en la m&#225;s amplia variedad de
    plataformas y entornos. Las diferentes plataformas y los
    diferentes entornos, hacen que a menudo sean necesarias diferentes
    caracter&#237;sticas o funcionalidades, o que una misma
    caracter&#237;stica o funcionalidad sea implementada de diferente
    manera para obtener una mayor eficiencia. Apache se ha adaptado
    siempre a una gran variedad de entornos a trav&#233;s de su
    dise&#241;o modular. Este dise&#241;o permite a los
    administradores de sitios web elegir que caracter&#237;sticas van
    a ser incluidas en el servidor seleccionando que m&#243;dulos se
    van a cargar, ya sea al compilar o al ejecutar el servidor.</p>

    <p>Apache 2.0 extiende este dise&#241;o modular hasta las
    funciones m&#225;s b&#225;sicas de un servidor web. El servidor
    viene con una serie de M&#243;dulos de MultiProcesamiento que son
    responsables de conectar con los puertos de red de la
    m&#225;quina, acceptar las peticiones, y generar los procesos hijo
    que se encargan de servirlas.</p>

    <p>La extensi&#243;n del dise&#241;o modular a este nivel del
    servidor ofrece dos beneficios importantes:</p>

    <ul>
      <li>Apache puede soportar de una forma m&#225;s f&#225;cil y
      eficiente una amplia variedad de sistemas operativos. En
      concreto, la versi&#243;n de Windows de Apache es mucho m&#225;s
      eficiente, porque el m&#243;dulo <module>mpm_winnt</module>
      puede usar funcionalidades nativas de red en lugar de usar la
      capa POSIX como hace Apache 1.3. Este beneficio se extiende
      tambi&#233;n a otros sistemas operativos que implementan sus
      respectivos MPMs.</li>

      <li>El servidor puede personalizarse mejor para las necesidades
      de cada sitio web. Por ejemplo, los sitios web que necesitan
      m&#225;s que nada escalibildad pueden usar un MPM hebrado como
      <module>worker</module>, mientras que los sitios web que
      requieran por encima de otras cosas estabilidad o compatibilidad
      con software antiguo pueden usar
      <module>prefork</module>. Adem&#225;s, se pueden configurar
      funcionalidades especiales como servir diferentes hosts con
      diferentes identificadores de usuario
      (<module>perchild</module>).</li>
    </ul>

    <p>A nivel de usuario, los MPMs son como cualquier otro
    m&#243;dulo de Apache. La diferencia m&#225;s importante es que
    solo un MPM puede estar cargado en el servidor en un determinado
    momento. La lista de MPMs disponibles est&#225; en la <a
    href="mod/">secci&#243;n &#237;ndice de M&#243;dulos</a>.</p>

</section>

<section id="choosing"><title>C&#243;mo Elegir un MPM</title>

    <p>Los MPMs deben elegirse durante el proceso de
    configuraci&#243;n, y deben ser compilados en el servidor. Los
    compiladores son capaces de optimizar muchas funciones si se usan
    hebras, pero solo si se sabe que se est&#225;n usando hebras. Como
    algunos MPM usan hebras en Unix y otros no, Apache tendr&#225; un
    mejor rendimiento si el MPM es elegido en el momento de compilar y
    est&#225; incorporado en el servidor.</p>

    <p>Para elegir el MPM deseado, use el argumento --with-mpm=
    <em>NAME</em> con el script ./configure.  <em>NAME</em> es el
    nombre del MPM deseado.</p>

    <p>Una vez que el servidor ha sido compilado, es posible
    determinar que MPM ha sido elegido usando <code>./httpd
    -l</code>. Este comando lista todos los m&#243;dulos compilados en
    el servidor, incluido en MPM.</p>
</section>

<section id="defaults"><title>MPM por defecto</title>

<p>En la siguiente tabla se muestran los MPMs por defecto para varios
sistemas operativos.  Estos ser&#225;n los MPM seleccionados si no se
especifica lo contrario al compilar.</p>

<table>
<columnspec><column width=".2"/><column width=".2"/></columnspec>
<tr><td>BeOS</td><td><module>beos</module></td></tr>
<tr><td>Netware</td><td><module>mpm_netware</module></td></tr>
<tr><td>OS/2</td><td><module>mpmt_os2</module></td></tr>
<tr><td>Unix</td><td><module>prefork</module></td></tr>
<tr><td>Windows</td><td><module>mpm_winnt</module></td></tr>
</table>
</section>

</manualpage>

