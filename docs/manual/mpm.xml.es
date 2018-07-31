<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 1602766 -->
<!-- Reviewed by Luis Gil de Bernabé Pfeiffer--> 

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

  <title>Módulos de MultiProcesamiento (MPMs)</title>

<summary>
<p>Este documento describe que es un Módulo de Multiprocesamiento y
como los usa Apache.</p>
</summary>

<section id="introduction"><title>Introducción</title>

    <p>Apache está diseñado para ser un servidor web potente
    y flexible que pueda funcionar en la más amplia variedad de
    plataformas y entornos. Las diferentes plataformas y los
    diferentes entornos, hacen que a menudo sean necesarias diferentes
    características o funcionalidades, o que una misma
    característica o funcionalidad sea implementada de diferente
    manera para obtener una mayor eficiencia. Apache se ha adaptado
    siempre a una gran variedad de entornos a través de su
    diseño modular. Este diseño permite a los
    administradores de sitios web elegir que características van
    a ser incluidas en el servidor seleccionando que módulos se
    van a cargar, ya sea al compilar o en tiempo de ejecución.</p>

    <p>Apache 2.0 extiende este diseño modular hasta las
    funciones más básicas de un servidor web. El servidor
    viene con una serie de Módulos de MultiProcesamiento que son
    responsables de conectar con los puertos de red de la
    máquina, aceptar las peticiones, y generar los procesos hijo
    que se encargan de servirlas.</p>

    <p>La extensión del diseño modular a este nivel del
    servidor ofrece dos beneficios importantes:</p>

    <ul>
      <li>Apache puede soportar de una forma más fácil y
      eficiente una amplia variedad de sistemas operativos. En
      concreto, la versión de Windows de Apache es mucho más
      eficiente, porque el módulo <module>mpm_winnt</module>
      puede usar funcionalidades nativas de red en lugar de usar la
      capa POSIX como hace Apache 1.3. Este beneficio se extiende
      también a otros sistemas operativos que implementan sus
      respectivos MPMs.</li>

      <li>El servidor puede personalizarse mejor para las necesidades
      de cada sitio web. Por ejemplo, los sitios web que necesitan
      más que nada escalabilidad pueden usar un proceso MPM como
      <module>worker</module>, mientras que los sitios web que
      requieran por encima de otras cosas estabilidad o compatibilidad
      con software antiguo pueden usar
      <module>prefork</module>.
      </li>
    </ul>

    <p>A nivel de usuario, los MPMs son como cualquier otro
    módulo de Apache. La diferencia más importante es que
    solo un MPM puede estar cargado en el servidor en un determinado
    momento. La lista de MPMs disponibles está en la <a
    href="mod/">sección índice de Módulos</a>.</p>

</section>

<section id="defaults"><title>MPM por defecto</title>

<p>En la siguiente tabla se muestran los MPMs por defecto para varios
sistemas operativos.  Estos serán los MPM seleccionados si no se
especifica lo contrario al compilar.</p>

<table border="1" style="zebra">
<columnspec><column width=".2"/><column width=".2"/></columnspec>
<tr><td>Netware</td><td><module>mpm_netware</module></td></tr>
<tr><td>OS/2</td><td><module>mpmt_os2</module></td></tr>
<tr><td>Unix</td><td><module>prefork</module>, <module>worker</module>, or
    <module>event</module>, depending on platform capabilities</td></tr>
<tr><td>Windows</td><td><module>mpm_winnt</module></td></tr>
</table>

<note><p>aquí, 'Unix' se usa para designar a los sistemas operativos "Unix-like", como
Linux, BSD, Solaris, Mac OS X, etc.</p></note>

<p>En el caso de los Unix, la decisión de que MPM se va a instalar
  depende de dos pregunas:</p>
<p>1. ¿Nos permite el Sistema Operativo hilos?</p>
<p>2. -¿Nos permite el sistema operativo soporte a pila de hilos seguros 
  (Especificamente, las funciones kqueue y epoll)?</p>
</section>

</manualpage>

