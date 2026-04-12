<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 1602764 $ -->
<!-- Translation Updated and Extended by: Daniel Ferradal -->

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

    <p>El servidor Apache HTTPD está diseñado para ser un servidor web potente
    y flexible que pueda funcionar en la más amplia variedad de
    plataformas y entornos. Las diferentes plataformas y los
    diferentes entornos, hacen que a menudo sean necesarias diferentes
    características o funcionalidades, o que una misma
    característica o funcionalidad sea implementada de diferente
    manera para obtener una mayor eficiencia. Apache httpd se ha adaptado
    siempre a una gran variedad de entornos a través de su
    diseño modular. Este diseño permite a los administradores de sitios web 
    elegir que características van a ser incluidas en el servidor seleccionando 
    que módulos se van a cargar, ya sea al compilar o al ejecutar el servidor.</p>

    <p>El servidor Apache HTTP 2.0 extiende este diseño modular hasta las
    funciones más básicas de un servidor web. El servidor
    viene con una serie de Módulos de MultiProcesamiento que son
    responsables de conectar con los puertos de red de la
    máquina, acceptar las peticiones, y generar los procesos hijo
    que se encargan de servirlas.</p>

    <p>La extensión del diseño modular a este nivel del
    servidor ofrece dos beneficios importantes:</p>

    <ul>
      <li>Apache httpd puede soportar de una forma más fácil y
      eficiente una amplia variedad de sistemas operativos. En
      concreto, la versión del servidor en Windows es mucho más
      eficiente, porque el módulo <module>mpm_winnt</module>
      puede usar funcionalidades nativas de red en lugar de usar la
      capa POSIX como hace Apache HTTPD 1.3. Este beneficio se extiende
      tambi&#233;n a otros sistemas operativos que implementan sus
      MPMs especializados.</li>

      <li>El servidor puede personalizarse mejor para las necesidades
      de cada sitio web. Por ejemplo, los sitios web que necesitan
      más que nada escalibildad pueden usar un MPM multihilo como
      <module>worker</module> o <module>event</module>, mientras que los sitios web que
      requieran por encima de otras cosas estabilidad o compatibilidad
      con software antiguo pueden usar <module>prefork</module>.
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

<table>
<columnspec><column width=".2"/><column width=".2"/></columnspec>
<tr><td>BeOS</td><td><module>beos</module></td></tr>
<tr><td>Netware</td><td><module>mpm_netware</module></td></tr>
<tr><td>OS/2</td><td><module>mpmt_os2</module></td></tr>
<tr><td>Unix</td><td><module>prefork</module></td></tr>
<tr><td>Windows</td><td><module>mpm_winnt</module></td></tr>
</table>

<note><p>Aquí, 'Unix' indicaba sistemas operativos tipo Unix, tales como
Linux, BSD, Solares, Mac OS X, etc.</p></note>

<p>En el caso de Unix, la decisiónd e qué MPM se debe instalar se basa
en dos preguntas:</p>
<p>1. ¿El sistema soporta hilos?</p>
<p>2. ¿El sistema soporta thread-safe polling (Especificamente, las funciones
kqueue y epoll)?</p>

<p>Si la respuesta a ambas preguntas es 'si', el MPM por defecto es
<module>event</module>.</p>

<p>Si la respuesta a #1 es 'si', pero la respues a #2 es 'no', el módulo por
defecto será <module>worker</module>.</p>

<p>Si la respuesta a ambas preguntas es 'no', entonces el MPM por defecto
será <module>prefork</module>.</p>

<p>En términos prácticos, esto significa que el valor por defecto casi siempre
será <module>event</module>, puesto que todos los sistemas operativos modernos
soportan estas dos características.</p>

</section>

<section id="static"><title>Compilando un MPM como módulo estático</title>

    <p>Los MPMs pueden ser compilados como módulos estáticos en todas las plataformas. 
    Un solo MPM es elegido en tiempo de compilación y se enlaza al servidor. El servidor
    debe ser recompilado para cambiar el MPM.</p>

    <p>Para anular la elección por defecto de MPM, usar la opción
    <code>--with-mpm=<em>NOMBRE</em></code> del script
    <program>configure</program>. <em>NOMBRE</em> es el nombre del MPM deseado.</p>

    <p>Una vez el servidor ha sido compilado, es posible determinar qué MPM fue elegido usando 
    <code>./httpd -l</code>. Este comando listará cada módulo compilado en el servidor
    incluyendo el MPM.</p>

</section>

<section id="dynamic"><title>Compilando un MPM como módulo DSO</title>

    <p>En Unix y plataformas similares, MPMs se pueden compilar como módulos
    DSO y ser cargados dinámicamente en el servidor de la misma forma que otros
    módulos DSO. Compilar MPMs como módulos DSO permite cambiar de MPM actualizando
    la directiva <directive module="mod_so">LoadModule</directive>
    para el MPM en lugar de tener que recompilar el servidor.</p>

    <highlight language="config">
    LoadModule mpm_prefork_module modules/mod_mpm_prefork.so
    </highlight>

    <p>Intentar usar <directive module="mod_so">LoadModule</directive>
    con más de un MPM dará como un fallo con el siguiente error.</p>

    <example>AH00534: httpd: Configuration error: More than one MPM
    loaded.</example>

    <p>Esta características se habilita con la opción 
    <code>--enable-mpms-shared</code> del script <program>configure</program>.
    Con el parámetro <code><em>all</em></code>, se instalaran todos los MPMs posibles
    en la plataforma.  Alternativamente, se puede especificar una lista de MPMs 
    como parámetro.</p>

    <p>El MPM por defecto, bien seleccionado automáticamente o especificado con la
    opción <code>--with-mpm</code> del script <program>configure</program>
    script, se cargaran en el fichero de configuración del servidor generado. 
    Editar la directiva <directive module="mod_so">LoadModule</directive> para seleccionar
    un MPM diferente.</p>

</section>

</manualpage>

