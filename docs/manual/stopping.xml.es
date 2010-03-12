<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 105989:922234 (outdated) -->

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

<manualpage metafile="stopping.xml.meta">

  <title>Iniciar y Parar el servidor Apache</title>

<summary>
    <p>Este documento explica como iniciar y parar el servidor Apache
     en sistemas tipo Unix. Los usuarios de Windows NT, 2000 y XP
     deben consultar la secci&#243;n <a
     href="platform/windows.html#winsvc">Ejecutar Apache como un
     servicio</a> y los usuario de Windows 9x y ME deben consultar <a
     href="platform/windows.html#wincons">Ejecutar Apache como una
     Aplicaci&#243;n de Consola</a> para obtener informaci&#243;n
     sobre como controlar Apache en esas plataformas.</p>
</summary>

<seealso><a href="programs/httpd.html">httpd</a></seealso>
<seealso><a href="programs/apachectl.html">apachectl</a></seealso>

<section id="introduction"><title>Introducci&#243;n</title>

    <p>Para parar y reiniciar Apache, hay que enviar la se&#241;al
    apropiada al proceso padre <code>httpd</code> que se est&#233;
    ejecutando.  Hay dos maneras de enviar estas se&#241;ales.  En
    primer lugar, puede usar el comando de Unix <code>kill</code> que
    env&#237;a se&#241;ales directamente a los procesos. Puede que
    tenga varios procesos <code>httpd</code> ejecutandose en su
    sistema, pero las se&#241;ales deben enviarse solamente al proceso
    padre, cuyo pid est&#225; especificado en la directiva <directive
    module="mpm_common">PidFile</directive>. Esto quiere decir que no
    debe necesitar enviar se&#241;ales a ning&#250;n proceso excepto
    al proceso padre. Hay tres se&#241;ales que puede enviar al
    proceso padre: <code><a href="#term">TERM</a></code>, <code><a
    href="#hup">HUP</a></code>, y <code><a
    href="#graceful">USR1</a></code>, que van a ser descritas a
    continuaci&#243;n.</p>

    <p>Para enviar una se&#241;al al proceso padre debe escribir un
    comando como el que se muestra en el ejemplo:</p>

<example>kill -TERM `cat /usr/local/apache2/logs/httpd.pid`</example>

    <p>La segunda manera de enviar se&#241;ales a los procesos
    <code>httpd</code> es usando las opciones de l&#237;nea de
    comandos <code>-k</code>: <code>stop</code>, <code>restart</code>,
    y <code>graceful</code>, como se muestra m&#225;s abajo.  Estas
    opciones se le pueden pasar al binario <a
    href="programs/httpd.html">httpd</a>, pero se recomienda que se
    pasen al script de control <a
    href="programs/apachectl.html">apachectl</a>, que a su vez los
    pasar&#225; a <code>httpd</code>.</p>

    <p>Despu&#233;s de haber enviado las se&#241;ales que desee a
    <code>httpd</code>, puede ver como progresa el proceso
    escribiendo:</p>

<example>tail -f /usr/local/apache2/logs/error_log</example>

    <p>Modifique estos ejemplos para que coincidan con la
    configuraci&#243;n que tenga especificada en las directivas
    <directive module="core">ServerRoot</directive> y <directive
    module="mpm_common">PidFile</directive> en su fichero principal de
    configuraci&#243;n.</p>
</section>

<section id="term"><title>Parar Apache</title>

<dl><dt>Se&#241;al: TERM</dt>
<dd><code>apachectl -k stop</code></dd>
</dl>

    <p>Enviar las se&#241;ales <code>TERM</code> o <code>stop</code>
    al proceso padre hace que se intenten eliminar todos los procesos
    hijo inmediatamente. Esto puede tardar algunos minutos. Una vez
    que hayan terminado todos los procesos hijo, terminar&#225; el
    proceso padre. Cualquier petici&#243;n en proceso terminar&#225;
    inmediatanmente, y ninguna petici&#243;n posterior ser&#225;
    atendida.</p>
</section>

<section id="graceful"><title>Reinicio Graceful</title>

<dl><dt>Se&#241;al: USR1</dt>
<dd><code>apachectl -k graceful</code></dd>
</dl>

    <p>Las se&#241;ales <code>USR1</code> o <code>graceful</code>
    hacen que el proceso padre <em>indique</em> a sus hijos que
    terminen despu&#233;s de servir la petici&#243;n que est&#233;n
    atendiendo en ese momento (o de inmediato si no est&#225;n
    sirviendo ninguna petici&#243;n). El proceso padre lee de nuevo
    sus ficheros de configuraci&#243;n y vuelve a abrir sus ficheros
    log. Conforme cada hijo va terminando, el proceso padre lo va
    sustituyendo con un hijo de una nueva <em>generaci&#243;n</em> con
    la nueva configuraci&#243;n, que empeciezan a servir peticiones
    inmediatamente.</p>

    <note>En algunas plataformas que no permiten usar
    <code>USR1</code> para reinicios graceful, puede usarse una
    se&#241;al alternativa (como <code>WINCH</code>). Tambien puede
    usar <code>apachectl graceful</code> y el script de control
    enviar&#225; la se&#241;al adecuada para su plataforma.</note>

    <p>Apache est&#225; dise&#241;ado para respetar en todo momento la
    directiva de control de procesos de los MPM, as&#237; como para
    que el n&#250;mero de procesos y hebras disponibles para servir a
    los clientes se mantenga en los valores adecuados durante el
    proceso de reinicio.  A&#250;n m&#225;s, est&#225; dise&#241;ado
    para respetar la directiva <directive
    module="mpm_common">StartServers</directive> de la siguiente
    manera: si despu&#233;s de al menos un segundo el nuevo hijo de la
    directiva <directive module="mpm_common">StartServers</directive>
    no ha sido creado, entonces crea los suficientes para se atienda
    el trabajo que queda por hacer. As&#237;, se intenta mantener
    tanto el n&#250;mero de hijos adecuado para el trabajo que el
    servidor tenga en ese momento, como respetar la configuraci&#243;n
    determinada por los par&#225;metros de la directiva
    <directive>StartServers</directive>.</p>

    <p>Los usuarios del m&#243;dulo <module>mod_status</module>
    notar&#225;n que las estad&#237;sticas del servidor
    <strong>no</strong> se ponen a cero cuando se usa la se&#241;al
    <code>USR1</code>. Apache fue escrito tanto para minimizar el
    tiempo en el que el servidor no puede servir nuevas peticiones
    (que se pondr&#225;n en cola por el sistema operativo, de modo que
    se no se pierda ning&#250;n evento), como para respetar sus
    par&#225;metros de ajuste. Para hacer esto, tiene que guardar el
    <em>scoreboard</em> usado para llevar el registro de los procesos
    hijo a trav&#233;s de las distintas generaciones.</p>

    <p>El mod_status tambi&#233;n usa una <code>G</code> para indicar
    que esos hijos est&#225;n todav&#237;a sirviendo peticiones
    previas al reinicio graceful.</p>

    <p>Actualmente no existe ninguna manera de que un script con un
    log de rotaci&#243;n usando <code>USR1</code> sepa con seguridad
    que todos los hijos que se registraron en el log con anterioridad
    al reinicio han terminado. Se aconseja que se use un retardo
    adecuado despu&#233;s de enviar la se&#241;al <code>USR1</code>
    antes de hacer nada con el log antiguo. Por ejemplo, si la mayor
    parte las visitas que recibe de usuarios que tienen conexiones de
    baja velocidad tardan menos de 10 minutos en completarse, entoces
    espere 15 minutos antes de hacer nada con el log antiguo.</p>

    <note>Si su fichero de configuraci&#243;n tiene errores cuando
    haga el reinicio, entonces el proceso padre no se reinciciar&#225;
    y terminar&#225; con un error. En caso de un reinicio graceful,
    tambi&#233;n dejar&#225; a los procesos hijo ejecutandose mientras
    existan.  (Estos son los hijos de los que se est&#225; saliendo de
    forma graceful y que est&#225;n sirviendo sus &#250;ltimas
    peticiones.) Esto provocar&#225; problemas si intenta reiniciar el
    servidor -- no ser&#225; posible conectarse a la lista de puertos
    de escucha. Antes de reiniciar, puede comprobar que la sintaxis de
    sus ficheros de configuracion es correcta con la opci&#243;n de
    l&#237;nea de comandos <code>-t</code> (consulte <a
    href="programs/httpd.html">httpd</a>). No obstante, esto no
    garantiza que el servidor se reinicie correctamente. Para
    comprobar que no hay errores en los ficheros de
    configuraci&#243;n, puede intentar iniciar <code>httpd</code> con
    un usuario diferente a root. Si no hay errores, intentar&#225;
    abrir sus sockets y logs y fallar&#225; porque el usuario no es
    root (o porque el <code>httpd</code> que se est&#225; ejecutando
    en ese momento ya est&#225; conectado a esos puertos). Si falla
    por cualquier otra raz&#243;n, entonces casi seguro que hay
    alg&#250;n error en alguno de los ficheros de configuraci&#243;n y
    debe corregir ese o esos errores antes de hacer un reinicio
    graceful.</note>
</section>

<section id="hup"><title>Reiniciar Apache</title>

<dl><dt>Se&#241;al: HUP</dt>
<dd><code>apachectl -k restart</code></dd>
</dl>

    <p>El env&#237;o de las se&#241;ales <code>HUP</code> o
    <code>restart</code> al proceso padre hace que los procesos hijo
    terminen como si le envi&#225; ramos la se&#241;al
    <code>TERM</code>, para eliminar el proceso padre. La diferencia
    est&#225; en que estas se&#241;ales vuelven a leer los archivos de
    configuraci&#243;n y vuelven a abrir los ficheros log. Se genera
    un nuevo conjunto de hijos y se contin&#250;a sirviendo
    peticiones.</p>

    <p>Los usuarios del m&#243;dulo <module>mod_status</module>
    notar&#225;n que las estad&#237;sticas del servidor se ponen a
    cero cuando se env&#237;a la se&#241;al <code>HUP</code>.</p>

<note>Si su fichero de configuraci&#243;n contiene errores, cuando
intente reiniciar, el proceso padre del servidor no se
reiniciar&#225;, sino que terminar&#225; con un error. Consulte
m&#225;s arriba c&#243;mo puede solucionar este problema.</note>
</section>

<section id="race"><title>Ap&#233;ndice: se&#241;ales y race conditions</title>

    <p>Con anterioridad a la versi&#243;n de Apache 1.2b9 hab&#237;a
    varias <em>race conditions</em> implicadas en las se&#241;ales
    para parar y reiniciar procesos (una descripci&#243;n sencilla de
    una race condition es: un problema relacionado con el momento en
    que suceden las cosas, como si algo sucediera en momento en que no
    debe, y entonces el resultado esperado no se corresponde con el
    obtenido). Para aquellas arquitecturas que tienen el conjunto de
    caracter&#237;sticas "adecuadas", se han eliminado tantas race
    conditions como ha sido posible. Pero hay que tener en cuenta que
    todav&#237;a existen race conditions en algunas arquitecturas.</p>

    <p>En las arquitecturas que usan un <directive
    module="mpm_common">ScoreBoardFile</directive> en disco, existe la
    posibilidad de que se corrompan los scoreboards. Esto puede hacer
    que se produzca el error "bind: Address already in use"
    (despu&#233;s de usar<code>HUP</code>) o el error "long lost child
    came home!"  (despu&#233;s de usar <code>USR1</code>). En el
    primer caso se trata de un error irrecuperable, mientras que en el
    segundo, solo ocurre que el servidor pierde un slot del
    scoreboard. Por lo tanto, ser&#237;a aconsejable usar reinicios
    graceful, y solo hacer reinicios normales de forma
    ocasional. Estos problemas son bastante complicados de solucionar,
    pero afortunadamente casi ninguna arquitectura necesita un fichero
    scoreboard. Consulte la documentaci&#243;n de la directiva
    <directive module="mpm_common">ScoreBoardFile</directive> para ver
    las arquitecturas que la usan.</p>

    <p>Todas las arquitecturas tienen una peque&#241;a race condition
    en cada proceso hijo implicada en la segunda y subsiguientes
    peticiones en una conexi&#243;n HTTP persistente
    (KeepAlive). Puede ser que el servidor termine despu&#233;s de
    leer la l&#237;nea de petici&#243;n pero antes de leer cualquiera
    de las cebeceras de petici&#243;n. Hay una soluci&#243;n que fue
    descubierta demasiado tarde para la incluirla en versi&#243;n
    1.2. En teoria esto no debe suponer ning&#250;n problema porque el
    cliente KeepAlive ha de esperar que estas cosas pasen debido a los
    retardos de red y a los timeouts que a veces dan los
    servidores. En la practica, parece que no afecta a nada m&#225;s
    -- en una sesi&#243;n de pruebas, un servidor se reinici&#243;
    veinte veces por segundo y los clientes pudieron navegar sin
    problemas por el sitio web sin encontrar problemas ni para
    descargar una sola imagen ni encontrar un solo enlace roto. </p>
</section>

</manualpage>

