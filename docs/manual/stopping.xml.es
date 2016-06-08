<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 1174747 -->
<!-- Translated by Luis Gil de Bernabé Pfeiffer lgilbernabe[AT]apache.org -->
<!-- Reviewed by Sergio Ramos-->

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
     deben consultar la sección <a
     href="platform/windows.html#winsvc">Ejecutar Apache como un
     servicio</a> y los usuario de Windows 9x y ME deben consultar <a
     href="platform/windows.html#wincons">Ejecutar Apache como una
     Aplicación de Consola</a> para obtener información
     sobre como controlar Apache en esas plataformas.</p>
</summary>

<seealso><program>httpd</program></seealso>
<seealso><program>apachectl</program></seealso>
<seealso><a href="invoking.html"></a>Iniciar Apache</seealso>

<section id="introduction"><title>Introducción</title>

    <p>Para parar y reiniciar Apache, hay que enviar la señal
    apropiada al proceso padre <code>httpd</code> que se está
    ejecutando.  Hay dos maneras de enviar estas señales.  En
    primer lugar, puede usar el comando de Unix <code>kill</code> que
    envía señales directamente a los procesos. Puede que
    tenga varios procesos <code>httpd</code> ejecutándose en su
    sistema, pero las señales deben enviarse solamente al proceso
    padre, cuyo PID está especificado en la directiva <directive
    module="mpm_common">PidFile</directive>. Esto quiere decir que no
    debe necesitar enviar señales a ningún proceso excepto
    al proceso padre. Hay tres señales que puede enviar al
    proceso padre: 
    <code><a href="#term">TERM</a></code>, 
    <code><a href="#graceful">USR1</a></code>
    <code><a href="#hup">HUP</a></code>, y
    <code><a href="#gracefulstop">WINCH</a></code>,
    que van a ser descritas a continuación.</p>

    <p>Para enviar una señal al proceso padre debe escribir un
    comando como el que se muestra en el ejemplo:</p>

<example>kill -TERM `cat /usr/local/apache2/logs/httpd.pid`</example>

    <p>La segunda manera de enviar señales a los procesos
    <code>httpd</code> es usando las opciones de línea de
    comandos <code>-k</code>: <code>stop</code>, <code>restart</code>,
    y <code>graceful</code> y <code>graceful-stop</code>, como se 
    muestra más abajo. Estas opciones se le pueden pasar al binario 
    <program>httpd</program>, pero se recomienda que se pasen al 
    script de control <program>apachectl</program>, que a su vez los
    pasará a <program>httpd</program>.</p>

    <p>Después de haber enviado las señales que desee a
    <code>httpd</code>, puede ver como progresa el proceso
    escribiendo:</p>

<example>tail -f /usr/local/apache2/logs/error_log</example>

    <p>Modifique estos ejemplos para que coincidan con la
    configuración que tenga especificada en las directivas
    <directive module="core">ServerRoot</directive> y <directive
    module="mpm_common">PidFile</directive> en su fichero principal de
    configuración.</p>
</section>

<section id="term"><title>Parar Ahora Apache</title>

<dl><dt>Señal: TERM</dt>
<dd><code>apachectl -k stop</code></dd>
</dl>

    <p>Enviar las señales <code>TERM</code> o <code>stop</code>
    al proceso padre hace que se intenten eliminar todos los procesos
    hijos inmediatamente. Esto puede tardar algunos segundos. Una vez que hayan 
    terminado todos los procesos hijos, terminará el proceso padre. 
    Cualquier petición en proceso terminará inmediatamente, y 
    ninguna petición posterior será
    atendida.</p>
</section>

<section id="graceful"><title>Reinicio "Graceful" o elegante</title>

<dl><dt>Señal: USR1</dt>
<dd><code>apachectl -k graceful</code></dd>
</dl>

    <p>Las señales <code>USR1</code> o <code>graceful</code>
    hacen que el proceso padre <em>indique</em> a sus hijos que
    terminen después de servir la petición que están
    atendiendo en ese momento (o de inmediato si no están
    sirviendo ninguna petición). El proceso padre lee de nuevo
    sus ficheros de configuración y vuelve a abrir sus ficheros
    log. Conforme cada hijo va terminando, el proceso padre lo va
    sustituyendo con un hijo de una nueva <em>generación</em> con
    la nueva configuración, que empiezan a servir peticiones
    inmediatamente.</p>

    <note>En algunas plataformas que no permiten usar
    <code>USR1</code> para reinicios graceful, puede usarse una
    señal alternativa (como <code>WINCH</code>). También puede
    usar <code>apachectl graceful</code> y el script de control
    enviará la señal adecuada para su plataforma.</note>

    <p>Apache está diseñado para respetar en todo momento la
    directiva de control de procesos de los MPM, así como para
    que el número de procesos e hilos disponibles para servir a
    los clientes se mantenga en los valores adecuados durante el
    proceso de reinicio.  Aún más, está diseñado
    para respetar la directiva <directive
    module="mpm_common">StartServers</directive> de la siguiente
    manera: si después de al menos un segundo el nuevo hijo de la
    directiva <directive module="mpm_common">StartServers</directive>
    no ha sido creado, entonces crea los suficientes para que se atienda
    el trabajo que queda por hacer. Así, se intenta mantener
    tanto el número de hijos adecuado para el trabajo que el
    servidor tenga en ese momento, como respetar la configuración
    determinada por los parámetros de la directiva
    <directive>StartServers</directive>.</p>

    <p>Los usuarios del módulo <module>mod_status</module>
    notarán que las estadísticas del servidor
    <strong>no</strong> se ponen a cero cuando se usa la señal
    <code>USR1</code>. Apache fue escrito tanto para minimizar el
    tiempo en el que el servidor no puede servir nuevas peticiones
    (que se pondrán en cola por el sistema operativo, de modo que
    se no se pierda ningún evento), como para respetar sus
    parámetros de ajuste. Para hacer esto, tiene que guardar el
    <em>scoreboard</em> usado para llevar el registro de los procesos
    hijo a través de las distintas generaciones.</p>

    <p>El mod_status también usa una <code>G</code> para indicar
    que esos hijos están todavía sirviendo peticiones
    previas al reinicio graceful.</p>

    <p>Actualmente no existe ninguna manera de que un script con un
    log de rotación usando <code>USR1</code> sepa con seguridad
    que todos los hijos que se registraron en el log con anterioridad
    al reinicio han terminado. Se aconseja que se use un retardo
    adecuado después de enviar la señal <code>USR1</code>
    antes de hacer nada con el log antiguo. Por ejemplo, si la mayor
    parte las visitas que recibe de usuarios que tienen conexiones de
    baja velocidad tardan menos de 10 minutos en completarse, entonces
    espere 15 minutos antes de hacer nada con el log antiguo.</p>

    <note>Si su fichero de configuración tiene errores cuando
    haga el reinicio, entonces el proceso padre no se reiniciará
    y terminará con un error. En caso de un reinicio graceful,
    también dejará a los procesos hijo ejecutándose mientras
    existan.  (Estos son los hijos de los que se está saliendo de
    forma graceful y que están sirviendo sus últimas
    peticiones.) Esto provocará problemas si intenta reiniciar el
    servidor no será posible conectarse a la lista de puertos
    de escucha. Antes de reiniciar, puede comprobar que la sintaxis de
    sus ficheros de configuración es correcta con la opción de
    línea de comandos <code>-t</code> (consulte <program>httpd</program>). 
    No obstante, esto no
    garantiza que el servidor se reinicie correctamente. Para
    comprobar que no hay errores en los ficheros de
    configuración, puede intentar iniciar <code>httpd</code> con
    un usuario diferente a root. Si no hay errores, intentará
    abrir sus sockets y logs y fallará porque el usuario no es
    root (o porque el <code>httpd</code> que se está ejecutando
    en ese momento ya está conectado a esos puertos). Si falla
    por cualquier otra razón, entonces casi seguro que hay
    algún error en alguno de los ficheros de configuración y
    debe corregir ese o esos errores antes de hacer un reinicio
    graceful.</note>
</section>

<section id="hup"><title>Reiniciar Apache</title>

<dl><dt>Señal: HUP</dt>
<dd><code>apachectl -k restart</code></dd>
</dl>

    <p>El envío de las señales <code>HUP</code> o
    <code>restart</code> al proceso padre hace que los procesos hijo
    terminen como si le enviáramos la señal
    <code>TERM</code>, para eliminar el proceso padre. La diferencia
    está en que estas señales vuelven a leer los archivos de
    configuración y vuelven a abrir los ficheros log. Se genera
    un nuevo conjunto de hijos y se continúa sirviendo
    peticiones.</p>

    <p>Los usuarios del módulo <module>mod_status</module>
    notarán que las estadísticas del servidor se ponen a
    cero cuando se envía la señal <code>HUP</code>.</p>

<note>Si su fichero de configuración contiene errores, cuando
intente reiniciar, el proceso padre del servidor no se
reiniciará, sino que terminará con un error. Consulte
más arriba cómo puede solucionar este problema.</note>
</section>

<section id="race"><title>Apándice: señales y race conditions</title>

    <p>Con anterioridad a la versión de Apache 1.2b9 había
    varias <em>race conditions</em> implicadas en las señales
    para parar y reiniciar procesos (una descripción sencilla de
    una race condition es: un problema relacionado con el momento en
    que suceden las cosas, como si algo sucediera en momento en que no
    debe, y entonces el resultado esperado no se corresponde con el
    obtenido). Para aquellas arquitecturas que tienen el conjunto de
    características "adecuadas", se han eliminado tantas race
    conditions como ha sido posible. Pero hay que tener en cuenta que
    todavía existen race conditions en algunas arquitecturas.</p>

    <p>En las arquitecturas que usan un <directive
    module="mpm_common">ScoreBoardFile</directive> en disco, existe la
    posibilidad de que se corrompan los scoreboards. Esto puede hacer
    que se produzca el error "bind: Address already in use"
    (después de usar<code>HUP</code>) o el error "long lost child
    came home!"  (después de usar <code>USR1</code>). En el
    primer caso se trata de un error irrecuperable, mientras que en el
    segundo, solo ocurre que el servidor pierde un slot del
    scoreboard. Por lo tanto, sería aconsejable usar reinicios
    graceful, y solo hacer reinicios normales de forma
    ocasional. Estos problemas son bastante complicados de solucionar,
    pero afortunadamente casi ninguna arquitectura necesita un fichero
    scoreboard. Consulte la documentación de la directiva
    <directive module="mpm_common">ScoreBoardFile</directive> para ver
    las arquitecturas que la usan.</p>

    <p>Todas las arquitecturas tienen una pequeña race condition
    en cada proceso hijo implicada en la segunda y subsiguientes
    peticiones en una conexión HTTP persistente
    (KeepAlive). Puede ser que el servidor termine después de
    leer la línea de petición pero antes de leer cualquiera
    de las cabeceras de petición. Hay una solución que fue
    descubierta demasiado tarde para la incluirla en versión
    1.2. En teoría esto no debe suponer ningún problema porque el
    cliente KeepAlive ha de esperar que estas cosas pasen debido a los
    retardos de red y a los timeouts que a veces dan los
    servidores. En la practica, parece que no afecta a nada más
    en una sesión de pruebas, un servidor se reinició
    veinte veces por segundo y los clientes pudieron navegar sin
    problemas por el sitio web sin encontrar problemas ni para
    descargar una sola imagen ni encontrar un solo enlace roto. </p>
</section>
</manualpage>
