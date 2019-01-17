<?xml version='1.0' encoding='UTF-8' ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.es.xsl"?>
<!-- English Revision: 1597027 -->
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

<manualpage metafile="invoking.xml.meta">

  <title>Iniciar Apache</title>

<summary>
    <p>En Windows, Apache se ejecuta normalmente como un servicio. 
        Para obtener más información, consulte
    <a href="platform/windows.html#winsvc">Ejecutar Apache como un
    servicio</a>.</p>

    <p>En Unix, el programa <program>httpd</program> se
    ejecuta como un demonio (daemon) de forma contíniua y en segundo plano
    y atiende las peticiones que le lleguen.  Este documento describe cómo
    invocar el programa <program>httpd</program>.</p>
</summary>

<seealso><a href="stopping.html">Parar y reiniciar Apache</a></seealso>
<seealso><program>httpd</program></seealso>
<seealso><program>apachectl</program></seealso>

<section id="startup"><title>Cómo iniciar Apache</title>

    <p>Si el puerto especificado en la directiva <directive
    module="mpm_common">Listen</directive> del fichero de
    configuración es el que viene por defecto, es decir, el
    puerto 80 (o cualquier otro puerto por debajo del 1024), entonces
    es necesario tener privilegios de usuario root (superusuario) para
    iniciar Apache, de modo que pueda establecerse una conexión a
    través de esos puertos privilegiados. Una vez que el servidor
    Apache se ha iniciado y ha completado algunas tareas preliminares,
    tales como abrir sus ficheros log, lanzará varios procesos,
    procesos <em>hijo</em>, que hacen el trabajo de escuchar y atender
    las peticiones de los clientes.  El proceso principal,
    <code>httpd</code> continúa ejecutándose con el usuario root, pero los
    procesos hijo se ejecutan con menores privilegios de usuario.
    Esto lo controla el <a href="mpm.html">Módulo de
    MultiProcesamiento (MPM)</a> seleccionado.</p>

    <p>La forma recomendada para invocar el ejecutable
    <program>httpd</program> es usando el script de control 
    <program>apachectl</program>.  Este script fija
    determinadas variables de entorno que son necesarias para que
    <program>httpd</program> funcione correctamente en el sistema operativo,
    y después invoca el binario <program>httpd</program>.
    <program>apachectl</program> pasa a <program>httpd</program>
    cualquier argumento que se le pase a través de la línea de comandos, 
    de forma que cualquier opción de <code>httpd</code> puede ser usada
    también con <code>apachectl</code>.  Puede editar
    directamente el script <code>apachectl</code> y cambiar la
    variable <code>HTTPD</code> variable que está al principio y
    que especifica la ubicación exacta en la que está el
    binario <program>httpd</program> y cualquier argumento de línea de
    comandos que quiera que esté <em>siempre</em> presente.</p>

    <p>La primera cosa que hace <program>httpd</program> cuando es invocado
    es localizar y leer el <a href="configuring.html">fichero de
    configuración</a> <code>httpd.conf</code>. El lugar en el que
    está ese fichero se determina al compilar, pero también
    es posible especificar la ubicación en la que se encuentra al
    iniciar el servidor Apache usando la opción de línea de
    comandos <code>-f</code></p>

<example>/usr/local/apache2/bin/apachectl -f
      /usr/local/apache2/conf/httpd.conf</example>

    <p>Si todo va bien durante el arranque, la sesión de terminal
    se suspenderá un momento y volverá a estar activa casi
    inmediatamente. Esto quiere decir que el servidor está activo
    y funcionando. Puede usar su navegador para conectarse al
    servidor y ver la página de prueba que hay en el directorio de
    la directiva
    <directive module="core">DocumentRoot</directive>.</p>
</section>

<section id="errors"><title>Errores Durante el Arranque</title>

    <p>Si Apache encuentra una error irrecuperable durante el
    arranque, escribirá un mensaje describiendo el problema en la
    consola o en el archivo <directive
    module="core">ErrorLog</directive> antes de abortar la
    ejecución. Uno de los mensajes de error más comunes es
    "<code>Unable to bind to Port ...</code>". Cuando se recibe este
    mensaje es normalmente por alguna de las siguientes razones:</p>

    <ul>
      <li>Está intentando iniciar el servidor Apache en un puerto
      privilegiado (del 0 al 1024) sin haber hecho login como usuario
      root; ó bien</li>

      <li>Está intentando iniciar el servidor Apache mientras
      está ya ejecutando Apache o algún otro servidor web en
      el mismo puerto.</li>
    </ul>

    <p>Puede encontrar más información sobre cómo
    solucionar problemas, en la sección de <a
    href="http://wiki.apache.org/httpd/FAQ">Preguntas Frecuentes</a> de Apache.</p>
</section>

<section id="boot"><title>Iniciar Apache al Iniciar el Sistema</title>

    <p>Si quiere que el servidor Apache continúe su ejecución
    después de reiniciar el sistema, debe añadir una llamada
    a <program>apachectl</program> en sus archivos de arranque (normalmente
    <code>rc.local</code> o un fichero en ese directorio del tipo
    <code>rc.N</code>). Esto iniciará Apache como usuario
    root. Antes de hacer esto, asegúrese de que la
    configuración de seguridad y las restricciones de acceso de
    su servidor Apache están correctamente configuradas.</p>

    <p>El script <program>apachectl</program> está diseñado para
    actuar como un script estándar de tipo <code>SysV init</code>; puede tomar los
    argumentos <code>start</code>, <code>restart</code>, y
    <code>stop</code> y traducirlos en las señales apropiadas
    para <program>httpd</program>.  De esta manera, casi siempre puede
    simplemente enlazar <program>apachectl</program>con el directorio init
    adecuado. Pero asegúrese de comprobar los requisitos exactos
    de su sistema.</p>
</section>

<section id="info"><title>Información Adicional</title>

    <p>En la sección <a href="programs/">El Servidor y Programas
    de Soporte </a> puede encontrar más información sobre
    las opciones de línea de comandos que puede pasar a <program>
    httpd</program> y <program>apachectl</program> así como sobre otros
    programas de soporte incluidos con el servidor Apache.
    También hay documentación sobre todos los <a
    href="mod/">módulos</a> incluidos con la distribución de
    Apache y sus correspondientes <a
    href="mod/directives.html">directivas</a> asociadas.</p>
</section>

</manualpage>

