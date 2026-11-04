<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1937646 -->
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

<modulesynopsis metafile="mod_systemd.xml.meta">

<name>mod_systemd</name>
<description>Proporciona mejor soporte para la integración con systemd</description>
<status>Extension</status>
<sourcefile>mod_systemd.c</sourcefile>
<identifier>systemd_module</identifier>
<compatibility>Disponible en Apache 2.4.42 y posteriores</compatibility>

<summary>
    <p>Este módulo proporciona soporte para la integración con systemd. Permite
    usar httpd en un servicio con <code>Type=notify</code> o
    <code>Type=notify-reload</code> de systemd (consulte <a
    href="https://www.freedesktop.org/software/systemd/man/systemd.service.html">systemd.service(5)</a>
    para más información). El módulo se activa si se carga.</p>

    <example>
    <title>Ejemplo de unidad de servicio systemd (probablemente se necesiten más opciones para sistemas en producción)</title>
    <pre>
[Unit]
Description=The Apache HTTP Server
After=network.target

[Service]
Type=notify
ExecStart=/usr/local/apache2/bin/httpd -D FOREGROUND -k start
ExecReload=/usr/local/apache2/bin/httpd -k graceful
KillMode=mixed

[Install]
WantedBy=multi-user.target
    </pre>
    </example>

   <p>Debe prestarse especial atención a cómo se configuran
   <code>ExecStop</code> y/o <code>KillMode</code> para el servicio. Si
   se configura, un comando <code>ExecStop</code> debe ser una
   <em>operación síncrona</em> que finalice por sí misma cuando el demonio
   haya terminado. Ejecutar <code>httpd -k stop</code>
   de forma <em>asíncrona</em> inicia la terminación del demonio, por lo que no
   satisface esta condición. El ejemplo anterior usa
   <code>KillMode=mixed</code> para que systemd envíe
   <code>SIGTERM</code> y así indicar al proceso padre (y solo al
   padre) que se detenga. A continuación, se envía <code>SIGKILL</code> a todo
   el grupo de procesos una vez transcurrido <code>TimeoutStopSec</code>, si
   todavía quedan procesos en ejecución. Consulte <a
   href="https://www.freedesktop.org/software/systemd/man/systemd.kill.html">systemd.kill(5)</a>
   para más información.</p>

   <p>Un gestor de servicios de systemd 253 en adelante ofrece
   <code>Type=notify-reload</code>, que conviene usar preferentemente.
   Con <code>Type=notify</code>, un <code>systemctl reload</code>
   retorna en cuanto el comando <code>ExecReload</code> ha enviado su
   señal, lo que ocurre antes de que se haya leído la nueva configuración, y
   siempre informa de éxito, sea lo que sea lo que ocurra después con el
   reinicio. <code>Type=notify-reload</code>, en cambio, mantiene la
   recarga abierta hasta que el servidor informa de que ha terminado, de modo que el
   comando espera a que la nueva configuración esté en uso y falla si nunca
   llega a estarlo. mod_systemd envía la notificación <code>RELOADING=1</code>
   que el protocolo espera mientras se está leyendo la configuración, con la
   marca de tiempo <code>MONOTONIC_USEC</code> que requiere el gestor de
   servicios, y <code>READY=1</code> en cuanto se ha cargado.</p>

    <example>
    <title>Ejemplo de una unidad de servicio que se recarga de forma síncrona</title>
    <pre>
[Service]
Type=notify-reload
ReloadSignal=SIGCONT
ExecStart=/usr/local/apache2/bin/httpd -D FOREGROUND -k start
ExecReload=/usr/local/apache2/bin/httpd -k graceful
KillMode=mixed
    </pre>
    </example>

   <p>El gestor de servicios ejecuta primero <code>ExecReload</code>, y envía
   la señal indicada por <code>ReloadSignal</code> solo cuando ese comando
   ha terminado con éxito. Mantener <code>ExecReload</code> es lo que
   hace segura la recarga: <code>httpd -k graceful</code> analiza la nueva
   configuración en un proceso propio y termina sin enviar ninguna señal si no
   consigue analizarla, de modo que la recarga falla y el servidor en
   ejecución sigue con la configuración que ya tenía. Si se omite
   <code>ExecReload</code> y se deja que el gestor de servicios señale
   directamente al servidor, se pierde esa comprobación: el proceso padre en
   ejecución lee él mismo la nueva configuración, y una configuración que no
   se puede analizar hace que termine, tirando abajo el servidor.</p>

   <p>La señal enviada después de ejecutar <code>ExecReload</code> es entonces
   redundante, por lo que <code>ReloadSignal</code> debería nombrar una señal
   sobre la que httpd no actúe, como <code>SIGCONT</code>. Es importante que se
   establezca: el valor por defecto es <code>SIGHUP</code>, que httpd interpreta
   como un reinicio <em>no ordenado</em>, lo que descarta las conexiones que una
   recarga pretende conservar. Una unidad que sí omita
   <code>ExecReload</code> debe establecer <code>ReloadSignal=SIGUSR1</code>,
   la señal con la que httpd se reinicia de forma ordenada.</p>

   <p>La activación de sockets de systemd se admite si httpd se compiló con
   ella. Cada puerto de <directive module="mpm_common">Listen</directive>
   debe entonces ser uno de los que pasa systemd; un puerto que no lo sea es
   un error de configuración fatal, en lugar de uno que httpd abra por sí mismo.
   La activación de sockets solo se usa si este módulo está cargado, de modo que
   puede estar incluido en la compilación sin usarse.</p>

    <p><directive module="core">ExtendedStatus</directive> está
    activada por defecto si el módulo está cargado. Si <directive
    module="core">ExtendedStatus</directive> no está desactivada en
    la configuración, las estadísticas de carga y peticiones en tiempo de ejecución estarán
    disponibles en la salida de <code>systemctl status</code>.</p>

    <p>Se admite el watchdog de systemd. Si la unidad de servicio establece
    <code>WatchdogSec=</code>, el proceso padre envía la notificación de keep-alive
    que indica a systemd que el servidor sigue vivo; un servidor que deja de
    enviarla se termina y, con un valor adecuado de
    <code>Restart=</code>, se reinicia. La notificación se envía
    mientras se está leyendo la configuración y de nuevo una vez cargada, de modo
    que una recarga queda cubierta, y periódicamente desde el proceso padre
    mientras el servidor está en ejecución.</p>

    <p>Esa notificación periódica se envía aproximadamente cada diez segundos, que
    es la frecuencia con la que el proceso padre ejecuta el hook desde el que se
    envía. Un <code>WatchdogSec=</code> inferior al doble de ese valor no se puede
    cumplir, y provocaría que systemd terminara un servidor que funciona con
    normalidad; tal configuración se notifica como advertencia al arrancar. Use un
    <code>WatchdogSec=</code> de al menos 20 segundos.</p>

    <example>
    <title>Añadir supervisión de watchdog a cualquiera de las unidades anteriores</title>
    <pre>
[Service]
WatchdogSec=30
Restart=on-failure
    </pre>
    </example>
</summary>

</modulesynopsis>
