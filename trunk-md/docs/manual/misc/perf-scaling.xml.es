<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.en.xsl"?>
<!-- English Revision: 1690137 -->
<!-- Spanish Translation: Daniel Ferradal -->

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
<manualpage metafile="perf-scaling.xml.meta">
    <parentdocument href="./">Documentación diversa</parentdocument>

    <title>Escalado de Rendimiento</title>

    <summary>
        <p>La página de ajuste de rendimiento en la documentación de Apache 1.3 dice:</p>

        <blockquote><p>
            "Apache es un servidor web genérico, que primero está está diseñado para ser correcto, y segundo para ser rápido. Aun así, su rendimiento es bastante satisfactorio. La mayoría de los sitios web tienen menos de 10Mbits de ancho de banda de salida, que Apache puede utilizar con tan solo un servidor web que use un Pentium de gama baja."</p></blockquote>

        <p>Aun así, esta frase se escribió hace unos cuantos años, y desde entonces han ocurrido muchas cosas. Por un lado, el hardware para servidores web se ha vuelto mucho más rápido. Por otro lado, a muchos sitios web ahora se les permite usar mucho más que diez megabits de ancho de banda de salida. Además, las aplicaciones web se han vuelto más complejas. La página típica de contenido estático sigue existiendo, pero la web ha crecido sustancialmente como una plataforma de computación y los webmasters acaban ejecutando contenido dinámico en perl, PHP, o JAVA, los cuales afectan al rendimiento.</p>

        <p>Por lo tanto, a pesar de los avances en velocidad del hardware y el crecimiento del ancho de banda, el rendimiento del servidor web y el rendimiento de las aplicaciones web siguen siendo temas de interés. En esta documentación, se hablará de muchos aspectos del rendimiento del servidor web.</p>
    </summary>

  <section id="what-will-and-will-not-be-discussed">
        <title>De qué hablaremos y de qué no</title>

        <p>Este documento se centrará en documentación de fácil acceso y opciones de ajuste para Apache HTTPD 2.2 y 2.4, así como herramientas de monitorización. Las herramientas de monitorización le permiten observar su servidor web para obtener información de su rendimiento, o su falta de él. Asumiremos que usted no tiene un presupuesto ilimitado para hardware de servidor, así que la infraestructura existente tiene que hacer el trabajo. Usted probablemente tampoco desea compilar su propio Apache, o recompilar el kernel del sistema operativo. Aunque si asumimos que está familiarizado con el fichero de configuración de Apache httpd.</p>
    </section>

    <section id="monitoring-your-server">
        <title>Monitorizando Su Servidor</title>

        <p>La primera tarea cuando se mide o se ajusta el rendimiento de su servidor es averiguar como está rindiendo actualmente. Monitorizando su servidor con  carga real, o carga generada artificialmente, puede extrapolar su comportamiento bajo estrés, como por ejemplo cuando se le menciona en Slashdot.</p>

        <section id="monitoring-tools">
            <title>Herramientas de Monitorización</title>

            <section id="top">
                <title>top</title>

                <p>La herramienta top va incluida en Linux y FreeBSD. Solaris ofrece <code>prstat(1)</code>. Ésta recolecta una serie de estadísticas para el sistema de cada proceso que se está ejecutando, y después los muestra en su terminal. Los datos que se muestran se refrescan cada segundo y dependen de cada plataforma, pero generalmente incluye la carga general del sistema, número de procesos y su estado actual, el porcentaje de tiempo de CPU(s) utilizado ejecutando código de usuario o sistema, y el estado de la memoria virtual del sistema. Los datos que se muestran para cada proceso generalmente se pueden configurar e incluyen su nombre de proceso e ID, prioridad y valor "nice", uso de memoria y porcentaje de uso de CPU. El siguiente ejemplo muestra multiples procesos httpd (con MPM worker o event) corriendo en un sistema Linux (Xen):</p>

                <example><pre>
top - 23:10:58 up 71 days,  6:14,  4 users,  load average: 0.25, 0.53, 0.47
Tasks: 163 total,   1 running, 162 sleeping,   0 stopped,   0 zombie
Cpu(s): 11.6%us,  0.7%sy,  0.0%ni, 87.3%id,  0.4%wa,  0.0%hi,  0.0%si,  0.0%st
Mem:   2621656k total,  2178684k used,   442972k free,   100500k buffers
Swap:  4194296k total,   860584k used,  3333712k free,  1157552k cached

  PID USER      PR  NI  VIRT  RES  SHR S %CPU %MEM    TIME+  COMMAND
16687 example_  20   0 1200m 547m 179m S   45 21.4   1:09.59 httpd-worker
15195 www       20   0  441m  33m 2468 S    0  1.3   0:41.41 httpd-worker
    1 root      20   0 10312  328  308 S    0  0.0   0:33.17 init
    2 root      15  -5     0    0    0 S    0  0.0   0:00.00 kthreadd
    3 root      RT  -5     0    0    0 S    0  0.0   0:00.14 migration/0
    4 root      15  -5     0    0    0 S    0  0.0   0:04.58 ksoftirqd/0
    5 root      RT  -5     0    0    0 S    0  0.0   4:45.89 watchdog/0
    6 root      15  -5     0    0    0 S    0  0.0   1:42.52 events/0
    7 root      15  -5     0    0    0 S    0  0.0   0:00.00 khelper
   19 root      15  -5     0    0    0 S    0  0.0   0:00.00 xenwatch
   20 root      15  -5     0    0    0 S    0  0.0   0:00.00 xenbus
   28 root      RT  -5     0    0    0 S    0  0.0   0:00.14 migration/1
   29 root      15  -5     0    0    0 S    0  0.0   0:00.20 ksoftirqd/1
   30 root      RT  -5     0    0    0 S    0  0.0   0:05.96 watchdog/1
   31 root      15  -5     0    0    0 S    0  0.0   1:18.35 events/1
   32 root      RT  -5     0    0    0 S    0  0.0   0:00.08 migration/2
   33 root      15  -5     0    0    0 S    0  0.0   0:00.18 ksoftirqd/2
   34 root      RT  -5     0    0    0 S    0  0.0   0:06.00 watchdog/2
   35 root      15  -5     0    0    0 S    0  0.0   1:08.39 events/2
   36 root      RT  -5     0    0    0 S    0  0.0   0:00.10 migration/3
   37 root      15  -5     0    0    0 S    0  0.0   0:00.16 ksoftirqd/3
   38 root      RT  -5     0    0    0 S    0  0.0   0:06.08 watchdog/3
   39 root      15  -5     0    0    0 S    0  0.0   1:22.81 events/3
   68 root      15  -5     0    0    0 S    0  0.0   0:06.28 kblockd/0
   69 root      15  -5     0    0    0 S    0  0.0   0:00.04 kblockd/1
   70 root      15  -5     0    0    0 S    0  0.0   0:00.04 kblockd/2
</pre></example>

                <p>Top es una gran herramienta incluso aunque consume algunos recursos (cuando se ejecuta, su propio proceso generalmente está entre el top 10 de los que más usan CPU). Es indispensable para determinar el tamaño de los procesos que se están ejecutando, lo cual es bastante práctico para determinar cuantos procesos de servidor puede ejecutar en su máquina. Cómo hacer eso se describre en <a href="#sizing-MaxRequestWorkers">Dimensionando MaxRequestWorkers</a>. Top es, aun así, una herramienta interactiva y ejecutarla continuamente tiene muy pocas o ninguna ventaja. (aunque actualmente tiene un modo no interactivo "-b")</p>
            </section>

            <section id="free">
                <title>free</title>

                <p>Este comando solo está disponible en Linux. Muestra cuanta memoria y de swap hay en uso. Linux ubica la memoria no usada como un caché de sistema de ficheros. El comando "free" muestra el uso de ambos sin esta cache. El comando free se puede usar para averiguar cuanta memoria está usando el sistema operativo, como se describe en el párrafo <a href="#sizing-MaxRequestWorkers">Dimensionando MaxRequestWorkers</a>. El resultado del comando free parece algo como esto:</p>

                <example><pre>
sctemme@brutus:~$ free
              total       used     free   shared    buffers    cached
Mem:        4026028    3901892   124136         0    253144    841044
-/+ buffers/cache:     2807704  1218324
Swap:       3903784      12540  3891244
                </pre></example>
            </section>

            <section id="vmstat">
                <title>vmstat</title>

                <p>Este comando está disponible en muchas plataformas de unix. Muestra un gran número de métricas del sistema operativo. Ejecutado sin parámetros, muestra una linea del estado en ese momento. Cuando se añade un parámetro numérico el estado se va refrescando en intervalos según lo indicado. Por ejemplo,
                <code>vmstat 5</code> provoca que la información se refresque cada cinco segundos. Vmstat muestra la cantidad de memoria virtual en uso, cuanta memoria se está paginando (swap) cada segundo, el número de procesos ejecutándose y en estado "sleep", el número de interrupciones, cambios de contexto por segundo y el porcentaje de uso de CPU.</p>

                <p>A continuación se puede ver lo que muestra <code>vmstat</code> de un servidor sin actividad:</p>


                <example><pre>
[sctemme@GayDeceiver sctemme]$ vmstat 5 3
   procs                      memory     swap         io    system        cpu
 r b w     swpd   free   buff cache si so       bi    bo in     cs us  sy id
 0 0 0        0 186252   6688 37516    0    0   12     5 47    311  0   1 99
 0 0 0        0 186244   6696 37516    0    0    0    16 41    314  0   0 100
 0 0 0        0 186236   6704 37516    0    0    0     9 44    314  0   0 100
                  </pre></example>

                <p>Y esto es lo que muestra de un servidor que tiene la carga de 100 conexiones simultáneas sirviendo contenido estático:</p>

                <example><pre>
[sctemme@GayDeceiver sctemme]$ vmstat 5 3
   procs                      memory     swap    io      system       cpu
 r b w     swpd   free   buff cache si so     bi bo   in     cs us sy  id
 1 0 1        0 162580   6848 40056    0    0 11  5 150     324  1  1  98
 6 0 1        0 163280   6856 40248    0    0  0 66 6384 1117   42 25  32
11 0 0        0 162780   6864 40436    0    0  0 61 6309 1165   33 28  40
                  </pre></example>

                <p>La primera línea da la media desde el último reinicio. Las siguientes líneas dan información a intervalos de cinco segundos. El segundo parámetro le dice a vmstat que genere tres reportes y luego se cierre.</p>
            </section>

            <section id="se-toolkit">
                <title>SE Toolkit</title>

                <p>El SE Toolkit es un kit de herramientas de monitorización para Solaris. Su lenguaje de programación está basado en el preprocesador de C y viene con un gran número de scripts de ejemplo. Se puede usar tanto en la línea de comandos como el GUI (Interfaz Gráfico de Usuario) para mostrar información. También puede programarse para aplicar reglas a los datos del sistema.</p>

                <p>El SE Toolkit ha dado unas cuantas vueltas durante un tiempo y ha cambiado de dueño varias veces desde que se creó. Parece que ha encontrado su hogar finalmente en Sunnfreeware.com, donde puede ser descargado sin coste alguno. Hay un solo paquete para Solaris 8, 9 y 10 en SPARC y x86, e incluye el código fuente. El autor del SE Toolkit, Richard Pettit ha comenzado una nueva compañía, Captive Metrics4 que planea traer al mercado una herramienta de monitorización multiplataforma diseñada en los mismos principios que el SE Toolkit, escrito en Java.</p>
            </section>

            <section id="dtrace">
                <title>DTrace</title>

                <p>Teniendo en cuenta que DTrace está disponible para Solaris, FreeBSD, y OS X, puede ser interesante explorarlo. También está disponible mod_dtrace para httpd.</p>
            </section>

            <section id="mod_status">
                <title>mod_status</title>

                <p>El módulo mod_status da una vista general del rendimiento del servidor en un momento dado. Genera una página HTML con, entre otros, el número de procesos Apache que está funcionando y cuantos bytes ha servido cada uno, y la carga de CPU utilizada por httpd y el resto del sistema. La Apache Software
                Foundation usa <module>mod_status</module> en su <a href="http://apache.org/server-status">web site</a>. Si configura la directiva <code>ExtendedStatus On</code> en su <code>httpd.conf</code>, la página <module>mod_status</module> le dará más información a costa de un poco más de carga por cada petición. Hay una nueva página de status en la página de Apache, basada en lua que pronto se incorporará al código fuente de Apache, puede encontrar el código en <a href="https://github.com/Humbedooh/server-status">Humbedoo's server-status page at github</a>.</p>
            </section>
        </section>

        <section id="web-server-log-files">
            <title>Ficheros de Log del Servidor Web</title>

            <p>Monitorizar y analizar los ficheros de log es una de las formas más efectivas de estar al tanto de la salud del servidor y su rendimiento. Monitorizar el log de errores ayuda a detectar condiciones de error, descubrir ataques y encontrar problemas de rendimiento. Analizar los logs de acceso le indica cuán ocupado está su servidor, qué recursos son los más populares y de dónde vienen los usuarios. Los datos de ficheros de log históricos puede darle una visión inmejorable sobre las tendencias de acceso a su servidor, que le permite predecir cuando sus necesidades de rendimiento sobrepasarán las de la capacidad de su servidor.</p>

            <section id="ErrorLog">
                <title>Log de Errores</title>

                <p>El log de errores contendrá mensajes si el servidor ha alcanzado el número máximo de procesos activos o el número máximo de ficheros abiertos simultaneamente. El log de errores también refleja cuando los procesos se están generando a un ritmo mayor del usual en respuesta a bajadas repentinas de carga. Cuando el servidor arranca, se redirige el descriptor de salida estandar de errores (stderr) hacia el log de errores, así que cualquier error que httpd se encuentre después de abrir sus ficheros de log aparecerán en este log. Esto hace que sea buena práctica revisar el log de errores frecuentemente.</p>

                <p>Antes de que httpd abra sus ficheros de log, cualquier error se volcará en la salida estándar de errores stderr. Si inicia httpd manualmente, esta información de errores le aparecerá en la terminal y usted la podrá usar directamente para realizar la solución de problemas en su servidor. Si su httpd se arranca con un script de inicio, el destino de los mensajes de error iniciales dependerá del diseño de éste. El fichero <code>/var/log/messages</code> es generalmente un buen sitio donde empezar a mirar. En Windows, los primeros mensajes de error se escriben en el Log de Eventos de Aplicaciones, al que se puede acceder a través del Visor de Eventos en las Herramientas Administrativas.</p>

                <p>El Log de errores se configura con las directivas <directive module="core">ErrorLog</directive> y <directive module="core">LogLevel</directive>. El log de errores de la configuración principal de httpd recibe los mensajes de log relacionados con las funcionalidades principales del servidor: arranque, parada, fallos, generación excesiva de procesos, etc. La directiva <directive module="core">ErrorLog</directive> puede usarse también en contenedores de host virtual. El log de errores de un host virtual recibe solo mensajes específicos de ese virtualhost, tales como errores de autenticación y errores de ficheros no encontrado.</p>

                <p>En un servidor que está visible desde Internet, espere recibir multiples sondeos de vulnerabilidad y ataques de gusano en el log de errores. Muchos de estos son el objetivo de otro tipo de plataformas de servidor en lugar de Apache, pero con el estado actual de las cosas, los scripts de ataque sencillamente mandan todo lo que tienen contra cualquier puerto abierto, independientemente del servidor que se esté ejecutando o las aplicaciones que pueda haber instaladas en el servidor. Puede bloquear estos intentos usando un cortafuegos o con <a href="http://www.modsecurity.org/">mod_security</a>, pero ésto se sale del ámbito de este manual.</p>

                <p>La directiva <directive module="core">LogLevel</directive> determina qué nivel de detalle se incluye en los logs. Hay ocho niveles de log como se describe aquí:
                </p>
                <table>
                    <tr>
                        <td>
                            <p><strong>Nivel</strong></p>
                        </td>
                        <td>
                            <p><strong>Descripción</strong></p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p>emerg</p>
                        </td>
                        <td>
                            <p>Emergencias - el sistema es inestable.</p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p>alert</p>
                        </td>
                        <td>
                            <p>Se deben tomar medidas inmediatamente..</p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p>crit</p>
                        </td>
                        <td>
                            <p>Condiciones Críticas.</p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p>error</p>
                        </td>
                        <td>
                            <p>Condiciones de Error.</p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p>warn</p>
                        </td>
                        <td>
                            <p>Condiciones de Aviso.</p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p>notice</p>
                        </td>
                        <td>
                            <p>Normal pero condición significativa.</p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p>info</p>
                        </td>
                        <td>
                            <p>Informacional.</p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p>debug</p>
                        </td>
                        <td>
                            <p>Mensajes de nivel Debug (depuración)</p>
                        </td>
                    </tr>
                </table>

                <p>El nivel de log por defecto es warn. Un servidor de producción no debería ser ejecutado en nivel debug, pero incrementar el nivel de detalle puede ser útil en el log de errores para hacer análisis de fallos. Empezando con la versión 2.3.8 puede especificarse <directive module="core">LogLevel</directive> por módulo:</p>

                <highlight language="config">
                    LogLevel debug mod_ssl:warn
                </highlight>

                <p>Esto pone a todo el servidor en modo debug, excepto para <module>mod_ssl</module>, que suele ser muy ruidoso en ese nivel.</p>

            </section>

            <section id="AccessLog">
                <title>Log de Acceso</title>

                <p>Apache httpd mantiene un registro de cada petición que sirve en su fichero de log de acceso. Además de la hora y la naturaleza de la petición, httpd puede registrar la dirección ip del cliente, la fecha y la hora de la petición, el resultado y el host u otra información. Los distintos formatos de log están documentados en el manual. Este fichero existe por defecto en el servidor principal y puede configurarse por cada virtualhost usando las directivas de configuración <directive module="mod_log_config">TransferLog</directive> o <directive module="mod_log_config">CustomLog</directive>.</p>

                <p>Los logs de acceso se pueden analizar con muchos programas de licencia libre o comerciales. Paquetes conocidos de licencia libre incluyen "Analog" o "Webalizer". El análisis de log debería hacerse offline para que el servidor de log no sea sobrecargado con el procesamiento de esos ficheros de log. La mayor parte de software de analisis de log reconocen el formato "Common". Los campos en las líneas de log se explican en las siguientes entradas:</p>


                <example><pre>
195.54.228.42 - - [24/Mar/2007:23:05:11 -0400] "GET /sander/feed/ HTTP/1.1" 200 9747
64.34.165.214 - - [24/Mar/2007:23:10:11 -0400] "GET /sander/feed/atom HTTP/1.1" 200 9068
60.28.164.72 - - [24/Mar/2007:23:11:41 -0400] "GET / HTTP/1.0" 200 618
85.140.155.56 - - [24/Mar/2007:23:14:12 -0400] "GET /sander/2006/09/27/44/ HTTP/1.1" 200 14172
85.140.155.56 - - [24/Mar/2007:23:14:15 -0400] "GET /sander/2006/09/21/gore-tax-pollution/ HTTP/1.1" 200 15147
74.6.72.187 - - [24/Mar/2007:23:18:11 -0400] "GET /sander/2006/09/27/44/ HTTP/1.0" 200 14172
74.6.72.229 - - [24/Mar/2007:23:24:22 -0400] "GET /sander/2006/11/21/os-java/ HTTP/1.0" 200 13457
                </pre></example>

                <table>
                    <tr>
                        <td>
                            <p><strong>Campo</strong></p>
                        </td>
                        <td>
                            <p><strong>Contenido</strong></p>
                        </td>
                        <td>
                            <p><strong>Explicación</strong></p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p>IP de Cliente</p>
                        </td>
                        <td>
                            <p>195.54.228.42</p>
                        </td>
                        <td>
                            <p>Dirección IP desde la que se envía la petición.</p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p>Identidad RFC 1413</p>
                        </td>
                        <td>
                            <p>-</p>
                        </td>
                        <td>
                          <p>La identidad del Usuario Remoto tal y como la reporta su servicio identd</p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p>nombre de usuario</p>
                        </td>
                        <td>
                            <p>-</p>
                        </td>
                        <td>
                            <p>Nombre de usuario remoto autenticado por Apache</p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p>Marca de tiempo</p>
                        </td>
                        <td>
                            <p>[24/Mar/2007:23:05:11 -0400]</p>
                        </td>
                        <td>
                            <p>Fecha y hora de la petición</p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p>Petición</p>
                        </td>
                        <td>
                            <p>&quot;GET /sander/feed/ HTTP/1.1&quot;</p>
                        </td>
                        <td>
                            <p>La petición en si</p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p>Código de estado</p>
                        </td>
                        <td>
                            <p>200</p>
                        </td>
                        <td>
                            <p>Código de respuesta HTTP</p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p>Contenido en Bytes</p>
                        </td>
                        <td>
                            <p>9747</p>
                        </td>
                        <td>
                            <p>Bytes transferidos sin contar las cabeceras HTTP</p>
                        </td>
                    </tr>
                </table>
            </section>

            <section id="rotating-log-files">
                <title>Rotando ficheros de Log</title>

                <p>Hay muchas razones para rotar ficheros de log. Incluso aunque prácticamente ya ningún sistema operativo tiene un límite de tamaño de fichero de dos Gigabytes, los ficheros de log simplemente se hacen demasiado grandes con el tiempo. Además, no debería hacerse cualquier análisis periódico de log en ficheros que el servidor esté escribiendo. La rotación periódica de logs hace que el trabajo de análisis sea más manejable, y permite que usted pueda mantenerse al tanto de una manera más clara de las tendencias de uso del servidor.</p>

                <p>En sistemas unix, puede rotar ficheros de log sencillamente dándole al fichero antiguo un nombre nuevo con el comando mv. El servidor seguirá escribiendo en el fichero antiguo aunque tenga un nombre nuevo. Cuando envíe una señal de reinicio en caliente (graceful restart) al servidor, éste abrirá un nuevo fichero con el nombre configurado. Por ejemplo, podría ejecutar un script desde cron como este:</p>

                <example>
                    APACHE=/usr/local/apache2<br />
                    HTTPD=$APACHE/bin/httpd<br />
                    mv $APACHE/logs/access_log
                    $APACHE/logarchive/access_log-`date +%F`<br />
                    $HTTPD -k graceful
                </example>

                <p>Este método también funciona en Windows, solo que no te manera tan sencilla. Mientras que el proceso de httpd en su servidor Windows seguirá escribiendo sobre el fichero de log después de que se haya renombrado, el Servicio de Windows que ejecuta Apache no puede realizar un reinicio en caliente. Reiniciar un servicio en Windows significa pararlo y arrancarlo de nuevo. La ventaja de un reinicio en caliente es que los procesos hijo siguen respondiendo a las últimas peticiones antes de cerrarse. Mientras tanto, el servidor httpd sigue estando disponible para atender nuevas peticiones. La parada-arranque que el Servicio Windows tiene que realizar interrumpirá cualquier solicitud en progreso, y el servidor no estará disponible hasta que se haya arrancado de nuevo. Tenga en cuenta esto cuando planee las horas de sus reinicios.
                </p>

                <p>Un segundo método es usar "pipe" de logs. Desde las directivas
                  <directive module="mod_log_config">CustomLog</directive>,
                    <directive module="mod_log_config">TransferLog</directive>
                    o <directive module="core">ErrorLog
                    </directive> puede enviar datos de log hacia otro programa usando el caracter "pipe" (<code>|</code>). Por ejemplo:
                </p>

                <example>
CustomLog "|/usr/local/apache2/bin/rotatelogs /var/log/access_log 86400" common
                </example>

                <p>El programa destino del "pipe" recibirá los datos de log de Apache en su entrada estándar, y puede hacer con estos datos lo que quiera. El programa rotatelogs que viene con Apache rota de manera transparente los ficheros de log basados en un lapso de tiempo o cantidad de datos generados, y deja el fichero antiguo con un sufijo de marca de tiempo en su nombre de fichero. Este método de rotar ficheros funciona bien en plataformas unix, pero no funciona actualmente en Windows.</p>
            </section>

            <section id="logging-and-performance">
                <title>Registros de Log y Rendimiento</title>

                <p>Escribir entradas a los ficheros de log de Apache evidentemente conlleva cierta carga, pero la información recolectada por los logs es tan valiosa que bajo circunstancias normales, el registro de logs no debe desactivarse. Para un rendimiento óptimo, debería poner su contenido estático en un disco diferente que en el de los log de ficheros: los patrones de acceso son muy diferentes. Recolectar contenido del disco es una operación de lectura en un patrón relativamente aleatorio, y los ficheros de log se escriben de manera secuencial.</p>

                <p>No ponga un servidor de producción a funcionar con su <directive module="core">LogLevel</directive> configurado con debug. Este nivel de log provoca que una gran cantidad de información se escriba en el log de errores, incluyendo en el caso de acceso SSL, volcados completos de operaciones de lectura. Las implicaciones en rendimiento son significativas: use el valor por defecto "warn" en su lugar.</p>

                <p>Si su servidor tiene más de un host virtual, puede darle a cada uno un fichero de log distinto. Esto hace más facil analizar el fichero de log más adelante. Aunque, si su servidor tiene muchos host virtuales, todos los ficheros abiertos añaden más carga en su sistema, y podría ser preferible tener log con un solo fichero. Use el caracter de formato <code>%v</code> al comienzo de su <directive module="mod_log_config">LogFormat</directive>y desde la versión 2.3.8 en su <directive module="core">ErrorLog</directive> para hacer que httpd imprima el nombre del host virtual que recibe la  solicitud o el error al principio de cada línea de log. Un script sencillo en Perl puede separar el fichero después de rotar: uno se incluye con el código fuente de Apache bajo la ruta <code>support/split-logfile</code>.</p>

                <p>Puede usar la directiva <directive module="mod_log_config">BufferedLogs</directive> para que Apache recolecte muchas lineas de log en memoria antes de escribirlas a disco. Esto puede redundar en una mejora del rendimiento, pero puede afectar al orden en el que los ficheros de log se escriben en el servidor.</p>
            </section>
        </section>

        <section id="generating-a-test-load">
            <title>Generando una Carga de Prueba</title>
            
            <p>Es útil generar una carga de prueba para comprobar el rendimiento del sistema en situaciones de operación realistas. Además de paquetes de software comercial como <a href="http://learnloadrunner.com/">LoadRunner</a>, hay un gran número de herramientas libres para generar carga contra su servidor.</p>

            <ul>
                <li>Apache tiene un programa de pruebas llamado ab, siglas de Apache Bench. Puede generar carga para un servidor web solicitando una sucesión rápida de peticiones del mismo fichero. Puedes especificar el número de conexiones concurrentes y hacer que el programa se ejecute durante un tiempo determinado o un número especificado de peticiones.
                </li>

                <li>Otro generador de carga disponible sin coste es http load11. Este programa funciona con un fichero URL y puede ser compilado con soporte SSL.
                </li>

                <li>La Apache Software Foundation ofrece una herramienta que se llama flood12. Floo12 es un programa bastante sofisticado que se configura con un fichero XML.
                </li>

                <li>Por último, JMeter13 , un subproyecto de Jakarta, es una herramienta de carga hecha al completo en Java. Aunque las primeras versiones de esta aplicación eran lentas y difíciles de usar, la versión actual parece ser útil y versátil.
                </li>

                <li>
                    <p>Proyectos externos a la ASF que han demostrado ser muy buenos: grinder, httperf, tsung, <a href="http://funkload.nuxeo.org/">FunkLoad</a></p>
                </li>
            </ul>
            
            <p>Cuando haga pruebas de carga en su servidor web, por favor tenga en cuenta que si el servidor está en producción, la prueba puede afectar negativamente a los tiempos de respuesta del servidor.</p>
        </section>
    </section>

    <section id="configuring-for-performance">
        <title>Configurar para obtener Rendimiento</title>


        <section id="apache-configuration">
            <title>Configuración de httpd</title>

            <p>Apache httpd 2.2 es por defecto un servidor que hace pre-fork. Cuando el servidor arranca, el proceso padre arranca un número determinado de procesos hijos que hacen el trabajo actual de servir a las peticiones recibidas. Pero Apache httpd 2.0 introdujo el concepto de Módulo de Multi-Proceso (MPM). Los desarrolladores pueden desarrollar MPMs para que se ajuste al proceso- o una arquitectura multihilo para su sistema operativo específico. Apache 2 viene con MPMs especiales para Windows, OS/2, Netware y BeOS. En plataformas tipo-unix. los MPMs más populares son Prefork y Worker. El MPM Prefork ofrece el mismo modelo de pre-fork que usa Apache 1.3. El MPM Worker ejecuta un número de procesos hijo, y genera threads que gestionan un gran número de peticiones dentro de cada proceso hijo. En 2.4 los MPMs ya no tienen que estar vinculados al binario de httpd. Pueden cargarse intercambiare como cualquier otro módulo a través de <directive module="mod_so">LoadModule</directive>. El MPM por defecto en 2.4 es event.</p>

            <p>El número máximo de workers, sean procesos hijo en pre-fork, o hilos dentro de un proceso, es un indicativo de cuantas peticiones puede contestar simultaneamente su servidor. Es una mera estimación porque el kernel puede encolar intentos de conexión a su servidor web. Cuando su sitio web está muy ocupado y el número máximo de workers está activo, la máquina no alcanza un límite en el que los clientes dejarán de tener acceso. Sin embargo, una vez que las peticiones comienzan a acumularse, el rendimiento del sistema seguramente se verá degradado.</p>

            <p>Finalmente, si el servidor httpd en cuestión no está ejecutando código de terceros, a través de <code>mod_php</code>, <code>mod_perl</code> o similar, recomendamos el uso de <module outdated="true">mpm_event</module>. Este MPM es ideal para situaciones tipo proxy o cache, donde los servidores httpd trabajan como una fina capa entre los clientes y los servidores backend realizando el trabajo de verdad.</p>

            <section id="MaxRequestWorkers">
                <title>MaxRequestWorkers</title>

                <p>La directiva <code>MaxRequestWorkers</code> en el fichero de configuración de Apache httpd especifica el número máximo de workers que su servidor puede generar. Tiene dos directivas relacionadas, <code>MinSpareServers</code> ó <code>MinSpareThreads</code> en MPM's multihilo y <code>MaxSpareServers</code> ó <code>MaxSpareThreads</code> en MPM's multihilo, que especifican el número de Workers que Apache mantiene esperando a recibir peticiones. El número máximo absoluto de procesos se configura mediante la directiva <code>ServerLimit</code></p>
            </section>

            <section id="spinning-threads">
                <title>Rotación de hilos</title>

                <p>Para el MPM prefork las directivas de más arriba son todo lo necesario para determinar el límite de procesos. Sin embargo, si está usando un MPM multihilo la situación es un poco más complicada. Los MPMs Multihilo soportan la directiva  <code>ThreadsPerChild</code>. Apache requiere que <code>MaxRequestWorkers</code> sea divisible entre <code>ThreadsPerChild</code>. Si configura cualquiera de las dos directivas a un número que no cumple este requisito, Apache enviará un mensaje de aviso al log de errores para ajustar el valor de <code>ThreadsPerChild</code> hasta que su valor sea divisible con <code>MaxRequestWorkers</code>.</p>
            </section>

            <section id="sizing-MaxRequestWorkers">
                <title>Dimensionando MaxRequestWorkers</title>

                <p>De manera óptima, el número máximo de procesos debería configurarse para que se use toda la memoria del sistema, pero no más. Si su sistema se sobrecarga necesitará paginar memoria a disco, y el rendimiento se degradará rápidamente. La fórmula para determinar <directive module="mpm_common" name="MaxRequestWorkers">MaxRequestWorkers</directive> es muy sencilla:
                </p>

                <example>
                    RAM total - RAM para el SO - RAM para programas externos<br />
                    MaxRequestWorkers =
                    -------------------------------------------------------<br />
                    RAM para procesos httpd
                </example>

                <p>Las distinta cantidad de memoria dedicada al SO, programas externos y procesos httpd se determinan de la mejor manera mediante observación: use los comandos top y free descritos más arriba para determinar el uso de memoria de SO sin el servidor http funcionando. También puede determinar el uso del típico proceso de servidor web con top: la mayoría de implementaciones de top tienen una columna de Tamaño Residente (RSS) y una columna de memoria compartida.</p>

                <p>La diferencia entre estas dos es la cantidad de memoria por proceso. El segmento compartido realmente solo existe una vez y es usado por el código y librerías cargadas y el recuento dinámico de inter-proceso, o 'scoreboard', que Apache mantiene. Cuanta memoria usa cada proceso para sí mismo depende en gran manera del número y el tipo de modulos que usted use. El mejor método a usar para determinar esta necesidad es generar la típica prueba de carga contra su servidor web y ver hasta qué tamaño llegan sus procesos httpd.
                </p>

                <p>El parámetro de RAM para programas externos está dirigido a programas CGI y scripts que se ejecutan fuera de los procesos del servidor web. Aun así, si tiene una máquina virtual de Java ejecutando Tomcat en la misma máquina, también necesitará una cantidad significatiba de memoria. La estimación indicada más arriba le debería dar una idea de hasta dónde puede subir el valor de <code>MaxRequestWorkers</code>, pero no es una ciencia exacta.Cuando tenga dudas, sea conservador y use un valor bajo <code>MaxRequestWorkers</code>. El kernel Linux le dará a la memoria extra un buen uso para cahear accesos a disco. En Solaris necesita suficiente memoria disponible de memoria RAM real para crear cualquier proceso. Si no hay memoria real disponible, httpd comenzará a escribir mensajes 'No space left on device' (no queda espacio en el dispositivo) en el log de errores y no podrá generar nuevos procesos, así que un valor más alto de <code>MaxRequestWorkers</code> puede ser una desventaja.</p>
            </section>

            <section id="selecting-your-mpm">
                <title>Seleccionando su MPM</title>

                <p>La razón principal para seleccionar un MPM multihilo es que los hilos consumen menos recursos que los procesos, y le supone mucho menos esfuerzo al sistema cambiar entre hilos. Esto es más cierto en unos sistemas operativos que en otros. En sistemas como Solaris y AIX, manipular procesos es relativamente caro en términos de recursos del sistema. En estos sistemas, ejecutar un MPM multihilo tiene sentido. En Linux, la implementación multihilo actualmente usa un proceso por cada hilo. Los procesos en Linux son relativamente ligeros, pero eso significa que un MPM multihilo ofrece algo menos de ventaja de rendimiento que en otros sistemas.
                </p>

                <p>Desde cierta perspectiva, ejecutar un MPM multihilo podría provocar problemas de estabilidad en algunas situaciones. Por ejemplo, si un proceso hijo falla en un MPM prefork, como mucho una conexión de cliente se verá afectada. Sin embargo, si un proceso con hilos falla, todos los hilos en ese proceso desaparecen, lo cual significa que todos los clientes a los que se estaba sirviendo por ese proceso verán que su conexión es abortada. Además, están los problemas de &quot;thread-safety&quot; (seguras para multihilo), que ocurren especialmente con librerías de terceros. En aplicaciones multihilo, los hilos pueden acceder la mismas variables indiscriminadamente, no conociendo si esa variable ha sido cambiada por otro hilo.</p>

                <p>Este ha sido un punto "doloroso" en la comunidad de PHP. El procesaador de PHP depende en gran medida de librerías de terceros y no puede garantizar que que todas estas son thread-safe (seguras para uso multihilo). Las buenas noticias es que si ejecuta Apache en Linux, puede interpretar PHP con el MPM prefork sin miedo a perder demasiado rendimiento con respecto a la opción multihilo.</p>
            </section>

            <section id="spinning-locks">
                <title>Rotación de bloqueos</title>

                <p>Apache httpd mantiene un bloqueo inter-proceso alrededor de su listener de red. Para todos los propósitos prácticos, esto significa que solo un proceso httpd hijo puede recibir una petición en un momento dado. Los otros procesos o bien están ya sirviendo peticiones o están "acampando" en el bloqueo, esperando a que el listener de red esté disponible. Este proceso se visualiza mejor como una puerta giratoria, en el que solo se permite a un proceso en la puerta cada vez. En un servidor web muy cargado con peticiones llegando constantemente, la puerta gira rápidamente y se aceptan peticiones a un ritmo constante. En un servidor web con poca carga, los procesos que &quot;retienen&quot; el bloqueo pueden mantenerse en la puerta durante un tiempo, mientras tanto el resto de procesos no hacen nada y se mantienen esperando a obtener el bloqueo. En este momento, el proceso padre puede decidir que se cierren algunos hijos basando la decisión en su directiva <code>MaxSpareServers</code>.</p>
            </section>

            <section id="the-thundering-herd">
                <title>The Thundering Herd (Manada estruendosa)</title>

                <p>La función del 'accept mutex' (como este bloqueo de inter-proceso se llama) es mantener la recepción de peticiones funcionando de manera ordenada. Si el bloqueo está ausente, el servidor puede exhibir un síndrome de "Thundering Herd".</p>

                <p>Piense por un momento en un equipo de fútbol americano colocado en la línea de ataque. Si los jugadores fueran procesos Apache todos los miembros del equipo irían a por la bola simultáneamente en el saque. Un proceso la cogería y todos los demás tendrían que apelotonarse detrás en la línea de ataque para el saque. En esta metáfora, el accept mutex actua como el quarterback, entregando la &quot;pelota&quot; de conexión al proceso jugador adecuado.</p>

                <p>Mover esta cantidad de información de un lado a otro, es obviamente mucho trabajo, y, como una persona ingeligente, un servidor web inteligente intenta evitarlo cuando sea posible. Y por ello está el sistema de puerta giratoria. Últimamente, muchos sistemas operativos, incluido Linux y Solaris, han puesto código en su lugar para evitar el síndrome de Thundering Herd. Apache reconoce esto y si usted trabaja con un solo listener de red, es decir, con un solo host virtual o solo el servidor principal, Apache evitará usar un accept mutex. Si funciona con múltiples listeners (por ejemplo porque tiene un virtualhost atendiendo peticiones SSL), activará el accept mutex para evitar conflictos internos.</p>

                <p>Puede manipular el accept mutex con la directiva <code>AcceptMutex</code> en 2.2.x, o <code>Mutex</code> en 2.4.x. Además de poner el accept mutex a off, puede seleccionar el método de bloqueo. Métodos típicos de bloqueo incluyen fcntl, Semáforos System V y bloqueos pthread. No todos están disponibles en todas las plataformas, y su disponibilidad depende de configuraciones en el momento de compilar. Los distintos mecanismos de bloqueo pueden poner cierta carga en los recursos del sistema: manipúlelos con cuidado.</p>

                <p>No hay razón de peso para deshabilitar el accept mutex. Apache automáticamente reconoce cuando hay una situación de un solo listener como se describe más arriba y sabe si es seguro funcionar sin mutex en su plataforma.</p>
            </section>
        </section>
        
        <section id="tuning-the-operating-system">
            <title>Afinando el Sistema Operativo</title>

            <p>A menudo las personas buscan 'la clave mágica' que hará que su sistema rinda cuatro veces más rápido con tan solo cambiar una valor de configuración. La verdad es, los derivados de Unix de hoy en día están ya bastante bien ajustados "de fábrica" y no hay mucho que hacer para conseguir que fucionen de manera óptima. Sin embargo, hay algunas cosas que como administrador usted puede hacer para mejorar el rendimiendo.</p>

            <section id="ram-and-swap-space">
                <title>Memoria y Espacio Swap</title>

                <p>El típico mantra respecto a la RAM es &quot;más es mejor&quot;. Como se ha comentado con antelación, a la RAM sin utilizar el sistema le acaba dando buen uso como cache del sistema de ficheros. Los procesos de Apache usan más memoria si carga más módulos, especialmente si usa módulos que generan páginas de contenido dinámico, como PHP o mod_perl. Un archivo de configuración grande, con muchos host virtuales, también tiende a aumentar el uso de memoria del proceso. Tener RAM de sobra permite a Apache con más procesos hijo, que a su vez permiten a Apache servir más peticiones de manera concurrente.</p>

                <p>Mientras que varias plataformas tratan su memoria virtual de distinta manera, nunca es una buena idea trabajar con menos espacio swap basado en disco que RAM. La memoria virtual del sistema está diseñada para proveer un último recurso aparte de la RAM, pero cuando no tiene suficiente espacio en disco y se queda sin memoria swap, su máquina se para por completo. Esto puede hacer que su equipo falle, requiriendo un reinicio de máquina por el cual su hosting puede acabar cobrándole.</p>

                <p>Además, con tal pérdida de servicio naturalmente ocurre lo que usted menos quiere: cuando el mundo conoce su página web y está intentando entrar sin éxito. Si tiene suficiente espacio swap basado en disco disponible, y la máquina se sobrecarga, puede acabar siendo muy lenta mientras el sistema carga memoria swap del disco y la escribe, pero cuando la carga baja, entonces el sistema debería recuperarse. Recuerde, todavía tiene <code>MaxRequestWorkers</code> para limitar el uso de recursos.</p>

                <p>La mayoría de los sistemas operativos tipo-unix usan particiones específicas como espacio swap. Cuando el sistema arranca encuentra todas las particiones swap en los discos, por tipo de partición o porque están listadas en el fichero <code>/etc/fstab</code>, y automáticamente los activa. Cuando añade un disco al instalar el sistema operativo, asegúrese de alojar suficiente memoria swap para actualizaciones futuras de RAM. Reasignar espacio en disco en un sistema operativo es un proceso engorroso.</p>

                <p>Planifique el espacio disponible para swap en el disco duro para al menos el doble de la cantidad de RAM, quizás hasta cuatro veces en situaciones cuando alcanza el tope de RAM con frecuencia. Recuerde ajustar esta configuración cuando incremente la RAM en su sistema. En un apuro, puede usar un fichero normal como espacio swap. Para instrucciones sobre cómo hacer esto, vea las páginas de manual los comandos <code>mkswap</code> y <code>swapon</code> o <code>swap</code>.</p>
            </section>

            <section id="ulimit-files-and-processes">
                <title>ulimit: Ficheros y Procesos</title>

                <p>Con una máquina con suficiente memoria RAM y capacidad de procesador, puede hacer funcionar cientos de procesos de Apache si fuera necesario... y si el kernel lo permite.</p>

                <p>Imagine una situación en la que cientos de servidores web están funcionando; si algunos de ellos necesitan lanzar procesos CGI, se podría alcanzar rápidamente el máximo número de procesos.</p>

                <p>Sin embargo, puede cambiar este límite con el comando</p>

                <example>
                    ulimit [-H|-S] -u [newvalue]
                </example>

                <p>Esto debe cambiarse antes de arrancar el servidor web, puesto que el nuevo valor solo estará disponible en la shell actual y en programas que arranquen desde ella. En versiones nuevas del kernel de Linux el valor se ha subido a 2048. En FreeBSD, el valor parece que es bastante inusual, 513. En la shell del usuario por defecto del sistema, <code>csh</code> el equivalente es <code>limit</code> y funciona de manera análoga a la de la shell tipo-Bourne <code>ulimit</code>:</p>

                <example>
                    limit [-h] maxproc [newvalue]
                </example>

                <p>De manera similar, el kernel puede limitar el número de ficheros abiertos por proceso. Esto generalmente no es un problema en servidores pre-fork, que solo tratan una petición a la vez por procesos. Servidores multihilo, sin embargo, sirven muchas peticiones por proceso y es mucho más fácil acabar sin descriptores de fichero. Puede aumentar el número máximo de ficheros abiertos por proceso ejecutando el comando:</p>

                <example>ulimit -n [newvalue]</example>

                <p>Y reiteramos, esto debe realizarse antes de arrancar Apache.</p>
            </section>

            <section id="setting-user-limits-on-system-startup">
                <title>Configurando Límites de Usuario en el Arranque del Sistema</title>

                <p>En Linux, puede configurar los parámetros de ulimit en el arranque editando el fichero <code>/etc/security/limits.conf</code>. Este fichero le permite poner límites flexibles o estrictos por usuario o por grupo; el fichero contiene comentarios explicando estas opciones. Para activar esto, asegúrese de que el fichero <code>/etc/pam.d/login</code> contiene la línea</p>

                <example>session required /lib/security/pam_limits.so</example>

                <p>Todos los elementos pueden tener un límite 'flexible' o 'estricto': el primero es el valor por defecto y el segundo el máximo valor para ese elemento.</p>

                <p>En <code>/etc/login.conf</code> de FreeBSD estos recursos pueden limitarse o extenderse globalmente a nivel de sistema, de forma análoga a como se hace en <code>limits.conf</code>. Límites 'flexibles' pueden ser especificados con <code>-cur</code> y límites 'estrictos' con <code>-max</code>.</p>

                <p>Solaris tiene un mecanismo similar para manipuilar los valores límites en el arranque: En <code>/etc/system</code> puede configurar valores para el sistema entero en el arranque. Estos son los mismos valores que se pueden modificar con del depurador de kernel <code>mdb</code> en tiempo real. El límite flexible y estricto correspondiente a ulimit -u puede configurarse con:</p>

                <example>
                    set rlim_fd_max=65536<br />
                    set rlim_fd_cur=2048
                </example>

                <p>Solaris calcula el número máximo de procesos permitidos por usuario (<code>maxuprc</code>) basándose en la memoria total disponible en el sistema (<code>maxusers</code>). Puede examinar los valores con</p>

                <example>sysdef -i | grep maximum</example>

                <p>pero no está recomendado cambiarlos.</p>
            </section>

            <section id="turn-off-unused-services-and-modules">
                <title>Desactivar servicios y módulos que no se usan</title>

                <p>Muchas distribuciones UNIX y Linux vienen con una serie de servicios activados por defecto. Probablemente necesite algunos de ellos. Por ejemplo, su servidor web no necesita tener sendmail funcionando, y probablemente tampoco necesite el servidor NFS, etc. Apáguelos.</p>

                <p>En Linux Red Hat, la herramienta chkconfig le ayudará a hacer esto desde la línea de comandos. En sistemas Solaris <code>svcs</code> y <code>svcadm</code> le enseñará qué servicios están activados y se desactivarán respectivamente.</p>

                <p>De la misma manera, tenga un ojo crítico con los módulos de Apache que cargue. La mayor parte de distribuciones de binarios de Apache httpd, versiones pre-instaladas que vienen con distribuiciones Linux, tienen sus módulos cargados con la directiva <directive>LoadModule</directive>.</p>

                <p>Módulos sin utilizar pueden quitarse: si no depende ni de su funcionalidad ni de sus directivas de configuración, puede desactivarlos poniendo un comentario (poner el carácter '#'' delante) en la líneas correspondientes de <directive>LoadModule</directive>. Vea la documentación de cada módulo antes de decidir si lo mantiane cargado. Aunque la carga de un módulo que no se usa es pequeña, también es innecesaria.</p>
            </section>
        </section>
    </section>

    <section id="caching-content">
        <title>Cacheando Contenido</title>

        <p>Peticiones para contenido que se genera dinámicamente generalmente consumen más recursos que el contenido estático. El contenido estático consiste en ficheros sencillos como páginas, imágenes, etc. que se encuentran en el disco y se sirven de manera muy eficiente. Muchos sistemas operativos cachean automáticamente en memoria los contenidos de ficheros a los que se accede frecuentemente.</p>

        <p>Procesar solicitudes dinámicas, por el contrario, requieren mucho más esfuerzo. Ejecutando scripts CGI, pasando solicitudes a un servidor externo de aplicaciones y acceder a contenido en base de datos puede añadir retardo y carga de proceso a un servidor web ocupado. Bajo muchas circunstancias, el rendimiento se puede mejorar peticiones más realizadas de contenido dinámico convirtiéndolas en contenido estático. En esta sección se verán dos formas de gestionarlo.</p>


        <section id="making-popular-pages-static">
            <title>Convertir las Páginas Más Visitadas en Estáticas.</title>

            <p>Pre-renderizando las páginas que son más visitadas para las solicitudes más realizadas en su aplicación, puede darle una mejora significativa de rendimiento sin dejar de lado la flexibilidad del contenido generado dinámicamente. Por ejemplo, si su aplicación es un servicio de entrega de flores, probablemente quiera pre-renderizar sus página de catálogo para las rosas rojas en las semanas previas al día de los enamorados. Cuando el usuario busca rosas rojas, se sirven de páginas pre-renderizadas. Solicitudes para, por ejemplo, rosas amarillas se generarán directamente desde la base de datos. El módulo mod_rewrite incluido con Apache es una gran herramienta para implementar estas sustituciones.</p>


            <section id="example-a-statically-rendered-blog">
                <title>Ejemplo: Un plog Renderizado Estáticamente</title>
                    <!--we should provide a more useful example here.
                        One showing how to make Wordpress or Drupal suck less. -->

                <p>Blosxom es un paquete ligero de log de web que se ejecuta como CGI. Está escrito en Perl y usa texto plano para entradas de formulario. Además de ejecutarse como CGI, Blosxom puede ejecutar desde línea de comando páginas pre-renderizadas de blog. Pre-renderizando páginas a HTML estático pude resultar en mejoras de rendimiento significativas en el caso de que un gran número de personas empiece a leer el blog.</p>

                <p>Para ejecutar blosxom para generación de páginas estáticas, edite el script CGI de acuerdo con la documnetación. Configure la variable de directorio $static para el <directive>DocumentRoot</directive> del servidor web, y ejecute el script de la línea de comandos como sigue:</p>

                <example>$ perl blosxom.cgi -password='whateveryourpassword'</example>

                <p>Esto puede ejecutarse de manera periódica desde Cron, después de que suba contenido, etc. Para hacer que Apache sustituya las páginas renderizadas estáticamente por contenido dinámico, usaremos mod_rewrite. Este módulo se incluye en el ćodigo fuente de Apache, pero no se compila por defecto. Puede compilarse con el servidor pasando la opción <code>--enable-rewrite[=shared]</code> al comando configure. Muchas distribuciones de binarios de Apache vienen con <module>mod_rewrite </module> incluido. A continuación hay un ejemplo de host virtual de Apache que se beneficia de páginas de blog renderizadas:</p>

<highlight language="config">
Listen *:8001
  &lt;VirtualHost *:8001&gt;
      ServerName blog.sandla.org:8001
      ServerAdmin sander@temme.net
      DocumentRoot "/home/sctemme/inst/blog/httpd/htdocs"
      &lt;Directory "/home/sctemme/inst/blog/httpd/htdocs"&gt;
          Options +Indexes
          Require all granted
          RewriteEngine on
          RewriteCond "%{REQUEST_FILENAME}" "!-f"
          RewriteCond "%{REQUEST_FILENAME}" "!-d"
          RewriteRule "^(.*)$"              "/cgi-bin/blosxom.cgi/$1" [L,QSA]
      &lt;/Directory&gt;
      RewriteLog "/home/sctemme/inst/blog/httpd/logs/rewrite_log"
      RewriteLogLevel 9
      ErrorLog "/home/sctemme/inst/blog/httpd/logs/error_log"
      LogLevel debug
      CustomLog "/home/sctemme/inst/blog/httpd/logs/access_log" common
      ScriptAlias "/cgi-bin/" "/home/sctemme/inst/blog/bin/"
      &lt;Directory "/home/sctemme/inst/blog/bin"&gt;
          Options +ExecCGI
          Require all granted
      &lt;/Directory&gt;
  &lt;/VirtualHost&gt;
</highlight>

                <p>Las directivas <directive>RewriteCond</directive> y <directive>RewriteRule</directive> dicen que, si el recurso requerido no existe como fichero o directorio, su path se le pasará al CGI Blosxom para su renderizado. Blosxom usa Path Info (Información de Ruta) para especificar entradas de blog y páginas de índice, y esto quiere decir que si una ruta en concreto existe como fichero estático en el sistema de ficheros, el fichero se sirve directamente. Cualquier petición que no está pre-renderizada se sirve por el CGI. Esto significa que las entradas individuales, que muestran los comentarios, se sirven siempre por el CGI que entonces indica que su spam de comentarios siempre está visible. Esta configuración oculta el CGI Blosxom de la URL visible por el usuario en su barra de direcciones del navegador. Mod_rewrite es un módulo muy potente y versatil, investíguelo para llegar a una configuración que sea la más adecuada para su situación.</p>
            </section>
        </section>

        <section id="caching-content-with-mod_cache">
            <title>Cacheando Contenido con mod_cache</title>

            <p>El módulo mod_cache facilita cacheo inteligente de respuestas HTTP: está al tanto de los tiempos de expiración y requerimientos de contenido que son parte de la especificación HTTP. El módulo mod_cache cachea contenido de respuestas de URL. Si el contenido que se envía al cliente es considerado como cacheable, se guarda en disco. Peticiones posteriores a la misma URL se sirven del disco directamente desde la cache. El modulo que provee cache para mod_cache, mod_disk_cache, determina el contenido que se almacena en disco. Para la mayoría de sistemas de servidores tendrán más disco disponible que memoria, y es buno anotar que algunos kernel de sistema operativo frecuentemente cachean el acceso a disco de manera transparente en memoria, así que replicar esto en el servidor no es útil.</p>

            <p>Para activar un cacheo eficiente y evitar presentar al usuario contenido obsoleto o inválido, la aplicación que general el contenido real debe enviar las cabeceras de respuesta correctas. Sin cabeceras como <code>Etag:</code>, <code>Last-Modified:</code> o <code>Expires:</code>,  <module>mod_cache</module> no puede tomar la decisión adecuada sobre qué contenido debe cachear, servir desde la cache o no tocar. Cuando esté probando el cacheo, podrá encontrarse con que tiene que modificar su aplicación, o si esto es imposible, hacer una selección de URLs que causan problemas con el cacheo. Los módulos de mod_cache no se compilan por defecto, pero puede activarlos pasando la opción <code>--enable-cache[=shared]</code> al script configure. Si usa una distribución de binarios de Apache httpd, o Apache venía con un port o colección de paquetes, puede que ya venga <module>mod_cache</module> incluido.</p>


            <section id="example-wiki">
                <title>Ejemplo: wiki.apache.org</title>
                    <!-- Is this still the case? Maybe we should give
                        a better example here too.-->
                <p>El Wiki de la Apache Software Foundation se sirve con MoinMoin. MoinMoin está escrito en Python y se ejecuta como CGI. Hasta la fecha, cualquier intento de ejecutarlo con mod_python no ha tenido éxito. El CGI ha demostrado poner una carga insoportable en la máquina servidor, especialmente cuando el wiki estaba siendo indexado por motores de búsqueda como Google. Para aligerar la carga en la máquina servidor, el equipo de Infraestructuras de Apache activó mod_cache. Resultó que MoinMoin necesitaba un pequeño parche para asegurar un comportamiento adecuado detrás del servidor de cacheo: algunas peticiones no pueden cachearse nunca y los módulos correspondientes de Python fueron parcheados para enviar las cabeceras de respuesta HTTP adecuadas. Después de esta modificación, la cache delante del Wiki fue activada con el siguiente fragmento de configuración en <code>httpd.conf</code>:</p>

<highlight language="config">
CacheRoot /raid1/cacheroot
CacheEnable disk /
# Una página modificada hace 100 minutos expirará en 10 minutos
CacheLastModifiedFactor .1
# Siempre comprobar de nuevo después de 6 horas
CacheMaxExpire 21600
</highlight>

                <p>Esta configuración intentará cachear cualquiera y todo el contenido dentro del host virtual. Nunca cacheará contenido durante más de 6 horas (la directiva <directive module="mod_cache">CacheMaxExpire</directive>). Si no hay cabecera <code>Expires:</code> presente en la respuesta, <module>mod_cache</module> calculará un periodo de expiración con la cabecera <code>Last-Modified:</code>. El cálculo usando <directive module="mod_cache">CacheLastModifiedFactor</directive> está basado en la asunción de que la página se modificó recientemente, que probablemente cambie en un futuro cercano y que tendrá que ser re-cacheada.</p>

                <p>Tenga en cuenta que puede compensar <em>deshabilitar</em> la cabecera <code>ETag:</code>: Para ficheros más pequeños que 1k el servidor tiene que calcular el checksum (generalmente MD5) y después enviar una respuesta <code>304 Not Modified</code>, que usará algo de CPU y aun así saturar los recursos de red para la transferencia (un paquete TCP). Para recursos mayores que 1k puede resultar caro en CPU calcular la cabecera de cada petición. Desafortunadamente no existe una manera de cachear estas cabeceras.</p>

<highlight language="config">
&lt;FilesMatch "\.(jpe?g|png|gif|js|css|x?html|xml)"&gt;
    FileETag None
&lt;/FilesMatch&gt;
</highlight>

                <p>Esto deshabilitará la generación de la cabecera <code>ETag:</code> para la mayor parte de recursos estáticos. El servidor no calcula estas cabeceras para recursos dinámicos.</p>
            </section>
        </section>
    </section>

    <section id="further-considerations">
        <title>Otras Consideraciones</title>

        <p>Armado con el conocimiento de cómo afinar el sistema para entregar el rendimiento deseado, pronto descubrirá que <em>un</em> solo sistema puede provocar un cuello de botella. Cómo hacer que un sistema sea apto para crecimiento, o como afinar un número de sistemas como uno solo será comentado en la página<a href="http://wiki.apache.org/httpd/PerformanceScalingOut">PerformanceScalingOut</a>.
        </p>
    </section>
</manualpage>