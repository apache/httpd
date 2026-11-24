<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.es.xsl"?>
<!-- English Revision: 1933510 -->
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

<modulesynopsis metafile="mod_unique_id.xml.meta">

<name>mod_unique_id</name>
<description>Proporciona una variable de entorno con un identificador
único para cada petición</description>
<status>Extension</status>
<sourcefile>mod_unique_id.c</sourcefile>
<identifier>unique_id_module</identifier>

<summary>

    <p>Este módulo proporciona un token mágico para cada petición que está
    garantizado que es único entre "todas" las peticiones bajo condiciones
    muy específicas. El identificador único es incluso único entre
    varias máquinas en un clúster de máquinas configurado correctamente. La
    variable de entorno <code>UNIQUE_ID</code> se establece con el
    identificador de cada petición. Los identificadores únicos son útiles
    por varias razones que están fuera del alcance de este documento.</p>
</summary>

<section id="theory">
    <title>Teoría</title>

    <p>Primero, un breve resumen de cómo funciona el servidor Apache en
    máquinas Unix. Esta característica actualmente no está soportada en
    Windows NT. En máquinas Unix, Apache crea varios procesos hijos, que
    procesan las peticiones de una en una. Cada hijo puede servir varias
    peticiones durante su vida. A efectos de esta discusión, los procesos
    hijos no comparten ningún dato entre sí. Nos referiremos a ellos como
    <dfn>procesos httpd</dfn>.</p>

    <p>Su sitio web tiene una o más máquinas bajo su control
    administrativo, a las que llamaremos conjuntamente un clúster de
    máquinas. Cada máquina puede ejecutar posiblemente varias instancias de
    Apache. Todas ellas en conjunto se consideran "el universo", y con
    ciertas suposiciones mostraremos que en este universo podemos generar
    identificadores únicos para cada petición, sin necesidad de una
    comunicación extensa entre las máquinas del clúster.</p>

    <p>Las máquinas de su clúster deben cumplir estos requisitos. (Incluso
    si solo tiene una máquina, debería sincronizar su reloj con NTP.)</p>

    <ul>
      <li>Los relojes de las máquinas están sincronizados mediante NTP u
      otro protocolo de tiempo de red.</li>
    </ul>

    <note><title>Cambio en la versión 2.4.29 y posteriores</title>
    <p>En versiones anteriores, la unicidad también requería que cada
    máquina tuviera una dirección IP distinta. Desde la versión 2.4.29, el
    módulo usa un generador de números pseudoaleatorios criptográfico
    (PRNG) inicializado al arrancar, lo que elimina la dirección IP y el
    pid del identificador y suprime la necesidad de nombres de host
    distintos o de un retardo de arranque.</p></note>

    <p>En cuanto a las suposiciones sobre el sistema operativo, asumimos
    que los pids (identificadores de proceso) caben en 32 bits. Si el
    sistema operativo usa más de 32 bits para un pid, la corrección es
    trivial, pero debe realizarse en el código.</p>

    <p>Dadas esas suposiciones, en un único punto en el tiempo podemos
    identificar cualquier proceso httpd en cualquier máquina del clúster
    frente a todos los demás procesos httpd. El valor raíz generado por el
    PRNG y el índice de hilo son suficientes para lograrlo. Un proceso
    httpd puede gestionar varias peticiones simultáneamente si usa un MPM
    multihilo. Para identificar los hilos, usamos un índice de hilo que
    Apache httpd utiliza internamente. Así que para generar identificadores
    únicos para las peticiones solo necesitamos distinguir entre distintos
    puntos en el tiempo.</p>

    <p>Para distinguir el tiempo usaremos una marca de tiempo Unix
    (segundos desde el 1 de enero de 1970 UTC) y un contador de 16 bits. La
    marca de tiempo solo tiene una granularidad de un segundo, por lo que
    el contador se usa para representar hasta 65536 valores durante un
    mismo segundo. La cuádrupla <em>( ip_addr, pid, time_stamp, counter
    )</em> es suficiente para enumerar 65536 peticiones por segundo por
    proceso httpd. Sin embargo, existen problemas con la reutilización de
    pids a lo largo del tiempo, y el contador se usa para mitigar este
    problema.</p>

    <p>Cuando se crea un hijo httpd, el contador se inicializa con (los
    microsegundos actuales divididos por 10) módulo 65536 (esta fórmula se
    eligió para eliminar algunos problemas de varianza con los bits de
    orden bajo de los temporizadores de microsegundos en algunos sistemas).
    Cuando se genera un identificador único, la marca de tiempo usada es el
    momento en que la petición llegó al servidor web. El contador se
    incrementa cada vez que se genera un identificador (y se le permite dar
    la vuelta).</p>

    <p>El kernel genera un pid para cada proceso al bifurcarlo, y se
    permite que los pids den la vuelta (son de 16 bits en muchos Unix,
    aunque los sistemas más recientes los han ampliado a 32 bits). Así que,
    con el tiempo, el mismo pid se reutilizará. Sin embargo, a menos que se
    reutilice dentro del mismo segundo, no se destruye la unicidad de
    nuestra cuádrupla. Es decir, asumimos que el sistema no genera 65536
    procesos en un intervalo de un segundo (incluso podrían ser 32768
    procesos en algunos Unix, pero ni siquiera eso es probable que
    ocurra).</p>

    <p>Suponga que el tiempo se repite por alguna razón. Es decir, suponga
    que el reloj del sistema se estropea y vuelve a un momento pasado (o se
    adelanta demasiado, se corrige correctamente, y luego vuelve a visitar
    ese momento futuro). En este caso podemos demostrar fácilmente que
    podemos obtener una reutilización del pid y de la marca de tiempo. La
    elección del inicializador del contador está pensada para ayudar a
    evitar esto. Tenga en cuenta que realmente queremos un número aleatorio
    para inicializar el contador, pero no hay números fácilmente
    disponibles en la mayoría de los sistemas (<em>es decir</em>, no se
    puede usar rand() porque hay que inicializar el generador, y no se
    puede inicializar con la hora porque la hora, al menos con una
    resolución de un segundo, se ha repetido).
    Esta no es una defensa perfecta.</p>

    <p>¿Qué tan buena es esta defensa? Suponga que una de sus máquinas
    sirve como máximo 500 peticiones por segundo (lo cual es un límite
    superior bastante razonable a día de hoy, porque los sistemas en
    general hacen algo más que servir simplemente archivos estáticos).
    Para hacerlo, requerirá un número de hijos que depende de cuántos
    clientes concurrentes tenga. Pero seremos pesimistas y supondremos que
    un único hijo es capaz de servir 500 peticiones por segundo. Hay 1000
    valores de inicio posibles para el contador tales que dos secuencias de
    500 peticiones se solapan. Así que hay un 1,5% de probabilidad de que,
    si el tiempo (con una resolución de un segundo) se repite, este hijo
    repita un valor de contador, y se rompa la unicidad. Este fue un
    ejemplo muy pesimista, y con valores del mundo real es aún menos
    probable que ocurra. Si su sistema es tal que todavía es probable que
    ocurra, entonces quizá debería hacer el contador de 32 bits (editando
    el código).</p>

    <p>Puede que le preocupe que el reloj se "retrase" durante el horario
    de verano. Sin embargo, esto no es un problema porque las horas usadas
    aquí son UTC, que "siempre" avanzan. Tenga en cuenta que los Unix
    basados en x86 pueden necesitar una configuración adecuada para que
    esto sea cierto: deben configurarse para asumir que el reloj de la
    placa base está en UTC y compensar en consecuencia. Pero aun así, si
    está ejecutando NTP, su hora UTC será correcta muy poco después de
    reiniciar.</p>

    <!-- FIXME: thread_index is unsigned int, so not always 32bit.-->
    <p>Desde la versión 2.4.29, la variable de entorno
    <code>UNIQUE_ID</code> se construye codificando un valor de 160 bits
    (marca de tiempo de 32 bits, raíz del PRNG de 80 bits, contador de 16
    bits, índice de hilo de 32 bits) usando el
    alfabeto <code>[A-Za-z0-9_-]</code> de una forma similar a la
    codificación base64 de MIME, produciendo 27 caracteres. El alfabeto
    base64 de MIME es en realidad <code>[A-Za-z0-9+/]</code>, pero
    <code>+</code> y <code>/</code> necesitan codificarse de forma especial
    en las URL, lo que los hace menos deseables. Todos los valores se
    codifican en orden de bytes de red, de modo que la codificación es
    comparable entre arquitecturas con distinto orden de bytes. El orden
    real de la codificación es: marca de tiempo, raíz, contador, índice de
    hilo. Este orden tiene un propósito, pero debe subrayarse que las
    aplicaciones no deberían analizar la codificación. Las aplicaciones
    deberían tratar el <code>UNIQUE_ID</code> codificado completo como un
    token opaco, que solo puede compararse con otros
    <code>UNIQUE_ID</code>s para comprobar la igualdad.</p>

    <p>El orden se eligió de forma que sea posible cambiar la codificación
    en el futuro sin preocuparse por colisiones con una base de datos
    existente de <code>UNIQUE_ID</code>s. Las nuevas codificaciones también
    deberían mantener la marca de tiempo como primer elemento, y por lo
    demás pueden usar el mismo alfabeto y longitud de bits. Dado que las
    marcas de tiempo son esencialmente una secuencia creciente, basta con
    tener un <em>segundo bandera</em> en el que todas las máquinas del
    clúster dejen de servir peticiones y dejen de usar el formato de
    codificación antiguo. Después pueden reanudar las peticiones y empezar
    a emitir las nuevas codificaciones.</p>

    <p>Creemos que esta es una solución razonablemente portable a este
    problema. Los identificadores generados tienen esencialmente una vida
    infinita porque los identificadores futuros se pueden hacer más largos
    según se necesite. Esencialmente no se requiere ninguna comunicación
    entre las máquinas del clúster (solo se necesita la sincronización NTP,
    que tiene poca sobrecarga), ni comunicación entre procesos httpd (la
    comunicación es implícita en la semilla del PRNG asignada al
    arrancar).</p>
</section>


</modulesynopsis>
