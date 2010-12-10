<?xml version='1.0' encoding='KOI8-R' ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.ru.xsl"?>
<!-- English Revision: 421100:1044382 (outdated) -->

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

<!--***************************************************-->
<!-- Translator: Ilia Soldatenko (soldis@tversu.ru)    -->
<!-- Reviewers:                                        -->
<!--             Ivan Shvedov (ivan@tversu.ru)         -->
<!--             Arthur Reznikov (art@altair.tversu.ru)-->
<!--***************************************************-->

<manualpage metafile="invoking.xml.meta">

  <title>Запуск Apache</title>

<summary>
    <p>На Windows платформах Apache обычно работает как сервис Windows NT/2000/XP
    или как консольное приложение Windows 95/ME. Для получения более подробной
    информации по этому вопросу, обратитесь к документам, объясняющим <a
    href="platform/windows.html#winsvc">работу Apache под Windows в качестве сервиса</a> и
    <a href="platform/windows.xml#wincons">работу Apache под Windows в качестве консольного
    приложения</a>.</p>

    <p>В Unix программа <program>httpd</program> представляет собой
    демон, выполняющийся в фоновом режиме и обслуживающий поступающие запросы.
    О том, каким образом можно запустить <program>httpd</program> и что в результате этого
    получится, и рассказывается в этом документе.</p>
</summary>

<seealso><a href="stopping.html">Останов и перезапуск</a></seealso>
<seealso><program>httpd</program></seealso>
<seealso><program>apachectl</program></seealso>

<section id="startup"><title>Что происходит в момент запуска Apache</title>

    <p>Если в директиве <directive module="mpm_common">Listen</directive>
    в конфигурационном файле указано значение 80 (задаваемое по умолчанию)
    или любое другое значение порта меньшее 1024, то для запуска Apache
    необходимо быть привилегированным пользователем, так как Apache придется
    подключаться к привилегированному порту. После того, как сервер запустился
    и выполнил ряд подготовительных операций, таких как открытие своих log-файлов,
    он порождает несколько <em>процессов потомков</em>, которые и будут выполнять
    всю работу по обработке запросов от клиентов. Основной процесс <code>httpd</code>
    выполняется с правами привилегированного пользователя, в то время как процессы
    потомки имеют меньший приоритет. Все это контролируется <a
    href="mpm.html">МП-модулем</a>, который компилируется вместе с сервером.</p>

    <p>Для запуска демона <program>httpd</program> лучше всего использовать скрипт
    <program>apachectl</program>. Этот скрипт устанавливает ряд
    переменных окружения, необходимых для правильной работы сервера под некоторыми
    операционными системами, а затем запускает исполняемый файл <program>httpd</program>.
    Скрипт <program>apachectl</program> передаст серверу любую командную строку, так что
    при вызове можно указывать в его командной строке все необходимые для сервера опции.
    Вы также можете вручную внести некоторые изменения в скрипт <program>apachectl</program>,
    в частности, изменив значение переменной <code>HTTPD</code> для запуска Apache
    из другого каталога, и указав опции, которые будут передаваться серверу <em>каждый раз</em>
    при его запуске.</p>

    <p>Первым делом <code>httpd</code> находит и считывает <a href="configuring.html">конфигурационный
    файл</a> <code>httpd.conf</code>. Путь к этому файлу задается еще во время сборки сервера,
    но его можно изменить и после этого, запустив сервер с опцией <code>-f</code>, как это показано
    в следующем примере</p>

<example>/usr/local/apache2/bin/apachectl -f
      /usr/local/apache2/conf/httpd.conf</example>

    <p>Если во время запуска не возникло никаких проблем, то сервер отсоединится
    от консоли и приглашение на ввод командной строки вернется к пользователю
    практически мгновенно. Это указывает на то, что сервер запустился и теперь
    выполняет свою работу. Теперь вы можете, используя браузер, подключиться к
    нему и увидеть тестовую страницу, находящуюся в каталоге
    <directive module="core">DocumentRoot</directive>, а также локальную копию документации,
    ссылку на которую вы найдете на той же странице.</p>
</section>

<section id="errors"><title>Ошибки, которые могут возникнуть во время запуска</title>

    <p>Если во время запуска Apache произойдет какая-либо фатальная ошибка,
    то перед тем, как завершить свою работу, сервер пошлет на консоль или в
    <directive module="core">ErrorLog</directive> сообщение, описывающее
    данную ошибку. Наиболее распространенным сообщением об ошибке является
    <code>"Unable to bind to Port ..."</code>. Подобная ошибка возникает в двух случаях:</p>

    <ul>
      <li>Если вы пытаетесь запустить сервер на привилегированном порту, будучи зарегистрированным
      в системе как обычный пользователь; или</li>

      <li>Если вы пытаетесь запусть сервер, когда в системе уже есть выполняющийся демон Apache
      или другой web-сервер, слушающий тот же самый порт.</li>
    </ul>

    <p>Решение многих подобных проблем можно найти на странице
    <a href="faq/">FAQ</a>.</p>
</section>

<section id="boot"><title>Запуск сервера вместе с запуском всей системы</title>

    <p>Если вы хотите, чтобы сервер запускался автоматически после перезагрузки системы,
    добавьте вызов скрипта <program>apachectl</program> в системные файлы, отвечающие за загрузку
    операционной среды (обычно это <code>rc.local</code> или файлы в каталоге <code>rc.N</code>).
    Это приведет к запуску Apache от имени привилегированного пользователя.
    Во избежание проблем с безопасностью системы, убедитесь, что сервер сконфигурирован правильно.</p>

    <p>Скрипт <program>apachectl</program> разработан таким образом, что он может
    действовать как стандартный init-скрипт системы SysV; он может принимать
    аргументы <code>start</code>, <code>restart</code>, и <code>stop</code>
    и переводить их в соответствующие сигналы процессу <program>httpd</program>.
    Поэтому чаще всего вам достаточно сделать ссылку на <program>apachectl</program>
    в запускном каталоге процесса init. Но прежде чем делать это, узнайте
    точные требования вашей системы.</p>
</section>

<section id="info"><title>Дополнительная информация</title>

    <p>Дополнительную информацию по опциям командной строки <program>httpd</program>
    и <program>apachectl</program>, а также других
    вспомогательных программ, вы можете найти на странице <a href="programs/">"Сервер
    и вспомогательные программы"</a>. Имеется также <a href="mod/directives.html">документация</a>
    на все модули, входящие в дистрибутив Apache, и все директивы, которые они предоставляют.</p>
</section>

</manualpage>
