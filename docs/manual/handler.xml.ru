<?xml version="1.0" encoding="KOI8-R" ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="./style/manual.ru.xsl"?>
<!-- English Revision: 396056:421100 (outdated) -->

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

<manualpage metafile="handler.xml.meta">

  <title>Использование обработчиков в Apache</title>

  <summary>
    <p>Этот документ описывает использование обработчиков (handlers) в Apache.</p>
  </summary>

  <section id="definition">
    <title>Что такое обработчик</title>
    <related>
      <modulelist>
        <module>mod_actions</module>
        <module>mod_asis</module>
        <module>mod_cgi</module>
        <module>mod_imagemap</module>
        <module>mod_info</module>
        <module>mod_mime</module>
        <module>mod_negotiation</module>
        <module>mod_status</module>
     </modulelist>
      <directivelist>
        <directive module="mod_actions">Action</directive>
        <directive module="mod_mime">AddHandler</directive>
        <directive module="mod_mime">RemoveHandler</directive>
        <directive module="core">SetHandler</directive>
      </directivelist>
    </related>


    <p>Обработчик является внутренней структурой
    Apache, которая задаёт поведение сервера при обработке
    запрашиваемого файла. Как правило, каждому файлу соответствует
    свой внутренний обработчик, который назначается сервером
    исходя из типа файла. Обычно файлы просто возвращаются
    пользователю, но некоторые типы файлов предварительно
    обрабатываются (handled) сервером.</p>

    <p>В Apache 1.1 добавлена возможность использовать обработчики
    явно. Причём обработка файлов может основываться
    теперь не только на их типе, но и на расширении файлов или
    их местонахождении. Это представляется наиболее удачным
    решением, во-первых потому, что это решение элегантно, а
    во-вторых, это позволяет ассоциировать с файлом как
    тип, <strong>так и</strong> обработчик. (См. также
    <a href="mod/mod_mime.html#multipleext">&#171;Файлы с несколькими
    расширениями&#187;</a>)</p>

    <p>Обработчики могут представлять из себя как
    вкомпилированные в сервер (или подключаемые с помощью
    модулей) функции, или они могут быть добавлены с помощью
    директивы <directive module="mod_actions">Action</directive>.
    В стандартном дистрибутиве сервера имеются следующие встроенные
    обработчики:</p>

    <ul>
      <li><strong>default-handler</strong>: Посылает файл, используя функцию
      <code>default_handler()</code>, которая является обработчиком
      по-умолчанию для статических файлов. (ядро)</li>

      <li><strong>send-as-is</strong>: Посылает файл, содержащий в
      себе HTTP заголовки, как есть. (<module>mod_asis</module>)</li>

      <li><strong>cgi-script</strong>: Обрабатывает файл как CGI-скрипт.
      (<module>mod_cgi</module>)</li>

      <li><strong>imap-file</strong>: Обрабатывает файл как карту изображения
      (imagemap). (<module>mod_imagemap</module>)</li>

      <li><strong>server-info</strong>: Возвращает конфигурационную
      информацию сервера. (<module>mod_info</module>)</li>

      <li><strong>server-status</strong>: Возвращает отчет о состоянии
      сервера. (<module>mod_status</module>)</li>

      <li><strong>type-map</strong>: Обрабатывает файл как карту типов
      (type map). (<module>mod_negotiation</module>)</li>
    </ul>
  </section>
  <section id="examples">
    <title>Примеры</title>

    <section id="example1">
      <title>Обработка статического документа CGI-скриптом</title>

      <p>При использовании следующих директив, каждый запрос файла
      с расширением <code>html</code> будет запускать на выполнение
      CGI-скрипт <code>footer.pl</code> для предварительной обработки
      запрашиваемого файла.</p>

      <example>
        Action add-footer /cgi-bin/footer.pl<br/>
        AddHandler add-footer .html
      </example>

      <p>В этом случает CGI-скрипт ответственен за то, чтобы
      выслать пользователю запрошенный документ (на который указывает
      переменная окружения <code>PATH_TRANSLATED</code>), сделав
      в нём предварительно все необходимые изменения.</p>

    </section>
    <section id="example2">
      <title>Файлы с HTTP заголовками</title>

      <p>Следующие несколько директив заставят выполняться обработчик
      <code>send-as-is</code>, который используется для файлов, содержащих
      свои собственные HTTP-заголовки. Все файлы в каталоге
      <code>/web/htdocs/asis/</code> будут обрабатываться обработчиком
      <code>send-as-is</code>, независимо от их расширения.</p>

      <example>
        &lt;Directory /web/htdocs/asis&gt;<br/>
        SetHandler send-as-is<br/>
        &lt;/Directory&gt;
      </example>

    </section>
  </section>
  <section id="programmer">
    <title>Замечание для программистов</title>

    <p>Для того чтобы можно было использовать обработчики, в
    <a href="developer/API.html">Apache API</a> были внесены
    некоторые дополнения. В частности, в структуру <code>request_rec</code>
    было добавлено новое поле:</p>

    <example>
      char *handler
    </example>

    <p>Если вы хотите в своём модуле использовать обработчик,
    то всё, что вам надо сделать, это записать в <code>r-&gt;handler</code>
    имя соответствующего обработчика, причём сделать это необходимо
    перед тем, как запрос доходит до стадии <code>invoke_handler</code>.
    Обработчики реализуются точно так же, как и раньше,
    за исключением лишь того, что теперь необходимо указывать
    имя обработчика, а не тип содержимого (content type).
    Хотя это и не является обязательным, но существуют следующие
    правила именования обработчиков - необходимо использовать
    слова, разделённые дефисом и не содержащие косых черт - это
    позволит не пересекаться с пространством имён медиа-типов (media type).</p>
  </section>
</manualpage>
