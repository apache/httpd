<?xml version='1.0' encoding='KOI8-R' ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.ru.xsl"?>
<!-- English Revision: 421100 -->

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
<!-- Translator: Veniamin Zolotuhin(venya@dergachi.net)-->
<!-- Reviewers:                                        -->
<!--             Ivan Shvedov (ivan@tversu.ru)         -->
<!--             Arthur Reznikov (art@altair.tversu.ru)-->
<!--***************************************************-->

<manualpage metafile="index.xml.meta">
<parentdocument href="../"/>

   <title>Документация по виртуальным хостам в Apache</title>

<summary>

    <p>Термин <cite>виртуальный хост</cite> относится к практике
    размещения более чем одного веб-сайта (например,
    <code>www.company1.com</code> и <code>www.company2.com</code>)
    на одной машине. Виртуальный хост может быть как &#0171;<a
    href="ip-based.html">привязанным к IP-адресу</a>&#0187;, что означает
	использование отдельного IP адреса для каждого сайта, либо &#0171;<a
    href="name-based.html">привязанным к имени</a>&#0187;, позволяя вам
    иметь несколько различных имён для каждого IP-адреса. Факт того,
	что эти сайты работают на одном и том же физическом сервере,
	не очевиден конечным пользователям.</p>

    <p>Apache был одним из первых серверов, который поддерживал IP-привязанные
    виртуальные хосты. Версии Apache 1.1 и более новые поддерживают как
    IP-привязанные, так и виртуальные хосты, определяемые по имени.
    Последний вариант виртуальных хостов также иногда
    называют <em>хост-привязанными</em> или <em>не-IP виртуальными хостами</em>.</p>

    <p>Ниже вы видите список документов, которые детально объясняют
    поддержку виртуальных хостов в Apache 1.3 и выше.</p>

</summary>

<seealso><module>mod_vhost_alias</module></seealso>
<seealso><a href="name-based.html">Виртуальные хосты, основанные на имени</a></seealso>
<seealso><a href="ip-based.html">IP-привязанные виртуальные хосты</a></seealso>
<seealso><a href="examples.html">Примеры виртуальных хостов</a></seealso>
<seealso><a href="fd-limits.html">Ограничения файловых дескрипторов</a></seealso>
<seealso><a href="mass.html">Массовый виртуальный хостинг</a></seealso>
<seealso><a href="details.html">Подробности выбора соответствующего хоста</a></seealso>

<section id="support"><title>Поддержка виртуальных хостов</title>

    <ul>
      <li><a href="name-based.html">Виртуальные хосты, основанные на имени</a>
	  (несколько веб-сайтов на одном IP адресе).</li>
      <li><a href="ip-based.html">IP-привязанные виртуальные хосты</a> (отдельный
	  IP адрес для каждого веб-сайта).</li>
      <li><a href="examples.html">Примеры виртуальных хостов для стандартных случаев</a>.</li>
      <li><a href="fd-limits.html">Ограничения файловых дескрипторов</a> (или,
      <em>Too many log files</em>)</li>
      <li><a href="mass.html">Динамически конфигурируемый массовый виртуальный хостинг</a></li>
      <li><a href="details.html">Подробное обсуждение алгоритма выбора соответствующего хоста</a></li>
    </ul>

</section>

<section id="directives"><title>Конфигурационные директивы</title>

    <ul>
      <li><directive type="section"
           module="core">VirtualHost</directive></li>
      <li><directive module="core">NameVirtualHost</directive></li>
      <li><directive module="core">ServerName</directive></li>
      <li><directive module="core">ServerAlias</directive></li>
      <li><directive module="core">ServerPath</directive></li>
    </ul>

    <p>Если вы пытаетесь отлаживать вашу конфигурацию с виртуальными хостами, то
    ключ для запуска Apache из командной строки <code>-S</code> будет крайне полезен.
    То есть, слудет использовать следующую команду:</p>

    <example>
    /usr/local/apache2/bin/httpd -S
    </example>

    <p>Эта команда распечатает описание того, как Apache разобрал
    файл конфигурации. Тщательное изучение IP адресов и имён серверов
    поможет найти ошибки конфигурации. (Смотрите также
    документацию к программе <program>httpd</program> для
	изучения других параметров для запуска из командной строки.)</p>

</section>
</manualpage>

