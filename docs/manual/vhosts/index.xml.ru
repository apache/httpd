<?xml version='1.0' encoding='KOI8-R' ?>
<!DOCTYPE manualpage SYSTEM "../style/manualpage.dtd">

<!--***************************************************-->
<!-- English revision: 1.3.2.7                         -->
<!--***************************************************-->
<!-- Translator: Veniamin Zolotuhin(venya@dergachi.net)-->
<!-- Reviewers:                                        -->
<!--             Ivan Shvedov (ivan@tversu.ru)         -->
<!--             Arthur Reznikov (art@altair.tversu.ru)-->
<!--***************************************************-->

<?xml-stylesheet type="text/xsl" href="../style/manual.ru.xsl"?>

<manualpage metafile="index.xml.meta">
<parentdocument href="../"/>

   <title>Документация по виртуальным хостам в Apache</title>

<summary>

    <p>Термин <cite>виртуальный хост</cite> используется при размещении
    более чем одного веб-сайта (например
    <code>www.company1.com</code> и <code>www.company2.com</code>)
    на одной машине. Виртуальный хост может быть как "<a
    href="ip-based.html">базированным на IP-адресе</a>", что означает
	использование отдельного IP адреса для каждого сайта, либо "<a
    href="name-based.html">базированным на имени</a>", позволяя вам
    иметь несколько различных имен для каждого IP-адреса. Факт того,
	что эти сайты работают на одном и том же физическом сервере
	не очевиден конечным пользователям.</p>

    <p>Apache был одним из первых серверов, который поддерживал IP-базированные
    виртуальные хосты. Версии Apachr 1.1 и более новые поддерживают как
    IP-базированные так и виртуальные хосты, определяемые по имени
    (vhosts). Последний вариант виртуальных хостов также иногда
    называют <em>хост-базированными</em> или <em>не-IP виртуальными хостами</em>.</p>

    <p>Ниже вы видите список документов, которые детально объясняют
    поддержку виртуальных хостов в Apache 1.3 и выше.</p>

</summary>

<seealso><module>mod_vhost_alias</module></seealso>
<seealso><a href="name-based.html">Виртуальные хосты основанные на имени</a></seealso>
<seealso><a href="ip-based.html">IP-базированные виртуальные хосты</a></seealso>
<seealso><a href="examples.html">Примеры виртуальных хостов</a></seealso>
<seealso><a href="fd-limits.html">Ограничения файловых дескрипторов</a></seealso>
<seealso><a href="mass.html">Массовый виртуальный хостинг</a></seealso>
<seealso><a href="details.html">Подробности выбора соответствующего хоста</a></seealso>

<section id="support"><title>Поддержка виртуальных хостов</title>

    <ul>
      <li><a href="name-based.html">Виртуальные хосты основанные на имени</a>
	  (Несколько веб-сайтов на одном IP адресе)</li>
      <li><a href="ip-based.html">IP-базированные виртуальные хосты</a> (Отдельный
	  IP адрес для каждого веб-сайта)</li>
      <li><a href="examples.html">Примеры виртуальных хостов для общих случаев</a></li>
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
    ключ для запуска Apache с коммандной строки <code>-S</code> будет крайне полезен.
    То есть, слудет использовать следующую команду:</p>

    <example>
    /usr/local/apache2/bin/httpd -S
    </example>

    <p>Эта доманда распечатает описание того, как Apache интерпретировал
    файл конфигурации. Тщательное изучение IP адресов и имен серверов
    поможет найти ошибки конфигурации. (Смотрите также <a
    href="../programs/httpd.html">документацию к программе httpd</a> для
	изучения других параметров для запуска из командной строки)</p>

</section>
</manualpage>

