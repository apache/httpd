<?xml version="1.0" encoding="KOI8-R" ?>
<!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">

<!--***************************************************-->
<!-- English revision: 1.4.2.2                         -->
<!--***************************************************-->
<!-- Translator: Ilia Soldis (rkai@tversu.ru)          -->
<!-- Reviewers:                                        -->
<!--             Ivan Shvedov (ivan@tversu.ru)         -->
<!--             Arthur Reznikov (art@altair.tversu.ru)-->
<!--***************************************************-->

<?xml-stylesheet type="text/xsl" href="./style/manual.en.xsl"?>
<manualpage metafile="filter.xml.meta">

  <title>Фильтры</title>

  <summary>
    <p>Данный документ описывает использование фильтров в Apache.</p>
  </summary>

  <section id="filters">
    <title>Фильтры</title>
    <related>
      <modulelist>
        <module>mod_deflate</module>
        <module>mod_ext_filter</module>
        <module>mod_include</module>
      </modulelist>
      <directivelist>
        <directive module="mod_mime">AddInputFilter</directive>
        <directive module="mod_mime">AddOutputFilter</directive>
        <directive module="mod_mime">RemoveInputFilter</directive>
        <directive module="mod_mime">RemoveOutputFilter</directive>
        <directive module="mod_ext_filter">ExtFilterDefine</directive>
        <directive module="mod_ext_filter">ExtFilterOptions</directive>
        <directive module="core">SetInputFilter</directive>
        <directive module="core">SetOutputFilter</directive>
      </directivelist>
    </related>
    
    <p><em>Фильтр</em> - это процесс, преобразующий данные, которые
    посылаются или получаются сервером. Данные, получаемые от
    клиента, обрабатываются <em>входным (input)</em> фильтром,
    в то время как данные, посылаемые сервером клиенту -
    <em>выходным (output)</em>. К одним и тем же данным можно
    применять последовательно несколько фильтров, причем
    порядок их следования может быть явно задан.</p>

    <p>Фильтры используются самим серером Apache, для выполнения
    функций обработки данных. В дополнение к этому, фильтры могут
    предоставляться модулями - в этом случае управление ими
    производится посредством соответствующих директив,
    указываемых в конфигурационном файле. К числу таких директив
    относятся следующие:
    <directive module="core">SetInputFilter</directive>,
    <directive module="core">SetOutputFilter</directive>,
    <directive module="mod_mime">AddInputFilter</directive>,
    <directive module="mod_mime">AddOutputFilter</directive>,
    <directive module="mod_mime">RemoveInputFilter</directive>, and
    <directive module="mod_mime">RemoveOutputFilter</directive>.</p>

    <p>В стандартный дистрибутив HTTP сервера Apache в настоящее время
    входят следующие фильтры, доступные для пользователя:</p>

    <dl>
      <dt>INCLUDES</dt>
      <dd>Обработка Server-Side Includes обеспечивается фильтром <module>mod_include</module></dd>
      <dt>DEFLATE</dt>
      <dd>Сжать выходные данные перед отправкой можно с помощью фильтра
          <module>mod_deflate</module>
      </dd>
    </dl>

    <p>В дополнение к этому, модуль <module>mod_ext_filter</module>
     позволяет использовать внешние программы в качестве фильтров.</p>
  </section>
</manualpage>
