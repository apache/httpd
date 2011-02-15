<?xml version='1.0' encoding='KOI8-R' ?>
<!DOCTYPE quickreference SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.ru.xsl"?>
<!-- English Revision: 421100:1070905 (outdated) -->

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

<quickreference metafile="quickreference.xml.meta">

  <title>Краткий справочник по директивам</title>
  <summary>
    <p>В кратком справочнике по директивам вы найдёте информацию
    о том, как использовать ту или иную директиву, её значение по умолчанию, статус
    и контекст. Для расшифровки понятий &#171;статус&#187; и &#171;контекст&#187;, обратитесь
    к <a href="directive-dict.html">Словарю</a>.</p>

    <p>В первой колонке приводится название директивы и описание её
    использования. Во второй - значение по умолчанию, если таковое
    есть у директивы. Если это значение слишком велико, то после
    первых букв идет значёк &#171;+&#187;.</p>

    <p>В третьей и четвёртой колонках даются значения контекста, в
    котором данная директива имеет смысл (может использоваться), и
    её статус. Все сокращения, используемые при этом, расшифровываются
    в следующей таблице.</p>
  </summary>

  <legend>
    <table>
      <columnspec><column width=".1"/><column width=".2"/></columnspec>
      <tr><th>s</th><td>server&#160;config</td></tr>
      <tr><th>v</th><td>virtual&#160;host</td></tr>
      <tr><th>d</th><td>directory</td></tr>
      <tr><th>h</th><td>.htaccess</td></tr>
    </table>

    <table>
      <columnspec><column width=".1"/><column width=".2"/></columnspec>
      <tr><th>C</th><td>Core</td></tr>
      <tr><th>M</th><td>MPM</td></tr>
      <tr><th>B</th><td>Base</td></tr>
      <tr><th>E</th><td>Extension</td></tr>
      <tr><th>X</th><td>Experimental</td></tr>
    </table>
  </legend>
</quickreference>
