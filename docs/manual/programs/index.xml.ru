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
<!-- Translator: Ilia Soldatenko (soldis@tversu.ru)    -->
<!-- Reviewers:                                        -->
<!--             Ivan Shvedov (ivan@tversu.ru)         -->
<!--             Arthur Reznikov (art@altair.tversu.ru)-->
<!--***************************************************-->

<manualpage metafile="index.xml.meta">
<parentdocument href="../"/>

  <title>Сервер и вспомогательные программы</title>

<summary>
    <p>Этот документ описывает назначение и ипользование
    всех исполняемых файлов HTTP сервера Apache.</p>
</summary>

<section id="index"><title>Указатель</title>

    <dl>
      <dt><program>httpd</program></dt>

      <dd>HTTP сервер Apache</dd>

      <dt><program>apachectl</program></dt>

      <dd>Интерфейс управления HTTP сервером Apache</dd>

      <dt><program>ab</program></dt>

      <dd>Утилита для тестирования HTTP сервера Apache</dd>

      <dt><program>apxs</program></dt>

      <dd>Утилита APache eXtenSion</dd>

      <dt><program>dbmmanage</program></dt>

      <dd>Создание и обновление файлов паролей пользователей в формате DBM,
      необходимых для базовой аутентификации (basic authentification)</dd>

	  <dt><program>htcacheclean</program></dt>
      <dd>Очистить кэш на диске</dd>

      <dt><program>htdigest</program></dt>

      <dd>Создание и обновление файлов паролей пользователей для
      дайджестной аутентификации (digest authentification)</dd>

      <dt><program>htpasswd</program></dt>

      <dd>Создание и обновление файлов паролей пользователей
      для базовой аутентификации (basic authentification)</dd>

	  <dt><program>httxt2dbm</program></dt>

      <dd>Создание dbm файлов для использования с RewriteMap</dd>

      <dt><program>logresolve</program></dt>

      <dd>Утилита для преобразования IP-адресов в соответствующие
      им имена хостов в лог-файлах Apache</dd>

      <dt><program>rotatelogs</program></dt>

      <dd>Утилита, позволяющая производить ротацию лог-файлов Apache без
      остановки сервера</dd>

      <dt><program>suexec</program></dt>

      <dd>Switch User For Exec - утилита, позволяющая выполнять CGI-скрипт от имени
      другого пользователя</dd>

      <dt><a href="other.html">Другие программы</a></dt>
      <dd>Вспомогательные утилиты, не имеющие своих собственных справочных руководств</dd>
    </dl>
</section>

</manualpage>
