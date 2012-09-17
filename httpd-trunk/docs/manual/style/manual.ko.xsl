<?xml version="1.0" encoding="utf-8"?>

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

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

<xsl:output method="xml" encoding="EUC-KR" indent="no" doctype-public="-//W3C//DTD XHTML 1.0 Strict//EN" doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"/>

<!-- Read the localized messages from the specified language file -->
<xsl:variable name="message" select="document('lang/ko.xml')/language/messages/message"/>
<xsl:variable name="doclang">ko</xsl:variable>
<xsl:variable name="allmodules" select="document('xsl/util/allmodules.xml')/items/item[@lang=$doclang]"/>

<!-- some meta information have to be passed to the transformation -->
<xsl:variable name="output-encoding">EUC-KR</xsl:variable>
<xsl:variable name="is-chm" select="false()"/>
<xsl:variable name="is-zip" select="false()"/>

<!-- Now get the real guts of the stylesheet -->
<xsl:include href="xsl/common.xsl"/>

</xsl:stylesheet>