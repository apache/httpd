<?xml version="1.0" encoding="ISO-8859-1"?>

<!--
 Copyright 2002-2004 The Apache Software Foundation

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-->

<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output 
  method="xml"
  encoding="ISO-8859-1"
  indent="no"
  doctype-public="-//W3C//DTD XHTML 1.0 Strict//EN"
  doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"
/>

<!-- Read the localized messages from the specified language file -->
<xsl:variable name="messages" select="document('lang/pt-br.xml')/messages"/>

<!-- some meta information have to be passed to the transformation -->
<xsl:variable name="output-encoding" select="'ISO-8859-1'" />
<xsl:variable name="is-chm" select="false()" />
<xsl:variable name="is-zip" select="false()" />

<!-- Now get the real guts of the stylesheet -->
<xsl:include href="xsl/common.xsl"/>

</xsl:stylesheet>
