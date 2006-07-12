<?xml version="1.0"?>

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

<!DOCTYPE xsl:stylesheet [
    <!ENTITY lf SYSTEM "util/lf.xml">
]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/1999/xhtml">

<xsl:output method="text" encoding="ISO-8859-1" indent="no" />

<!-- Constants used for case translation -->
<xsl:variable name="lowercase" select="'abcdefghijklmnopqrstuvwxyz'" />
<xsl:variable name="uppercase" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'" />

<!-- ==================================================================== -->
<!-- <modulefilelist>                                                     -->
<!-- Builds the rewrite map                                               -->
<!-- ==================================================================== -->
<xsl:template match="modulefilelist">
<xsl:text># Mapping from directive names to URLs</xsl:text>&lf;
<xsl:text># GENERATED FROM XML -- DO NOT EDIT</xsl:text>&lf;
<xsl:text># You may use it as follows:</xsl:text>&lf;
<xsl:text># RewriteEngine On</xsl:text>&lf;
<xsl:text># RewriteMap dir2url </xsl:text>
<xsl:text>txt:/path/to/convenience.map</xsl:text>&lf;
<xsl:text># RewriteCond ${dir2url:$1} (.+)</xsl:text>&lf;
<xsl:text># RewriteRule ^/+([^/]+)$ /manual/%1 [R=301,NE,L]</xsl:text>&lf;&lf;

<xsl:apply-templates
    select="document(modulefile)/modulesynopsis[status!='Obsolete']
                /directivesynopsis[not(@location)]">
    <xsl:sort select="name" />
</xsl:apply-templates>

</xsl:template>
<!-- /modulefilelist -->

<!-- ==================================================================== -->
<!-- <directivesynopsis>                                                  -->
<!-- ==================================================================== -->
<xsl:template match="directivesynopsis">

    <xsl:value-of select="translate(name, $uppercase, $lowercase)" />
    <xsl:text>&#9;mod/</xsl:text>
    <xsl:value-of select="../name" />
    <xsl:text>.html#</xsl:text>
    <xsl:value-of select="translate(name, $uppercase, $lowercase)" />
    &lf;

</xsl:template>
<!-- /directivesynopsis -->

</xsl:stylesheet>
