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

<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<!-- load utility snippets -->
<xsl:include href="string-reverse.xsl" />


<!-- strip whitespace at the beginning if one-liner -->
<xsl:template name="pre-ltrim-one">
<xsl:param name="string" />

<xsl:choose>
<xsl:when test="contains($string, '&#x0a;')">
  <xsl:value-of select="$string" />
</xsl:when>
<xsl:otherwise>
    <xsl:value-of select="substring($string, string-length(substring-before($string, substring(normalize-space($string), 1, 1))) + 1, string-length($string))" />
</xsl:otherwise>
</xsl:choose>
</xsl:template>


<!-- strip empty lines at the beginning -->
<xsl:template name="pre-ltrim">
<xsl:param name="string" />

<xsl:variable name="lspace">
    <xsl:call-template name="string-reverse">
        <xsl:with-param name="string" select="substring-before($string, substring(normalize-space($string), 1, 1))" />
    </xsl:call-template>
</xsl:variable>

<xsl:choose>
<xsl:when test="contains($lspace, '&#x0a;')">
    <xsl:value-of select="substring(
        $string,
        1 + string-length($lspace)
            - string-length(substring-before($lspace, '&#x0a;')),
        string-length($string)
    )" />
</xsl:when>
<xsl:otherwise>
    <xsl:value-of select="$string" />
</xsl:otherwise>
</xsl:choose>
</xsl:template>

<!-- strip whitespace at the end -->
<xsl:template name="pre-rtrim">
<xsl:param name="string" />

<xsl:variable name="rev">
    <xsl:call-template name="string-reverse">
        <xsl:with-param name="string" select="$string" />
    </xsl:call-template>
</xsl:variable>

<xsl:call-template name="string-reverse">
    <xsl:with-param name="string" select="substring(
        $rev,
        1 + string-length(substring-before(
            $rev, substring(normalize-space($rev), 1, 1)
        )),
        string-length($rev)
    )" />
</xsl:call-template>
</xsl:template>


</xsl:stylesheet>
