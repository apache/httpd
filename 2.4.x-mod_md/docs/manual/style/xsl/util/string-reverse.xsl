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

<!-- O(log(n)) (stack usage!) string reverter -->
<xsl:template name="string-reverse">
<xsl:param name="string"/>
<xsl:variable name="length" select="string-length($string)"/>

<xsl:choose>
<xsl:when test="$length &lt; 2">
  <xsl:value-of select="$string"/>
</xsl:when>
<xsl:when test="$length = 2">
  <xsl:value-of select="concat(substring($string, 2, 1), substring($string, 1, 1))"/>
</xsl:when>
<xsl:otherwise>
  <xsl:variable name="middle" select="floor($length div 2)"/>

  <xsl:call-template name="string-reverse">
    <xsl:with-param name="string" select="substring($string, $middle + 1, $middle + 1)"/>
  </xsl:call-template>
  <xsl:call-template name="string-reverse">
    <xsl:with-param name="string" select="substring($string, 1, $middle)"/>
  </xsl:call-template>
</xsl:otherwise>
</xsl:choose>
</xsl:template>
<!-- /string-reverse -->

</xsl:stylesheet>
