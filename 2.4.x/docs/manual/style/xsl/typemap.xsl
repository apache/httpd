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
                  xmlns="">

<xsl:output 
  method="text"
  encoding="utf-8"
  indent="no"
/>

<!-- create nodeset for referencing later                                 -->
<xsl:variable name="design" select="document('util/designations.xml')
                                    /items/item" />

<!-- Constants used for case translation -->
<xsl:variable name="lowercase" select="'abcdefghijklmnopqrstuvwxyz'" />
<xsl:variable name="uppercase" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'" />

<!-- ==================================================================== -->
<!-- <metafile>                                                           -->
<!-- build typemap                                                        -->
<!-- ==================================================================== -->
<xsl:template match="/metafile">
<xsl:text># GENERATED FROM XML -- DO NOT EDIT</xsl:text>&lf;
&lf;
<xsl:apply-templates select="variants/variant" />
</xsl:template>
<!-- /metafile -->

<!-- ==================================================================== -->
<!-- <variant>                                                            -->
<!-- ==================================================================== -->
<xsl:template match="variant">
<xsl:variable name="lang" select="translate(., $uppercase, $lowercase)" />
<xsl:if test="not($design[translate(@lang, $uppercase, $lowercase) = $lang])">
    <xsl:message terminate="yes">
FATAL: missing designation data for language <xsl:value-of select="." />.
The XSLT-Stylesheet won't work without modification.
    </xsl:message>
</xsl:if>

<xsl:text>URI: </xsl:text>
<xsl:value-of select="/metafile/basename" />
<xsl:value-of select="$design[translate(@lang, $uppercase, $lowercase)
                              = $lang]" />&lf;

<xsl:text>Content-Language: </xsl:text>
<xsl:value-of select="$design[translate(@lang, $uppercase, $lowercase)
                              = $lang]/@lang" />&lf;

<xsl:text>Content-type: text/html; charset=</xsl:text>
<xsl:value-of select="$design[translate(@lang, $uppercase, $lowercase)
                              = $lang]/@charset" />&lf;

<xsl:if test="position() != last()">&lf;</xsl:if>
</xsl:template>
<!-- /variant -->

</xsl:stylesheet>
