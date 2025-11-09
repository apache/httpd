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

<!-- ==================================================================== -->
<!-- <modulefilelist>                                                     -->
<!-- Builds the rewrite map                                               -->
<!-- ==================================================================== -->
<xsl:template match="modulefilelist">
<xsl:text># GENERATED FROM XML -- DO NOT EDIT</xsl:text>&lf;
<xsl:text>#</xsl:text>&lf;
<xsl:text># Below is the up-to-date list of existing directives. The list is formatted</xsl:text>&lf;
<xsl:text># in order to be ready to use for the JS used in prettify.js</xsl:text>&lf;
&lf;
<xsl:text># The next line has to be copy/pasted into prettify.js around line 135</xsl:text>&lf;
<xsl:text># in place of the corresponding CONFIG_KEYWORDS array.</xsl:text>&lf;
&lf;

<xsl:variable name="directives"
    select="document(modulefile)/modulesynopsis[status!='Obsolete']
                /directivesynopsis[not(@location)]" />

<xsl:text>  var CONFIG_KEYWORDS = ["</xsl:text>
<xsl:for-each select="$directives">
    <!-- Sorting is useless here, but the output is nicer -->
    <xsl:sort select="name" />
    <xsl:call-template name="list_directive" />
</xsl:for-each>
<xsl:text>"];</xsl:text>

&lf;
&lf;
&lf;
<xsl:text># The next line has to be copy/pasted into prettify.js around line 920</xsl:text>&lf;
<xsl:text># in place of the corresponding PR_TAG array.</xsl:text>&lf;
&lf;

<xsl:text>        [PR_TAG,     /^\b(</xsl:text>
<xsl:for-each select="$directives[@type='section']">
    <!-- Sorting is useless here, but the output is nicer -->
    <xsl:sort select="name" />
    <xsl:call-template name="list_section" />
</xsl:for-each>
<xsl:text>)\b/, null],</xsl:text>

</xsl:template>
<!-- /modulefilelist -->

<!-- ==================================================================== -->
<!-- <list_directive>                                                     -->
<!-- ==================================================================== -->
<xsl:template name="list_directive">

    <xsl:if test="position()!=1">
        <xsl:text>,</xsl:text>
    </xsl:if>

    <xsl:if test="@type = 'section'"><xsl:text>&lt;</xsl:text></xsl:if>
    <xsl:value-of select="name" />
    <xsl:if test="@type = 'section'"><xsl:text>&gt;</xsl:text></xsl:if>

</xsl:template>
<!-- /list_directive -->

<!-- ==================================================================== -->
<!-- <list_section>                                                       -->
<!-- ==================================================================== -->
<xsl:template name="list_section">

    <xsl:if test="position()!=1">
        <xsl:text>|</xsl:text>
    </xsl:if>

    <xsl:value-of select="name" />

</xsl:template>
<!-- /list_section -->

</xsl:stylesheet>
