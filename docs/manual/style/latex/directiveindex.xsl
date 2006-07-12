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
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/1999/xhtml">

<!-- ==================================================================== -->
<!-- <directiveindex>                                                     -->
<!-- Builds the directive index page                                      -->
<!-- ==================================================================== -->
<xsl:template match="directiveindex">

    <xsl:variable name="directives"
        select="document(document($allmodules)/modulefilelist/modulefile)
                /modulesynopsis[status!='Obsolete']
                /directivesynopsis[not(@location)]" />


  <xsl:call-template name="section-title"/>

  <xsl:apply-templates select="summary" />

  <xsl:call-template name="seealso"/>

  <xsl:text>\begin{itemize}
</xsl:text>
  <xsl:for-each select="$directives">
  <xsl:sort select="name" />

  <xsl:text>
\item </xsl:text>
  <xsl:apply-templates select="name" mode="simple"/>
  <xsl:text> (p.\ \pageref{/mod/</xsl:text>
  <xsl:value-of select="../name"/><xsl:text>:</xsl:text>
  <xsl:value-of select="translate(name, $uppercase, $lowercase)"/>
  <xsl:text>})</xsl:text>
</xsl:for-each>

  <xsl:text>\end{itemize}</xsl:text>

</xsl:template>
<!-- /directiveindex -->

</xsl:stylesheet>
