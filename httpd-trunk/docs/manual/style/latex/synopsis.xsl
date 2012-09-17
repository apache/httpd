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
<!-- <modulesynopsis>                                                     -->
<!-- ==================================================================== -->

<xsl:template match="modulesynopsis">

<xsl:text>\section{</xsl:text>
<xsl:choose>
  <xsl:when test="../status='Core'">
    <xsl:value-of select="$message[@id='apachecore']" />
  </xsl:when>
  <xsl:when test=".='mpm_common'">
    <xsl:value-of select="$message[@id='apachempmcommon']" />
  </xsl:when>
  <xsl:when test="../status='MPM'">
    <xsl:value-of select="$message[@id='apachempm']" />
    <xsl:text> </xsl:text>
    <xsl:apply-templates select="name"/>
  </xsl:when>
  <xsl:otherwise>
    <xsl:value-of select="$message[@id='apachemodule']" />
    <xsl:text> </xsl:text>
    <xsl:apply-templates select="name"/>
  </xsl:otherwise>
</xsl:choose>
<xsl:text>}\label{</xsl:text>
<xsl:value-of select="concat('/mod/',name)"/>
<xsl:text>}\hypertarget{</xsl:text>
<xsl:value-of select="concat('/mod/',name)"/>
<xsl:text>}{}</xsl:text>

<xsl:text>
\begin{tabular}{lp{.75\linewidth}}
\hline
</xsl:text>
<xsl:value-of select="$message[@id='description']" />
<xsl:text>: &amp;</xsl:text> 
<xsl:apply-templates select="description" />
<xsl:text>\\
</xsl:text>

<xsl:value-of select="$message[@id='status']" />
<xsl:text>: &amp;</xsl:text>
    <xsl:variable name="status" select="translate(
        status, $uppercase, $lowercase)"/>
    <xsl:value-of select="$message[@id=$status]"/>
<xsl:text>\\
</xsl:text>

<xsl:if test="identifier">
<xsl:value-of select="$message[@id='moduleidentifier']" />
<xsl:text>: &amp;</xsl:text>
<xsl:apply-templates select="identifier" />
<xsl:text>\\
</xsl:text>
</xsl:if>

<xsl:if test="sourcefile">
<xsl:value-of select="$message[@id='sourcefile']" />
<xsl:text>: &amp;</xsl:text>
<xsl:apply-templates select="sourcefile" />
<xsl:text>\\
</xsl:text>
</xsl:if>

<xsl:if test="compatibility">
<xsl:value-of select="$message[@id='compatibility']" />
<xsl:text>: &amp;</xsl:text>
<xsl:apply-templates select="compatibility" />
<xsl:text> \\
</xsl:text>
</xsl:if>
<xsl:text>\hline \end{tabular}
</xsl:text>
    <!-- Summary of module features/usage (1 to 3 paragraphs, -->
    <!-- optional)                                            -->
    <xsl:if test="summary">
      <xsl:text>\subsection*{</xsl:text>
      <xsl:value-of select="$message[@id='summary']" />
      <xsl:text>}
</xsl:text>
      <xsl:apply-templates select="summary" />
     </xsl:if>

     <xsl:text>
\smallskip\textbf{</xsl:text>
     <xsl:value-of select="$message[@id='directives']" />
     <xsl:text>}
</xsl:text>

     <xsl:choose>
     <xsl:when test="directivesynopsis">
       <xsl:text>\begin{itemize}</xsl:text>
       <xsl:for-each select="directivesynopsis">
         <xsl:sort select="name" />
         <xsl:text>\item </xsl:text>
         <xsl:if test="@type='section'">
           <xsl:text>\textless{}</xsl:text>
         </xsl:if>
         <xsl:apply-templates select="name" mode="simple"/>
         <xsl:if test="@type='section'">
           <xsl:text>\textgreater{}</xsl:text>
         </xsl:if>
         <xsl:if test="@location">
           <xsl:variable name="lowerlocation"
            select="translate(@location, $uppercase, $lowercase)" />
           <xsl:text> (p.\ \pageref{/mod/</xsl:text>
           <xsl:value-of select="concat(translate(@location,$uppercase,$lowercase),':',translate(name,$uppercase,$lowercase))"/>
           <xsl:text>}) </xsl:text>
         </xsl:if>
         <xsl:text>
</xsl:text>
       </xsl:for-each>
       <xsl:text>\end{itemize}
</xsl:text>
     </xsl:when>
     <xsl:otherwise>
       <xsl:value-of select="$message[@id='nodirectives']" />
     <xsl:text>
</xsl:text>
     </xsl:otherwise>
     </xsl:choose>

     <xsl:text>
</xsl:text>

<xsl:call-template name="seealso"/>

     <!-- Sections of documentation about the module as a whole -->
       <xsl:apply-templates select="section" />

     <!-- Directive documentation -->
       <xsl:apply-templates select="directivesynopsis">
         <xsl:sort select="name" />
       </xsl:apply-templates>

</xsl:template>
<!-- /modulesynopsis -->


<!-- ==================================================================== -->
<!-- Directivesynopsis                                                    -->
<!-- ==================================================================== -->
<xsl:template match="directivesynopsis/name" mode="simple" name="simpledirname">
<xsl:if test="@type='section'"><xsl:text>\textless{}</xsl:text></xsl:if>
<xsl:apply-templates/>
<xsl:if test="@type='section'"><xsl:text>\textgreater{}</xsl:text></xsl:if>
</xsl:template>

<xsl:template match="directivesynopsis/name">
<xsl:text>\subsection*{</xsl:text>
<xsl:call-template name="simpledirname"/>
  <xsl:choose>
  <xsl:when test="$message[@id='directive']/@replace-space-with">
    <xsl:value-of select="$message[@id='directive']/@replace-space-with"/>
  </xsl:when>
  <xsl:otherwise>
    <xsl:text> </xsl:text>
  </xsl:otherwise>
  </xsl:choose>

<xsl:value-of select="$message[@id='directive']" />
<xsl:text>}\label{</xsl:text>
<xsl:value-of select="concat('/mod/', //modulesynopsis/name, ':', translate(., $uppercase, $lowercase))"/>
<xsl:text>}\hypertarget{</xsl:text>
<xsl:value-of select="concat('/mod/', //modulesynopsis/name, ':', translate(., $uppercase, $lowercase))"/>
<xsl:text>}{}</xsl:text>

</xsl:template>

<xsl:template match="directivesynopsis">
<xsl:if test="not(@location)">
  <xsl:apply-templates select="name"/>
  <!-- Directive header -->
  <xsl:text>
\begin{tabular}{lp{.8\linewidth}}
\hline
</xsl:text>
<xsl:value-of select="$message[@id='description']" />
<xsl:text>: &amp; </xsl:text>
<xsl:apply-templates select="description" />
<xsl:text>\\
</xsl:text>

<xsl:value-of select="$message[@id='syntax']" />
<xsl:text>: &amp; {\ttfamily </xsl:text>
<xsl:apply-templates select="syntax" />
<xsl:text>}\\
</xsl:text>

<xsl:if test="default">
<xsl:value-of select="$message[@id='default']" />
<xsl:text>: &amp; {\ttfamily </xsl:text>
<xsl:apply-templates select="default" />
<xsl:text>} \\
</xsl:text>
</xsl:if>

<xsl:value-of select="$message[@id='context']" />
<xsl:text>: &amp;</xsl:text>
<xsl:apply-templates select="contextlist" />
<xsl:text> \\
</xsl:text>

<xsl:if test="override">
<xsl:value-of select="$message[@id='override']"/>
<xsl:text>: &amp;</xsl:text>
<xsl:apply-templates select="override" />
<xsl:text> \\
</xsl:text>
</xsl:if>

<xsl:value-of select="$message[@id='status']" />
<xsl:text>: &amp;</xsl:text>
<xsl:variable name="status" select="translate(
    ../status, $uppercase, $lowercase)"/>
<xsl:value-of select="$message[@id=$status]"/>
<xsl:text> \\
</xsl:text>

<xsl:value-of select="$message[@id='module']" />
<xsl:text>: &amp;</xsl:text>
<xsl:choose>
<xsl:when test="modulelist">
  <xsl:apply-templates select="modulelist" />
</xsl:when>
<xsl:otherwise>
  <xsl:apply-templates select="../name" />
</xsl:otherwise>
</xsl:choose>
<xsl:text> \\
</xsl:text>

<xsl:if test="compatibility">
<xsl:value-of select="$message[@id='compatibility']" />
<xsl:text>: &amp;</xsl:text>
<xsl:apply-templates select="compatibility" />
<xsl:text> \\
</xsl:text>
</xsl:if>

<xsl:text>\hline
\end{tabular}

</xsl:text>

<xsl:apply-templates select="usage" />

<xsl:call-template name="seealso"/>

</xsl:if> <!-- /not(@location) -->
</xsl:template>
<!-- /directivesynopsis -->


<!-- ==================================================================== -->
<!-- <contextlist>                                                        -->
<!-- ==================================================================== -->
<xsl:template match="contextlist">
<xsl:apply-templates select="context" />
</xsl:template>
<!-- /contextlist -->


<!-- ==================================================================== -->
<!-- <context>                                                            -->
<!-- Each entry is separeted with a comma                                 -->
<!-- ==================================================================== -->
<xsl:template match="context">
<xsl:choose>
<xsl:when test="normalize-space(.) = 'server config'">
    <xsl:value-of select="$message[@id='serverconfig']" />
</xsl:when>
<xsl:when test="normalize-space(.) = 'virtual host'">
    <xsl:value-of select="$message[@id='virtualhost']" />
</xsl:when>
<xsl:when test="normalize-space(.) = 'directory'">
    <xsl:value-of select="$message[@id='directory']" />
</xsl:when>
<xsl:when test="normalize-space(.) = '.htaccess'">
    <xsl:value-of select="$message[@id='htaccess']" />
</xsl:when>
<xsl:otherwise> <!-- error -->
    <xsl:message terminate="yes">
        unknown context: <xsl:value-of select="." />
    </xsl:message>
</xsl:otherwise>
</xsl:choose>

<xsl:if test="position() != last()">
    <xsl:text>, </xsl:text>
</xsl:if>
</xsl:template>
<!-- /context -->


<!-- ==================================================================== -->
<!-- <modulelist>                                                         -->
<!-- ==================================================================== -->
<xsl:template match="modulelist">
<xsl:for-each select="module">
    <xsl:call-template name="module" />
    <xsl:if test="position() != last()">
        <xsl:text>, </xsl:text>
    </xsl:if>
</xsl:for-each>
</xsl:template>
<!-- /modulelist -->


<!-- ==================================================================== -->
<!-- modulesynopsis/compatibility                                         -->
<!-- ==================================================================== -->
<xsl:template match="modulesynopsis/compatibility">
<xsl:apply-templates />
</xsl:template>


<!-- ==================================================================== -->
<!-- directivesynopsis/compatibility                                      -->
<!-- ==================================================================== -->
<xsl:template match="directivesynopsis/compatibility">
<xsl:apply-templates />
</xsl:template>

</xsl:stylesheet>
