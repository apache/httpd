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
<!-- <quickreference>                                                     -->
<!-- Builds the directive quickreference page                             -->
<!-- ==================================================================== -->
<xsl:template match="quickreference">

  <xsl:call-template name="section-title"/>

  <xsl:apply-templates select="summary"/>

  <xsl:call-template name="seealso"/>

  <xsl:apply-templates select="legend"/>

  <xsl:variable name="directives"
       select="document(document($allmodules)/modulefilelist/modulefile)
         /modulesynopsis/directivesynopsis[not(@location)]" />

  <xsl:text>\footnotesize
</xsl:text>

  <xsl:text>\begin{longtable}{p{.60\textwidth}p{.25\textwidth}ll}\hline
</xsl:text>

<xsl:for-each
   select="$directives[translate(substring(normalize-space(name), 1,1),
                                          $lowercase,$uppercase)]">
<xsl:sort select="name" />

   <xsl:text>\texttt{</xsl:text>
   <xsl:apply-templates select="syntax" />
   <xsl:text>}</xsl:text>
   <xsl:text>&amp;</xsl:text>

   <!-- if the default value contains (at least) one <br />, -->
   <!-- this probably means that a short explanation follows -->
   <!-- the actual default value. We cut off the string      -->
   <!-- after the <br /> so it will not be shown here.       -->
   <!-- (add the + character instead)                        -->
   <xsl:variable name="default">
       <xsl:choose>
       <xsl:when test="count(default[count(br) &gt; 0]) &gt; 0">
          <xsl:value-of select="default/child::node()
                       [count(preceding-sibling::*) = 0]" />
       </xsl:when>
       <xsl:otherwise>
            <xsl:value-of select="default"/>
       </xsl:otherwise>
       </xsl:choose>
    </xsl:variable>

     <xsl:call-template name="ltescape">
        <xsl:with-param name="string">
            <xsl:value-of select="substring(substring-after(concat($default,
                                  ' '), name),1,20)" />
        </xsl:with-param>
      </xsl:call-template>

      <xsl:if test="string-length(substring-after(concat($default, ' '),
                name)) &gt; 20 or count(default[count(br) &gt; 0]) &gt; 0">
         <xsl:text> +</xsl:text>
      </xsl:if>

      <xsl:text>&amp;</xsl:text>
        <xsl:if test="contextlist/context
                      [normalize-space(.)='server config']">
            <xsl:value-of select="$message[@id='serverconfig']/@letter"/>
        </xsl:if>
        <xsl:if test="contextlist/context
                      [normalize-space(.)='virtual host']">
            <xsl:value-of select="$message[@id='virtualhost']/@letter"/>
        </xsl:if>
        <xsl:if test="contextlist/context
                      [normalize-space(.)='directory']">
            <xsl:value-of select="$message[@id='directory']/@letter"/>
        </xsl:if>
        <xsl:if test="contextlist/context
                      [normalize-space(.)='.htaccess']">
            <xsl:value-of select="$message[@id='htaccess']/@letter"/>
        </xsl:if>

      <xsl:text>&amp;</xsl:text>
        <xsl:variable name="status" select="translate(
            ../status, $uppercase, $lowercase)"/>
        <xsl:value-of select="$message[@id=$status]/@letter"/>
     <xsl:text>\\*
</xsl:text>

      <xsl:text>\multicolumn{4}{l}{\begin{minipage}[t]{.95\textwidth}</xsl:text>
         <xsl:choose>
         <xsl:when test="string-length(normalize-space(description)) &gt; 0">
             <xsl:apply-templates select="description"/>
         </xsl:when>
         <xsl:otherwise>
             <xsl:text>-</xsl:text>
         </xsl:otherwise>
         </xsl:choose>

      <xsl:text>\hfill p.\ \pageref{/mod/</xsl:text>
        <xsl:value-of select="../name"/> <xsl:text>:</xsl:text>
        <xsl:value-of select="translate(name, $uppercase, $lowercase)"/>
      <xsl:text>}</xsl:text>


    <xsl:text>\end{minipage}} \\ \hline
</xsl:text>

  </xsl:for-each> <!-- /directives -->

  <xsl:text>\end{longtable}
\normalsize</xsl:text>

</xsl:template>

<xsl:template match="legend">
<!-- TODO: This table is no longer in source file
     <xsl:apply-templates/>
-->
</xsl:template>

</xsl:stylesheet>
