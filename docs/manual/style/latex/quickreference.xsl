<?xml version="1.0"?><!--
/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2002-2004 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 */ -->
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
       select="document(modulefilelist/modulefile)
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
                          [normalize-space(.)='server config']">s</xsl:if>
            <xsl:if test="contextlist/context
                          [normalize-space(.)='virtual host']">v</xsl:if>
            <xsl:if test="contextlist/context
                          [normalize-space(.)='directory']">d</xsl:if>
            <xsl:if test="contextlist/context
                          [normalize-space(.)='.htaccess']">h</xsl:if>

      <xsl:text>&amp;</xsl:text>
            <xsl:choose>
            <xsl:when test="../status='Base'">B</xsl:when>
            <xsl:when test="../status='MPM'">M</xsl:when>
            <xsl:when test="../status='Core'">C</xsl:when>
            <xsl:when test="../status='Extension'">E</xsl:when>
            <xsl:when test="../status='Experimental'">X</xsl:when>
            </xsl:choose>

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
<xsl:apply-templates/>
</xsl:template>

</xsl:stylesheet>
