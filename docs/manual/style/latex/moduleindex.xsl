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
<!-- <moduleindex>                                                        -->
<!-- Builds the moduleindex page                                          -->
<!-- ==================================================================== -->
<xsl:template match="moduleindex">

  <xsl:variable name="metafile" select="document(/*/@metafile)/metafile" /> 

  <xsl:call-template name="section-title"/>

  <xsl:apply-templates select="summary"/>

  <xsl:call-template name="seealso"/>

   <xsl:text>\subsection*{</xsl:text>
   <xsl:value-of select="$messages/message[@name='corefeatures']" />
   <xsl:text>}

\begin{description}
\item[</xsl:text>
    <xsl:apply-templates select="document(modulefilelist/modulefile
                              [starts-with(., 'core.xml')])
                              /modulesynopsis/name"/>
    <xsl:text>] (p.\ \pageref{/mod/</xsl:text>
    <xsl:value-of select="document(modulefilelist/modulefile
                              [starts-with(., 'core.xml')])
                              /modulesynopsis/name"/>
    <xsl:text>}) </xsl:text>

    <xsl:apply-templates select="document(modulefilelist/modulefile
                                 [starts-with(., 'core.xml')])
                                 /modulesynopsis/description" />

    <xsl:text>
\item[</xsl:text>

    <xsl:apply-templates  select="document(modulefilelist/modulefile
                                  [starts-with(., 'mpm_common.xml')])
                                  /modulesynopsis/name" />
    <xsl:text>] (p.\ \pageref{/mod/</xsl:text>
    <xsl:value-of select="document(modulefilelist/modulefile
                                   [starts-with(., 'mpm_common.xml')])
                                   /modulesynopsis/name"/>
    <xsl:text>}) </xsl:text>
    <xsl:apply-templates select="document(modulefilelist/modulefile
                                         [starts-with(., 'mpm_common.xml')])
                                         /modulesynopsis/description" />



    <!-- and now the remaining MPMs -->
    <xsl:variable name="mpmmodules"
         select="document(modulefilelist/modulefile)
                 /modulesynopsis[status='MPM' and name != 'mpm_common']" />
    <xsl:variable name="translist">
      <xsl:call-template name="module-translist">
         <xsl:with-param name="modules" select="$mpmmodules" />
      </xsl:call-template>
    </xsl:variable>

    <xsl:for-each select="$mpmmodules">
      <xsl:sort select="substring-before(substring-after($translist,
                  concat('- ', translate(normalize-space(name), $lowercase,
                  $uppercase), ' ')), ' -')" />

      <xsl:text>
\item[</xsl:text>
      <xsl:apply-templates select="name"/>
      <xsl:text>] (p.\ \pageref{/mod/</xsl:text>
      <xsl:value-of select="name"/>
      <xsl:text>}) </xsl:text>

      <xsl:apply-templates select="description" />

    </xsl:for-each>

    <xsl:text>\end{description}

</xsl:text>

    <!-- /core section -->

    <xsl:text>\section*{</xsl:text>
    <xsl:value-of select="$messages/message[@name='othermodules']" />
    <xsl:text>}
\begin{description}
</xsl:text>
            
    <xsl:variable name="modules"
         select="document(modulefilelist/modulefile)
                 /modulesynopsis[status!='MPM' and status!='Core']" />

    <xsl:call-template name="mindex-of-letter">
       <xsl:with-param name="modules" select="$modules" />
    </xsl:call-template>

    <xsl:text>\end{description}
</xsl:text>
</xsl:template> 
<!-- /moduleindex -->


<!-- ==================================================================== -->
<!-- the working horse. builds list items of all modules starting with    -->
<!-- one letter when done, it calls itself to catch the next letter       -->
<!-- ==================================================================== -->
<xsl:template name="mindex-of-letter">
<xsl:param name="modules"/>

<xsl:variable name="translist">
    <xsl:call-template name="module-translist">
        <xsl:with-param name="modules" select="$modules" />
    </xsl:call-template>
</xsl:variable>

<xsl:for-each select="$modules">
<xsl:sort
    select="substring-before(substring-after($translist, concat('- ',
        translate(normalize-space(name),$lowercase,$uppercase), ' ')), ' -')" />

<xsl:text>
\item[</xsl:text>
<xsl:apply-templates select="name"/>
<xsl:text>] (p.\ \pageref{/mod/</xsl:text>
<xsl:value-of select="name"/>
<xsl:text>}) </xsl:text>

        <xsl:apply-templates select="description" />

</xsl:for-each> <!-- /directives -->

</xsl:template>
<!-- /mindex-of-letter -->

<!-- ==================================================================== -->
<!-- define module name translations for sorting                          -->
<!--                                                                      -->
<!-- it's a kind of a hack...                                             -->
<!-- we build a string that contains the following data:                  -->
<!-- "- modulename sortname - modulename sortname - ..."                  -->
<!-- (with all data in uppercase)                                         -->
<!--                                                                      -->
<!-- So, the translation from modulename to sortname can be done with the -->
<!-- expression below:                                                    -->
<!--
       substring-before(
           substring-after($translist, 
                           concat('- ', translate(modulename,
                                                  $lowercase, $uppercase),
                                  ' ')
                           ),
           ' -')
                                                                          -->
<!-- ==================================================================== -->
<xsl:template name="module-translist">
<xsl:param name="modules" />

<xsl:text>-</xsl:text>
<xsl:for-each select="$modules">
    <xsl:variable name="sname" select="translate(normalize-space(name),
                                       $lowercase, $uppercase)" />

    <xsl:text> </xsl:text>
    <xsl:value-of select="$sname" />
    <xsl:text> </xsl:text>
    <xsl:call-template name="module-translatename">
        <xsl:with-param name="name" select="$sname" />
    </xsl:call-template>
    <xsl:text> -</xsl:text>
</xsl:for-each>
</xsl:template>
<!-- /module-translist -->

<xsl:template name="module-translatename">
<xsl:param name="name" />

<xsl:variable name="sname" select="translate($name, $lowercase, $uppercase)" />

<xsl:choose>
<xsl:when test="starts-with($sname, 'MOD_') or starts-with($sname, 'MPM_')">
    <xsl:value-of select="substring($name, 5)" />
</xsl:when>

<xsl:when test="starts-with($sname, 'MPMT_')">
    <xsl:value-of select="substring($name, 6)" />
</xsl:when>

<xsl:otherwise>
    <xsl:value-of select="$name" />
</xsl:otherwise>
</xsl:choose>
</xsl:template>
<!-- /module-translatename -->

</xsl:stylesheet>
