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
<!-- <moduleindex>                                                        -->
<!-- Builds the moduleindex page                                          -->
<!-- ==================================================================== -->
<xsl:template match="moduleindex">

  <xsl:variable name="metafile" select="document(/*/@metafile)/metafile" /> 

  <xsl:call-template name="section-title"/>

  <xsl:apply-templates select="summary"/>

  <xsl:call-template name="seealso"/>

   <xsl:text>\subsection*{</xsl:text>
   <xsl:value-of select="$message[@id='corefeatures']" />
   <xsl:text>}

\begin{description}
\item[</xsl:text>
    <xsl:apply-templates select="document(document($allmodules)/modulefilelist/modulefile
                              [starts-with(., 'core.xml')])
                              /modulesynopsis/name"/>
    <xsl:text>] (p.\ \pageref{/mod/</xsl:text>
    <xsl:value-of select="document(document($allmodules)/modulefilelist/modulefile
                              [starts-with(., 'core.xml')])
                              /modulesynopsis/name"/>
    <xsl:text>}) </xsl:text>

    <xsl:apply-templates select="document(document($allmodules)/modulefilelist/modulefile
                                 [starts-with(., 'core.xml')])
                                 /modulesynopsis/description" />

    <xsl:text>
\item[</xsl:text>

    <xsl:apply-templates  select="document(document($allmodules)/modulefilelist/modulefile
                                  [starts-with(., 'mpm_common.xml')])
                                  /modulesynopsis/name" />
    <xsl:text>] (p.\ \pageref{/mod/</xsl:text>
    <xsl:value-of select="document(document($allmodules)/modulefilelist/modulefile
                                   [starts-with(., 'mpm_common.xml')])
                                   /modulesynopsis/name"/>
    <xsl:text>}) </xsl:text>
    <xsl:apply-templates select="document(document($allmodules)/modulefilelist/modulefile
                                         [starts-with(., 'mpm_common.xml')])
                                         /modulesynopsis/description" />



    <!-- and now the remaining MPMs -->
    <xsl:variable name="mpmmodules"
         select="document(document($allmodules)/modulefilelist/modulefile)
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
    <xsl:value-of select="$message[@id='othermodules']" />
    <xsl:text>}
\begin{description}
</xsl:text>
            
    <xsl:variable name="modules"
         select="document(document($allmodules)/modulefilelist/modulefile)
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
