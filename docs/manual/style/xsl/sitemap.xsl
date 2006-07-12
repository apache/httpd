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

<!-- ==================================================================== -->
<!-- <sitemap>                                                            -->
<!-- Process an entire document into an HTML page                         -->
<!-- ==================================================================== -->
<xsl:template match="/sitemap">
<html xml:lang="{$doclang}" lang="{$doclang}">
    <xsl:call-template name="head" />&lf;

    <body id="manual-page">&lf;
        <xsl:call-template name="top" />&lf;

        <div id="page-content">
            <div id="preamble">        
                <h1>
                    <xsl:value-of select="title" />
                </h1>&lf;

                <xsl:call-template name="langavail" />&lf;

                <xsl:apply-templates select="summary" />
            </div>&lf; <!-- /#preamble -->
          
            <xsl:if test="(not($is-chm) and count(category) &gt; 1) or seealso">
                <div id="quickview">
                    <xsl:if test="not($is-chm) and count(category) &gt; 1">
                        <ul id="toc">&lf;
                        <xsl:for-each select="category">
                            <xsl:choose>
                            <xsl:when test="@id">
                                <li>
                                    <img src="{$path}/images/down.gif" alt="" />
                                    <xsl:text> </xsl:text>
                                    <a href="#{@id}">
                                        <xsl:apply-templates
                                            select="title" mode="print" />
                                    </a>
                                </li>&lf;
                            </xsl:when>
                            <xsl:otherwise>
                                <li>
                                    <img src="{$path}/images/down.gif" alt="" />
                                    <xsl:text> </xsl:text>
                                    <xsl:apply-templates
                                        select="title" mode="print" />
                                </li>&lf;
                            </xsl:otherwise>
                            </xsl:choose>
                        </xsl:for-each>
                        </ul>&lf;
                    </xsl:if>

                    <xsl:if test="seealso">
                        <h3>
                            <xsl:value-of select="$message
                                                  [@id='seealso']" />
                        </h3>&lf;

                        <ul class="seealso">&lf;
                        <xsl:for-each select="seealso">
                            <li>
                                <xsl:apply-templates />
                            </li>&lf;
                        </xsl:for-each>
                        </ul>&lf;
                    </xsl:if>
	            </div>&lf; <!-- /#quickview -->
            </xsl:if> <!-- have sidebar -->

            <xsl:apply-templates select="category" />
        </div>&lf; <!-- /#page-content -->

        <xsl:call-template name="bottom" />&lf;
    </body>
</html>
</xsl:template>
<!-- /sitemap -->
  

<!-- ==================================================================== -->
<!-- category/page                                                        -->
<!-- ==================================================================== -->
<xsl:template match="sitemap/category/page">
<li>
    <xsl:if test="@separate='yes'">
        <xsl:attribute name="class">separate</xsl:attribute>
    </xsl:if>

    <xsl:choose>
    <xsl:when test="@href">
        <a href="{@href}">
            <xsl:call-template name="helper.uri.fix">
                <xsl:with-param name="uri" select="@href" />
            </xsl:call-template>
            <xsl:value-of select="." />
        </a>
    </xsl:when>
    <xsl:otherwise>
        <xsl:value-of select="." />
    </xsl:otherwise>
    </xsl:choose>
</li>&lf;
</xsl:template>
<!-- /category/page -->


<!-- ==================================================================== -->
<!-- Process a sitemap category                                           -->
<!-- ==================================================================== -->
<xsl:template match="sitemap/category">
<xsl:call-template name="toplink" />&lf;

<div class="section">
    <!-- Category title -->
    <h2>
        <xsl:choose>
        <xsl:when test="@id">
            <a id="{@id}" name="{@id}">
                <xsl:apply-templates select="title" mode="print" />
            </a>
        </xsl:when>
        <xsl:otherwise>
            <xsl:apply-templates select="title" mode="print" />
        </xsl:otherwise>
        </xsl:choose>
    </h2>&lf;

    <!-- category body -->
    <ul>
        <xsl:apply-templates select="page" />
    </ul>
      
    <!-- optional ... -->
    <xsl:if test="@id = 'modules'">
        <xsl:apply-templates select="document($allmodules)/modulefilelist" />
    </xsl:if>
    &lf;
</div> <!-- /.section -->
</xsl:template>
<!-- /category -->


<!-- ==================================================================== -->
<!-- category/modulefilelist                                              -->
<!-- insert module list into sitemap                                      -->
<!-- ==================================================================== -->
<xsl:template match="modulefilelist">
<xsl:variable name="translist">
    <xsl:text>-</xsl:text>
    <xsl:for-each select="modulefile">
        <xsl:variable name="current" select="document(.)/modulesynopsis" />
   
        <xsl:text> </xsl:text>
        <xsl:value-of select="$current/name" />
        <xsl:text> </xsl:text>
        <xsl:call-template name="module-translatename">
            <xsl:with-param name="name" select="$current/name" />
        </xsl:call-template>
        <xsl:text> -</xsl:text>
    </xsl:for-each>
</xsl:variable>

<ul>
<li>
    <a href="mod/core.html">
        <xsl:value-of select="$message[@id='apachecore']" />
    </a>
</li>&lf;
<li>
    <a href="mod/mpm_common.html">
        <xsl:value-of select="$message[@id='apachempmcommon']" />
    </a>
</li>&lf;

<xsl:for-each select="modulefile">
<xsl:sort select="substring-before(substring-after($translist, concat('- ',
                  document(.)/modulesynopsis/name, ' ')), ' -')" />

    <xsl:variable name="current" select="document(.)/modulesynopsis" />

    <xsl:if test="$current/status='MPM' and $current/name!='mpm_common'">
        <xsl:variable name="name" select="substring-before(substring-after(
                        $translist, concat('- ', $current/name, ' ')), ' -')" />

        <li>
            <a href="mod/{$current/name}.html">
                <xsl:value-of select="$message[@id='apachempm']" />
                <xsl:text> </xsl:text>
                <xsl:value-of select="$name" />
            </a>
        </li>&lf;
    </xsl:if>
</xsl:for-each>
</ul>

<ul>
<xsl:for-each select="modulefile">
<xsl:sort select="substring-before(substring-after($translist, concat('- ',
                  document(.)/modulesynopsis/name, ' ')), ' -')"/>

    <xsl:variable name="current" select="document(.)/modulesynopsis" />

    <xsl:if test="$current/status!='MPM' and $current/status!='Core'">
        <li>
            <a href="mod/{$current/name}.html">
                <xsl:value-of select="$message[@id='apachemodule']"/>
                <xsl:text> </xsl:text>
                <xsl:value-of select="$current/name"/>
            </a>
        </li>&lf;
    </xsl:if>
</xsl:for-each>
</ul>
</xsl:template>
<!-- /category/modulefilelist -->

</xsl:stylesheet>
