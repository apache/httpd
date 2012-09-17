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
<!-- <faq>                                                                -->
<!-- Process an entire document into an HTML page                         -->
<!-- ==================================================================== -->
<xsl:template match="faq">
<html xml:lang="{$doclang}" lang="{$doclang}">
    <xsl:call-template name="head"/>&lf;

    <body id="manual-page">
        <!-- unsqueeze if there's no sidebar -->
        <xsl:if test="   not(count(section) > 1
                      or (/faq/@all-in-one = 'yes')
                      or seealso)">
            <xsl:attribute name="class">no-sidebar</xsl:attribute>
        </xsl:if>

        <xsl:call-template name="top" />          

        <div id="page-content">
            <div id="preamble">        
                <h1>
                    <xsl:value-of select="title" />
                </h1>&lf;

                <xsl:call-template name="langavail" />&lf;

                <xsl:apply-templates select="summary"/>
            </div>&lf; <!-- /#preamble -->

            <xsl:if
                test="(    not($is-chm)
                       and (count(section) > 1 or (/faq/@all-in-one = 'yes')))
                      or seealso">
                <div id="quickview">
                    <xsl:if test="not($is-chm)">
                        <xsl:if test="count(section) > 1">
                            <ul id="toc">
                                <xsl:apply-templates
                                    select="section" mode="index" />
                            </ul>
                        </xsl:if>

                        <xsl:if test="/faq/@all-in-one = 'yes'">
                            <ul id="toc">
                            <li>
                                <img src="{$path}/images/down.gif" alt="" />
                                <xsl:text> </xsl:text>
                                <a href="#topics">
                                    <xsl:value-of select="$message
                                                          [@id='topics']" />
                                </a>
                            </li>&lf;

                            <xsl:apply-templates
                                select="categories/categoryfile" mode="toc" />
                            </ul>
                        </xsl:if>
                    </xsl:if> <!-- !$is-chm -->

                    <xsl:if test="seealso">
                        <h3>
                            <xsl:value-of
                                select="$message[@id='seealso']" />
                        </h3>

                        <ul class="seealso">
                        <xsl:for-each select="seealso">
                            <li>
                                <xsl:apply-templates />
                            </li>
                        </xsl:for-each>
                        </ul>
                    </xsl:if>
                </div>&lf; <!-- /#quickview -->
            </xsl:if> <!-- /have sidebar -->

            <!-- either one ... -->
            <xsl:apply-templates select="section" />
            <!-- ... or the other is allowed -->
            <xsl:apply-templates select="categories" />
        </div>&lf; <!-- /#page-content -->

        <xsl:call-template name="bottom" />&lf;
    </body>
</html>
</xsl:template>
<!-- /faq -->

<!-- ==================================================================== -->
<!-- <categories> (see categories.xml)                                    -->
<!-- ==================================================================== -->
<xsl:template match="categories">
<xsl:call-template name="toplink" />&lf;

<div class="section">&lf;

    <!-- Section heading -->
    <h2>
        <a name="topics" id="topics">
            <xsl:value-of select="$message[@id='topics']" />
        </a>
    </h2>&lf;

    <dl>
        <xsl:apply-templates select="categoryfile" mode="index"/>
    </dl>
</div> <!-- /.section -->

<xsl:if test="/faq/@all-in-one = 'yes'">
    <xsl:apply-templates select="categoryfile" mode="suckin" />
</xsl:if>
</xsl:template>
<!-- /categories -->

<!-- ==================================================================== -->
<!-- <categoryfile> mode="index"                                          -->
<!-- just write the short description with a link to the resource         -->
<!-- ==================================================================== -->
<xsl:template match="categories/categoryfile" mode="index">
<xsl:variable name="current" select="document(.)/faq" />

<dt>
    <a>
        <xsl:attribute name="href">
            <xsl:choose>
            <xsl:when test="/faq/@all-in-one = 'yes'">
                <xsl:value-of select="concat('#', $current/section/@id)" />
            </xsl:when>
            <xsl:otherwise>
                <xsl:value-of select="concat(document($current/@metafile)
                                             /metafile/basename, '.html')" />
            </xsl:otherwise>
            </xsl:choose>
        </xsl:attribute>

        <xsl:value-of select="$current/section/title" />
    </a>
</dt>
<dd>
    <xsl:apply-templates select="$current/description" />
</dd>&lf;
</xsl:template>
<!-- /categoryfile, "index" -->


<!-- ==================================================================== -->
<!-- <categoryfile> mode="toc"                                            -->
<!-- create sidebar links                                                 -->
<!-- ==================================================================== -->
<xsl:template match="categories/categoryfile" mode="toc">
<xsl:variable name="current" select="document(.)/faq" />

<li>
    <img src="{$path}/images/down.gif" alt="" />
    <xsl:text> </xsl:text>
    <a href="#{$current/section/@id}">
        <xsl:value-of select="$current/section/title" />
    </a>
</li>&lf;
</xsl:template>
<!-- /categoryfile, "toc" -->


<!-- ==================================================================== -->
<!-- <categoryfile> mode="suckin"                                         -->
<!-- load whole file contents (for all-in-one page)                       -->
<!-- ==================================================================== -->
<xsl:template match="categories/categoryfile" mode="suckin">
<xsl:apply-templates select="document(.)/faq/section" />
</xsl:template>
<!-- /categoryfile, "suckin" -->

</xsl:stylesheet>
