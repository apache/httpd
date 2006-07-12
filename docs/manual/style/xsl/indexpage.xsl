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

<!--                                                                      -->
<!-- three columns, select were the particular categories shall be        -->
<!-- placed in. (order is irrelevant, they're placed in document order)   -->
<!--                                                                      -->
<xsl:variable name="indexpage-column1" select="'
    release
    manual
'"/>

<xsl:variable name="indexpage-column2" select="'
    usersguide
'"/>

<xsl:variable name="indexpage-column3" select="'
    howto
    platform
    other
'"/>

<!-- ==================================================================== -->
<!-- <indexpage>                                                          -->
<!-- Process an entire document into an HTML page                         -->
<!-- ==================================================================== -->
<xsl:template match="/indexpage">
<html xml:lang="{$doclang}" lang="{$doclang}">
    <xsl:call-template name="head"/>&lf;

    <body id="index-page">&lf;
        <xsl:call-template name="top"/>&lf;

        <div id="page-content">
            <h1>
                <xsl:value-of select="title"/>
            </h1>&lf;

            <xsl:call-template name="langavail" />&lf;

            <form>
                <xsl:call-template name="search.spec" />
            </form>&lf;

            <table id="indextable">
            <tr>
                <td class="col1">
                    <xsl:apply-templates
                        select="category[contains($indexpage-column1, @id)]" />
                </td>
                <td>
                    <xsl:apply-templates
                        select="category[contains($indexpage-column2, @id)]" />
                </td>
                <td class="col3">
                    <xsl:apply-templates
                        select="category[contains($indexpage-column3, @id)]" />
                </td>
            </tr>
            </table>
        </div>&lf; <!-- /#page-content -->

        <xsl:call-template name="bottom" />&lf;
    </body>
</html>
</xsl:template>
<!-- /indexpage -->


<!-- ==================================================================== -->
<!-- category/page                                                        -->
<!-- ==================================================================== -->
<xsl:template match="indexpage/category/page">
<li>
    <xsl:if test="@separate='yes'">
        <xsl:attribute name="class">separate</xsl:attribute>
    </xsl:if>

    <xsl:choose>
    <xsl:when test="@href">
        <a href="{@href}">
            <xsl:call-template name="helper.uri.fix">
                <xsl:with-param name="uri" select="@href"/>
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
<!-- Process a indexpage category                                         -->
<!-- ==================================================================== -->
<xsl:template match="indexpage/category">
<div class="category">
    <!-- Section heading -->
    <h2>
        <xsl:if test="@id">
            <a id="{@id}" name="{@id}">
                <xsl:apply-templates select="title" mode="print" />
            </a>
        </xsl:if>

        <xsl:if test="not(@id)">
            <xsl:apply-templates select="title" mode="print" />
        </xsl:if>
    </h2>&lf;

    <!-- category body -->
    <ul>
        <xsl:apply-templates select="page" />
    </ul>&lf;
</div> <!-- /.section -->
</xsl:template>
<!-- /category -->


<!-- ==================================================================== -->
<!-- search specification                                                 -->
<!-- hidden fields are taken from the advanced search page                -->
<!-- ==================================================================== -->
<xsl:template name="search.spec">
<xsl:attribute name="method">get</xsl:attribute>
<xsl:attribute name="action">http://www.google.com/search</xsl:attribute>
<xsl:if test="$ext-target">
    <xsl:attribute name="target">_blank</xsl:attribute>
</xsl:if>

<p>
    <!-- search google: -->
    <!-- with all of the words -->
    <input type="text" value="" name="as_q" />
    <xsl:text> </xsl:text>
    <input type="submit" value="{$message[@id='search']}" />

    <!-- the specified number of results -->
    <input type="hidden" name="num" value="10" />

    <!-- the current displayed language -->
    <input type="hidden" name="hl" value="{$doclang}" />

    <!-- the current document encoding for input (?) -->
    <input type="hidden" name="ie" value="{$output-encoding}" />

    <!-- (submit the original button and name) -->
    <input type="hidden" name="btnG" value="Google Search" />

    <!-- including the exact phrase "Version major.minor" -->
    <input type="hidden" value="{normalize-space($message[@id='version'])}"
           name="as_epq" />

    <!-- with at least one of the words (none) -->
    <input type="hidden" value="" name="as_oq" />

    <!-- without the phrase "List-Post" (to exclude the mail archives) -->
    <input type="hidden" value="&quot;List-Post&quot;" name="as_eq" />

    <!-- return results written in (any) language -->
    <input type="hidden" name="lr" value="" />

    <!-- and any format -->
    <input type="hidden" name="as_ft" value="i" />
    <input type="hidden" name="as_filetype" value="" />

    <!-- updated anytime -->
    <input type="hidden" name="as_qdr" value="all" />

    <!-- where the result appears anywhere in the document -->
    <input type="hidden" name="as_occt" value="any" />

    <!-- only from httpd.apache.org -->
    <input type="hidden" name="as_dt" value="i" />
    <input type="hidden" name="as_sitesearch" value="httpd.apache.org" />

    <!-- turn off "safe" mode -->
    <input type="hidden" name="safe" value="off" />
</p>
</xsl:template>
<!-- /search.spec -->

</xsl:stylesheet>
