<?xml version="1.0"?><!--
/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2002-2003 The Apache Software Foundation.  All rights
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
<html xml:lang="{$messages/@lang}" lang="{$messages/@lang}">
    <xsl:call-template name="head"/>&lf;

    <body id="index-page">&lf;
        <xsl:call-template name="top"/>&lf;

        <div id="page-content">
            <h1>
                <xsl:value-of select="title"/>
            </h1>&lf;

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
    <input type="submit" value="{$messages/message[@name='search']}" />

    <!-- the specified number of results -->
    <input type="hidden" name="num" value="10" />

    <!-- the current displayed language -->
    <input type="hidden" name="hl" value="{$messages/@lang}" />

    <!-- the current document encoding for input (?) -->
    <input type="hidden" name="ie" value="{$output-encoding}" />

    <!-- (submit the original button and name) -->
    <input type="hidden" name="btnG" value="Google Search" />

    <!-- including the exact phrase "Apache 2.0" -->
    <input type="hidden" value="Apache 2.0" name="as_epq" />

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
