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
<html xml:lang="{$messages/@lang}" lang="{$messages/@lang}">
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
                                    <xsl:value-of select="$messages/message
                                                          [@name='topics']" />
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
                                select="$messages/message[@name='seealso']" />
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
            <xsl:value-of select="$messages/message[@name='topics']" />
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
