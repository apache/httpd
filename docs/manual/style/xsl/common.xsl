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
    <!ENTITY nbsp SYSTEM "util/nbsp.xml">
    <!ENTITY lf SYSTEM "util/lf.xml">
]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/1999/xhtml">

<!--                                                                      -->
<!-- Please, don't hard-code output strings! Use the language             -->
<!-- files and the translation "stuff"...                                 -->
<!--                                                                      -->

<!-- Injected variables:                                                  -->
<!--   $is-chm          - (boolean) target is for CHM generation or not   -->
<!--   $messages        - (node-set) localized common text snippets       -->
<!--   $output-encoding - (string) MIME charset name of the output        -->
<!--                      encoding                                        -->

<!-- Constants used for case translation -->
<xsl:variable name="lowercase" select="'abcdefghijklmnopqrstuvwxyz'" />
<xsl:variable name="uppercase" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'" />

<!-- space separated list of blockelements defined in common.dtd -->
<!--    used for inline content catching in <example>s           -->
<xsl:variable name="blockelements">
    p  example  note  table  ul  ol  dl  pre  img  blockquote
</xsl:variable>

<!-- relative path to /manual/ -->
<xsl:variable name="path" select="document(/*/@metafile)/metafile/relpath" />

<!-- load outsourced page types -->
<xsl:include href="moduleindex.xsl" />
<xsl:include href="directiveindex.xsl" />
<xsl:include href="manualpage.xsl" />
<xsl:include href="synopsis.xsl" />
<xsl:include href="sitemap.xsl" />
<xsl:include href="indexpage.xsl" />
<xsl:include href="quickreference.xsl" />
<xsl:include href="faq.xsl" />

<!-- load utility snippets -->
<xsl:include href="util/modtrans.xsl" />

<!-- make sure, we set relative anchors only, if we're actually -->
<!-- transforming a modulefile (see <directive> template)       -->
<xsl:variable name="in-modulesynopsis" select="boolean(/modulesynopsis)" />

<!-- when referencing to a directory, we may need to complete the path -->
<!-- with the index file (for offline applications like *.chm files)   -->
<xsl:variable name="index-file">
    <xsl:if test="$is-chm">index.html</xsl:if>
</xsl:variable>

<!-- it may be desired to open external targets in a new window -->
<xsl:variable name="ext-target" select="boolean($is-chm)" />

<!-- #################################################################### -->
<!-- Utility templates for constructing pages                             -->
<!-- #################################################################### -->

<!-- ==================================================================== -->
<!-- HTML head                                                            -->
<!-- ==================================================================== -->
<xsl:template name="head">
<head>
    <!-- the meta element is necessary for offline handling like CHM -->
    <xsl:choose>
    <xsl:when test="$is-chm">
        <meta http-equiv="Content-Type"
                 content="text/html; charset={$output-encoding}" />
    </xsl:when>
    <xsl:otherwise>
        <xsl:comment>
            &lf;
            <xsl:text>        </xsl:text>
            <xsl:text>XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX</xsl:text>
            &lf;
            <xsl:text>              </xsl:text>
            <xsl:text>This file is generated from xml source: DO NOT EDIT</xsl:text>
            &lf;
            <xsl:text>        </xsl:text>
            <xsl:text>XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX</xsl:text>
            &lf;
            <xsl:text>      </xsl:text>
        </xsl:comment>
    </xsl:otherwise>
    </xsl:choose>&lf;

    <title>
        <xsl:choose>
        <xsl:when test="name">
            <xsl:value-of select="name"/>
        </xsl:when>

        <xsl:otherwise>
            <xsl:value-of select="title"/>
        </xsl:otherwise>
        </xsl:choose>

        <xsl:text> </xsl:text>
        <xsl:value-of select="$messages/message[@name='apachetitle']"/>
    </title>&lf;

    <!-- chm files get a slightly different stylesheet -->
    <xsl:choose>
    <xsl:when test="$is-chm">
        <link type="text/css" rel="stylesheet" media="all"
              href="{$path}/style/css/manual-chm.css" />
    </xsl:when>
    <xsl:otherwise>
        <link title="Main stylesheet"  type="text/css" media="all"
                rel="stylesheet"
               href="{$path}/style/css/manual.css" />&lf;
        <link title="No Sidebar - Default font size" type="text/css" media="all"
               rel="alternate stylesheet"
               href="{$path}/style/css/manual-loose-100pc.css"/>
    </xsl:otherwise>
    </xsl:choose>&lf;

    <link type="text/css" media="print"
           rel="stylesheet"
           href="{$path}/style/css/manual-print.css"/>

    <!-- chm files do not need a favicon -->
    <xsl:if test="not($is-chm)">&lf;
        <link rel="shortcut icon" href="{$path}/images/favicon.ico" />
    </xsl:if>
</head>
</xsl:template>
<!-- /head -->


<!-- ==================================================================== -->
<!-- page top                                                             -->
<!-- ==================================================================== -->
<xsl:template name="top">
<div id="page-header">&lf;
    <xsl:call-template name="super-menu" />&lf;

    <p class="apache">
        <xsl:value-of select="$messages/message[@name='apachehttpserver']"/>
    </p>&lf;

    <img src="{$path}/images/feather.gif" alt="" />
</div>&lf; <!-- /page-header -->

<div class="up">
    <a href="./{$index-file}">
        <xsl:if test="parentdocument">
            <xsl:attribute name="href">
                <xsl:value-of select="parentdocument/@href"/>
            </xsl:attribute>

            <xsl:call-template name="helper.uri.fix">
                <xsl:with-param name="uri" select="parentdocument/@href" />
            </xsl:call-template>
      </xsl:if>

      <img src="{$path}/images/left.gif" alt="&lt;-" title="&lt;-" />
    </a>
</div>&lf;

<div id="path">&lf;
    <a href="http://www.apache.org/">
        <xsl:if test="$ext-target">
            <xsl:attribute name="target">_blank</xsl:attribute>
        </xsl:if>
        <xsl:value-of select="$messages/message[@name='apache']" />
    </a>

    <xsl:text> &gt; </xsl:text>

    <a href="http://httpd.apache.org/">
        <xsl:if test="$ext-target">
            <xsl:attribute name="target">_blank</xsl:attribute>
        </xsl:if>
        <xsl:value-of select="$messages/message[@name='http-server']" />
    </a>

    <xsl:text> &gt; </xsl:text>

    <a href="http://httpd.apache.org/docs-project/">
        <xsl:if test="$ext-target">
            <xsl:attribute name="target">_blank</xsl:attribute>
        </xsl:if>
        <xsl:value-of select="$messages/message[@name='documentation']" />
    </a>

    <xsl:if test="not(../indexpage)">
    <xsl:text> &gt; </xsl:text>

    <a href="{$path}/{$index-file}">
        <xsl:value-of select="$messages/message[@name='version']"/>
    </a>
    </xsl:if>

    <xsl:if test="../modulesynopsis or ../directiveindex or ../quickreference">
    <xsl:text> &gt; </xsl:text>

    <a href="./{$index-file}">
        <xsl:value-of select="$messages/message[@name='modules']"/>
    </a>
    </xsl:if>

    <xsl:if test="parentdocument/text()">
    <xsl:text> &gt; </xsl:text>

    <a href="{parentdocument/@href}">
        <xsl:call-template name="helper.uri.fix">
            <xsl:with-param name="uri" select="parentdocument/@href"/>
        </xsl:call-template>
        <xsl:value-of select="parentdocument"/>
    </a>
    </xsl:if>
</div> <!-- /path -->
</xsl:template>
<!-- /top -->


<!-- ==================================================================== -->
<!-- page bottom                                                          -->
<!-- ==================================================================== -->
<xsl:template name="bottom">
<xsl:call-template name="langavail">
    <xsl:with-param name="position" select="'bottom'" />
</xsl:call-template>

<div id="footer">&lf;
    <p class="apache">
        <xsl:value-of select="$messages/message[@name='maintainedby']"/>
        <xsl:text> </xsl:text>
        <a href="http://httpd.apache.org/docs-project/">
            <xsl:if test="$ext-target">
                <xsl:attribute name="target">_blank</xsl:attribute>
            </xsl:if>
            <xsl:text>Apache HTTP Server Documentation Project</xsl:text>
        </a>
    </p>&lf;

    <xsl:call-template name="super-menu"/>

</div> <!-- /footer -->
</xsl:template>
<!-- /bottom -->


<!-- ==================================================================== -->
<!-- build an "available languages" section                               -->
<!-- ==================================================================== -->
<xsl:template name="langavail">
<xsl:param name="position" select="'top'" />
<xsl:variable name="metafile" select="document(/*/@metafile)/metafile" />

<xsl:if test="not($is-chm)">
<div class="{$position}lang">&lf;
    <p>
        <span>
            <xsl:value-of select="$messages/message[@name='langavail']" />
            <xsl:text>: </xsl:text>
        </span>

        <xsl:for-each select="$metafile/variants/variant">
        <xsl:sort select="." />

            <a hreflang="{.}"
                   href="{$path}/{.}{$metafile/path}{$metafile/basename}.html">
                <xsl:if test="$metafile/basename = 'index'">
                    <xsl:attribute name="href">
                        <xsl:value-of
                            select="concat($path, '/', ., $metafile/path)" />
                    </xsl:attribute>
                </xsl:if>
                <xsl:attribute name="title">
                    <xsl:choose>
                    <xsl:when test=". != 'fr'"> <!-- no language file avail. -->
                        <xsl:value-of select="document(concat('../lang/', ., '.xml'))
                                              /messages/@langname" />
                    </xsl:when>
                    <xsl:otherwise>
                        <xsl:text>Fran&#231;ais</xsl:text>
                    </xsl:otherwise>
                    </xsl:choose>
                </xsl:attribute>

                &nbsp;
                <xsl:value-of select="." />
                &nbsp;
            </a>
            <xsl:if test="position() != last()"> | </xsl:if>
        </xsl:for-each>
    </p>&lf;
</div> <!-- /.{$position}lang -->
</xsl:if>
</xsl:template>
<!-- /langavail -->


<!-- ==================================================================== -->
<!-- Process a documentation section                                      -->
<!-- ==================================================================== -->
<xsl:template match="section">
<xsl:call-template name="toplink" />&lf;
<div class="section">&lf;

    <!-- Section heading -->
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
    </h2>

    <!-- Section body -->
    <xsl:apply-templates />
</div> <!-- /.section -->
</xsl:template>
<!-- /section -->


<!-- ==================================================================== -->
<!-- handle subsections (lower level headings)                            -->
<!-- ==================================================================== -->
<xsl:template match="section/section">
<!-- Section heading -->
<h3>
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
</h3>

<!-- Section body -->
<xsl:apply-templates />
</xsl:template>
<!-- /section/section -->


<!-- ==================================================================== -->
<!-- handle subsubsections (h4)                                           -->
<!-- ==================================================================== -->
<xsl:template match="section/section/section">
<!-- Section heading -->
<h4>
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
</h4>

<!-- Section body -->
<xsl:apply-templates/>

</xsl:template>
<!-- /section/section/section -->


<!-- ==================================================================== -->
<!-- section nesting > h4 is not supported for now                        -->
<!-- ==================================================================== -->
<xsl:template match="section/section/section/section">
<xsl:message terminate="yes">
    <xsl:text>FATAL: exceeding maximum section nesting level.</xsl:text>
    &lf;&lf;
    <xsl:text>Perhaps you should consider to split your document into</xsl:text>
    &lf;
    <xsl:text>several ones...</xsl:text>
    &lf;
</xsl:message>
</xsl:template>
<!-- /section/section/section/section -->


<!-- ==================================================================== -->
<!-- (sub)section titles                                                  -->
<!-- ==================================================================== -->
<xsl:template match="section/title" mode="print">
<xsl:apply-templates/>
</xsl:template>
<xsl:template match="section/title" />
<!-- /section/title -->


<!-- ==================================================================== -->
<!-- generate section index                                               -->
<!-- ==================================================================== -->
<xsl:template match="section" mode="index">
<li>
    <img src="{$path}/images/down.gif" alt="" />
    <xsl:text> </xsl:text>
    <xsl:choose>
    <xsl:when test="@id">
        <a href="#{@id}">
            <xsl:apply-templates select="title" mode="print" />
        </a>
    </xsl:when>
    <xsl:otherwise>
        <xsl:apply-templates select="title" mode="print" />
    </xsl:otherwise>
    </xsl:choose>
</li>&lf;
</xsl:template>
<!-- /section index -->


<!-- ==================================================================== -->
<!-- docs super menu                                                      -->
<!-- ==================================================================== -->
<xsl:template name="super-menu">
<p class="menu">
    <a href="{$path}/mod/{$index-file}">
        <xsl:value-of select="$messages/message[@name='modules']" />
    </a>

    <xsl:text> | </xsl:text>

    <a href="{$path}/mod/directives.html">
        <xsl:value-of select="$messages/message[@name='directives']" />
    </a>

    <xsl:text> | </xsl:text>

    <a href="{$path}/faq/{$index-file}">
        <xsl:value-of select="$messages/message[@name='faq']" />
    </a>

    <xsl:text> | </xsl:text>

    <a href="{$path}/glossary.html">
        <xsl:value-of select="$messages/message[@name='glossary']" />
    </a>

    <xsl:text> | </xsl:text>

    <a href="{$path}/sitemap.html">
        <xsl:value-of select="$messages/message[@name='sitemap']" />
    </a>
</p>
</xsl:template>
<!-- /super-menu -->


<!-- ==================================================================== -->
<!-- <example>                                                            -->
<!-- iterate over *all* nodes; bare text and other inline stuff is        -->
<!-- wrapped into <p><code>, block level elements (defined in             -->
<!-- $blockelements) are applied "as is"                                  -->
<!-- ==================================================================== -->
<xsl:variable name="blocks"
            select="concat(' ', normalize-space($blockelements), ' ')" />

<xsl:template match="example">
<div class="example">
    <xsl:apply-templates select="title" mode="print" />

    <xsl:for-each select="./node()">
        <xsl:variable name="is-block-node"
                    select="boolean(contains($blocks,
                                             concat(' ', local-name(), ' ')))"/>
        <!-- bb = (number of) blocks nodes before (the current) -->
        <xsl:variable name="bb"
                    select="count(preceding-sibling::*[
                                contains($blocks,
                                         concat(' ', local-name(), ' '))])" />

        <xsl:if test="$is-block-node or position()=last()">
            <xsl:variable name="content">
                <!-- phew. short explanation, what happens here:      -->
                <!-- We want to get the inline stuff between the last -->
                <!-- block node and the current node.                 -->
                <!-- So filter all previous nodes for the condition   -->
                <!-- that the number of block nodes of all of *their* -->
                <!-- previous nodes is >= $bb. Hope that helps ;-)    -->
                <xsl:apply-templates
                    select="preceding-sibling::node()[
                                count(preceding-sibling::*[
                                    contains($blocks,
                                             concat(' ', local-name(), ' '))])
                                &gt;= $bb]" />

                <xsl:apply-templates
                    select="self::node()[not($is-block-node)]" />
            </xsl:variable>

            <!-- apply bare text only, if it's not only \s or empty -->
            <xsl:if test="not(normalize-space($content) = '')">
                <p><code>
                    <!-- same as $content above. xsl:copy-of seems to make -->
                    <!-- thread problems with xalan-j ... -->
                    <xsl:apply-templates
                        select="preceding-sibling::node()[
                                    count(preceding-sibling::*[
                                        contains($blocks,
                                                 concat(' ', local-name(),
                                                        ' '))])
                                    &gt;= $bb]" />

                    <xsl:apply-templates
                        select="self::node()[not($is-block-node)]" />
                </code></p>
            </xsl:if>

            <xsl:apply-templates select="self::node()[$is-block-node]" />
        </xsl:if>
    </xsl:for-each>
    <!-- /node() -->
</div> <!-- /.example -->
</xsl:template>
<!-- /example -->


<!-- ==================================================================== -->
<!-- example/title                                                        -->
<!-- ==================================================================== -->
<xsl:template match="example/title" mode="print">
<h3>
    <xsl:apply-templates/>
</h3>
</xsl:template>
<xsl:template match="example/title" />
<!-- /example/title -->


<!-- ==================================================================== -->
<!-- indentations                                                         -->
<!-- ==================================================================== -->
<xsl:template match="indent">
<span class="indent">
    <xsl:apply-templates/>
</span>
</xsl:template>
<!-- /indent -->


<!-- ==================================================================== -->
<!-- <note>                                                               -->
<!-- ==================================================================== -->
<xsl:template match="note">
<div class="note">
    <xsl:if test="@type='warning'">
        <xsl:attribute name="class">warning</xsl:attribute>
    </xsl:if>

    <xsl:apply-templates/>
</div>
</xsl:template>
<!-- /note -->


<!-- ==================================================================== -->
<!-- <note><title>                                                        -->
<!-- ==================================================================== -->
<xsl:template match="note/title">
<h3>
    <xsl:apply-templates/>
</h3>
</xsl:template>
<!-- /note/title -->


<!-- ==================================================================== -->
<!-- <directive>                                                          -->
<!-- Inserts link to another directive, which might be in another module. -->
<!-- References are converted into lower case.                            -->
<!-- ==================================================================== -->
<xsl:template match="directive" name="directive">
<code class="directive">
    <xsl:choose>
    <xsl:when test="@module">
        <xsl:variable name="lowerdirective"
            select="translate(., $uppercase, $lowercase)" />

        <xsl:choose>
        <xsl:when test="$in-modulesynopsis and @module = /modulesynopsis/name">
            <a href="#{$lowerdirective}">
                <xsl:if test="@type='section'">&lt;</xsl:if>
                <xsl:value-of select="."/>
                <xsl:if test="@type='section'">&gt;</xsl:if>
            </a>
        </xsl:when>
        <xsl:otherwise>
            <a href="{$path}/mod/{@module}.html#{$lowerdirective}">
                <xsl:if test="@type='section'">&lt;</xsl:if>
                <xsl:value-of select="."/>
                <xsl:if test="@type='section'">&gt;</xsl:if>
            </a>
        </xsl:otherwise>
        </xsl:choose>
    </xsl:when>

    <xsl:otherwise>
        <xsl:if test="@type='section'">&lt;</xsl:if>
        <xsl:value-of select="."/>
        <xsl:if test="@type='section'">&gt;</xsl:if>
    </xsl:otherwise>
    </xsl:choose>
</code>
</xsl:template>
<!-- /directive -->


<!-- ==================================================================== -->
<!-- <module>                                                             -->
<!-- Inserts a link to refereed module                                    -->
<!-- ==================================================================== -->
<xsl:template match="module" name="module">
<code class="module">
    <a href="{$path}/mod/{.}.html">
        <xsl:value-of select="."/>
    </a>
</code>
</xsl:template>
<!-- /module -->


<!-- ==================================================================== -->
<!-- <related>                                                            -->
<!-- ==================================================================== -->
<xsl:template match="related">
<table class="related">
<tr>
    <th>
        <xsl:value-of select="$messages/message[@name='relatedmodules']" />
    </th>
    <th>
        <xsl:value-of select="$messages/message[@name='relateddirectives']" />
    </th>
</tr>
<tr>
    <td>
        <xsl:if test="count(modulelist/*) &gt; 0">
            <ul>
                <xsl:apply-templates select="modulelist" />
            </ul>
        </xsl:if>
    </td>
    <td>
        <xsl:if test="count(directivelist/*) &gt; 0">
            <ul>
                <xsl:apply-templates select="directivelist"/>
            </ul>
        </xsl:if>
    </td>
</tr>
</table>
</xsl:template>
<!-- /related -->

<!-- ==================================================================== -->
<!-- related/modulelist                                                   -->
<!-- ==================================================================== -->
<xsl:template match="related/modulelist">
<xsl:for-each select="module">
    <li>
        <xsl:call-template name="module"/>
    </li>
</xsl:for-each>
</xsl:template>
<!-- /related/modulelist -->


<!-- ==================================================================== -->
<!-- related/directivelist                                                -->
<!-- ==================================================================== -->
<xsl:template match="related/directivelist">
<xsl:for-each select="directive">
    <li>
        <xsl:call-template name="directive"/>
    </li>
</xsl:for-each>
</xsl:template>
<!-- /related/directivelist -->

<!-- ==================================================================== -->
<!-- <table>                                                              -->
<!-- ==================================================================== -->
<xsl:template match="table">
<table>
    <!-- existing border attribute will result in <table class="bordered"> -->
    <xsl:if test="@border">
        <xsl:attribute name="class">bordered</xsl:attribute>
    </xsl:if>

    <!-- style="zebra": alternating colors per row, i.e. every second row -->
    <!--                gets a class="odd". Header lines (no <td>) get a  -->
    <!--                class="header". These lines will be excluded from -->
    <!--                the "odd" line count. That way header lines act   -->
    <!--                interjectional, which creates a better visual and -->
    <!--                psychological effect.                             -->
    <xsl:choose>
    <xsl:when test="@style = 'zebra'">
        <xsl:for-each select="tr">
            <tr>
                <xsl:choose>
                <xsl:when test="count(td) = 0">
                    <xsl:attribute name="class">header</xsl:attribute>
                </xsl:when>

                <xsl:when
                    test="position() mod 2 =
                            (count(preceding-sibling::*[count(td) = 0]) mod 2)">
                    <xsl:attribute name="class">odd</xsl:attribute>
                </xsl:when>
                </xsl:choose>

                <xsl:apply-templates />
            </tr>&lf;
        </xsl:for-each>
    </xsl:when>
    <xsl:otherwise>
        <xsl:apply-templates />
    </xsl:otherwise>
    </xsl:choose>
</table>
</xsl:template>
<!-- /table -->


<!-- ==================================================================== -->
<!-- <ol>                                                                 -->
<!-- ==================================================================== -->
<xsl:template match="ol">
<ol>
    <!-- A. B. C. D. (list-style-type="upper-alpha") -->
    <xsl:if test="@type = 'A'">
        <xsl:attribute name="class">up-A</xsl:attribute>
    </xsl:if>

    <xsl:apply-templates/>
</ol>
</xsl:template>
<!-- /ol -->


<!-- ==================================================================== -->
<!-- diverse elements                                                     -->
<!-- Passes through content                                               -->
<!-- ==================================================================== -->
<xsl:template match="summary|description|usage|syntax|default">
<xsl:apply-templates/>
</xsl:template>
<!-- /diverse -->


<!-- ==================================================================== -->
<!-- <a>                                                                  -->
<!-- ==================================================================== -->
<xsl:template match="a">
<xsl:choose>
<xsl:when test="not(@href)">
    <xsl:copy>
        <xsl:apply-templates select="@*|*|text()"/>
    </xsl:copy>
</xsl:when>
<xsl:otherwise>
    <a href="@href">
        <xsl:apply-templates select="@*"/>
        <xsl:call-template name="helper.uri.fix">
            <xsl:with-param name="uri" select="@href"/>
        </xsl:call-template>

        <xsl:apply-templates select="*|text()"/>
    </a>
</xsl:otherwise>
</xsl:choose>
</xsl:template> 
<!-- /a -->


<!-- ==================================================================== -->
<!-- toplink                                                              -->
<!-- ==================================================================== -->
<xsl:template name="toplink">
<div class="top">
    <a href="#page-header"><img src="{$path}/images/up.gif" alt="top" /></a>
</div>
</xsl:template>
<!-- /toplink -->


<!-- ==================================================================== -->
<!-- <transnote>                                                          -->
<!-- translator's notes are displayed in a different color                -->
<!-- ==================================================================== -->
<xsl:template match="transnote">
<span class="transnote">
    <xsl:text>(</xsl:text>
    <em>
        <xsl:value-of select="$messages/message[@name='transnote']" />
    </em>
    <xsl:text> </xsl:text>
    <xsl:apply-templates />
    <xsl:text>)</xsl:text>
</span>
</xsl:template>
<!-- /transnote -->


<!-- ==================================================================== -->
<!-- Filter &#160; in text() nodes.                                       -->
<!-- In some environments this character won't be transformed correctly,  -->
<!-- so we just write it explicitely as "&nbsp;" into the output.         -->
<!-- ==================================================================== -->
<xsl:template match="text()" name="filter.nbsp">
<xsl:param name="text" select="." />

<xsl:choose>
<xsl:when test="contains($text, '&#160;')">
    <xsl:value-of select="substring-before($text, '&#160;')" />
    &nbsp;
    <xsl:call-template name="filter.nbsp">
        <xsl:with-param name="text" select="substring-after($text, '&#160;')" />
    </xsl:call-template>
</xsl:when>
<xsl:otherwise>
    <xsl:value-of select="$text" />
</xsl:otherwise>
</xsl:choose>
</xsl:template>
<!-- /filter.nbsp -->


<!-- ==================================================================== -->
<!-- Process everything else by just passing it through                   -->
<!-- ==================================================================== -->
<xsl:template match="*|@*">
<xsl:copy>
    <xsl:apply-templates select="*|@*|text()" />
</xsl:copy>
</xsl:template>
<!-- /pass through -->


<!-- ==================================================================== -->
<!-- create a letter bar                                                  -->
<!-- ==================================================================== -->
<xsl:template name="letter-bar">
<xsl:param name="letters" />
<xsl:param name="first" />

<xsl:if test="not($first)">
    <xsl:text> | </xsl:text>
</xsl:if>

<a href="#{substring($letters,1,1)}">
    &nbsp;
    <xsl:value-of select="substring($letters, 1, 1)" />
    &nbsp;
</a>

<xsl:if test="string-length($letters) &gt; 1">
    <xsl:call-template name="letter-bar">
        <xsl:with-param name="letters" select="substring($letters, 2)" />
        <xsl:with-param name="first" select="false()" />
    </xsl:call-template>
</xsl:if>
</xsl:template>
<!-- /letter-bar -->


<!-- ==================================================================== -->
<!-- template(s) for collecting all start letters of directives           -->
<!-- ==================================================================== -->
<xsl:template name="directive-startletters">
<xsl:param name="directives" />

<xsl:call-template name="_squeeze-letters">
    <xsl:with-param name="lastletter" select="''" />
    <xsl:with-param name="letters">
        <xsl:for-each select="$directives">
        <xsl:sort select="name"/>
            <xsl:value-of
                select="translate(substring(normalize-space(name), 1, 1),
                                  $lowercase, $uppercase)" />
        </xsl:for-each>
    </xsl:with-param>
</xsl:call-template>
</xsl:template>
<!-- /directive-startletters -->


<!-- ==================================================================== -->
<!-- squeeze subsequent letters in a string                               -->
<!-- ==================================================================== -->
<xsl:template name="_squeeze-letters">
<xsl:param name="letters"/>
<xsl:param name="lastletter"/>

<xsl:variable name="current" select="substring($letters, 1, 1)" />

<xsl:if test="not($lastletter = $current)">
    <xsl:value-of select="$current" />
</xsl:if>

<xsl:if test="string-length($letters) &gt; 1">
    <xsl:call-template name="_squeeze-letters">
        <xsl:with-param name="letters" select="substring($letters, 2)" />
        <xsl:with-param name="lastletter" select="$current"/>
    </xsl:call-template>
</xsl:if>
</xsl:template>
<!-- /_squeeze-letters -->


<!-- ==================================================================== -->
<!-- fix href and target attribute of an element.                         -->
<!-- ==================================================================== -->
<xsl:template name="helper.uri.fix">
<xsl:param name="uri"/>

<xsl:choose>
<!-- lame is_absolute_uri test -->
<xsl:when test="    contains($uri, ':')
                and string-length(substring-before($uri, ':')) &lt; 7">
    <xsl:if test="$ext-target">
        <xsl:attribute name="target">_blank</xsl:attribute>
    </xsl:if>
</xsl:when>
<xsl:otherwise>
    <xsl:variable name="fragment">
        <xsl:if test="contains($uri, '#')">
            <xsl:value-of select="concat('#', substring-after($uri, '#'))"/>
        </xsl:if>
    </xsl:variable>
    <xsl:variable name="absuri">
        <xsl:choose>
        <xsl:when test="contains($uri, '#')">
            <xsl:value-of select="concat('#', substring-before($uri, '#'))"/>
        </xsl:when>
        <xsl:otherwise>
            <xsl:value-of select="$uri"/>
        </xsl:otherwise>
        </xsl:choose>
    </xsl:variable>
        
    <xsl:if test="substring($absuri, string-length($uri), 1) = '/'">
        <xsl:attribute name="href">
            <xsl:value-of select="concat($absuri, $index-file, $fragment)"/>
        </xsl:attribute>
    </xsl:if>
</xsl:otherwise>
</xsl:choose>
</xsl:template>
<!-- /helper.uri.fix -->

</xsl:stylesheet>
