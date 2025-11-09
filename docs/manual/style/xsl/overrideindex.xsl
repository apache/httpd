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
                xmlns:exslt="http://exslt.org/common"
                xmlns:func="http://exslt.org/functions"
                xmlns:httpd="http://httpd.apache.org/xsl/manual"
                xmlns:set="http://exslt.org/sets"
                xmlns:str="http://exslt.org/strings"
                xmlns="http://www.w3.org/1999/xhtml"
                exclude-result-prefixes="exslt func httpd set str">

<!-- ======================================================================= -->
<!-- <overrideindex>                                                         -->
<!-- Builds the .htaccess overridable directive index                        -->
<!-- ======================================================================= -->
<xsl:template match="overrideindex">
<html xml:lang="{$doclang}" lang="{$doclang}">
    <xsl:call-template name="head"/>&lf;

    <xsl:variable name="directives"
                  select="document(
                            document($allmodules)/modulefilelist/modulefile
                          )/modulesynopsis[status!='Obsolete']
                           /directivesynopsis[not(@location)]" />

    <body id="override-index">&lf;
        <xsl:call-template name="top"/>&lf;&lf;

        <div id="page-content">
            <xsl:call-template name="retired" />

            <div id="preamble">
                <h1>
                    <xsl:value-of select="title" />
                </h1>&lf;

                <xsl:call-template name="langavail" />&lf;

                <xsl:apply-templates select="summary" />
            </div>&lf; <!-- /#preamble -->

            <!-- Quickview Sidebar -->
            <xsl:if test="not($is-chm) or seealso">
                <div id="quickview">
                    <xsl:if test="not($is-chm)">
                        <xsl:if test="overridesummary">
                            <h3>
                                <xsl:value-of select="$message[@id='topics']" />
                            </h3>&lf;

                            <ul id="topics">&lf;
                            <xsl:apply-templates select="overridesummary"
                                                 mode="index" />
                            </ul>
                        </xsl:if>
                    </xsl:if> <!-- /!is-chm -->

                    <!-- The seealso section shows links to related documents
                         explicitly set in .xml docs or simply the comments. -->
                    <xsl:if test="seealso or not($is-chm or $is-zip)">
                        <h3>
                            <xsl:value-of select="$message[@id='seealso']" />
                        </h3>&lf;

                        <ul class="seealso">&lf;
                        <xsl:for-each select="seealso">
                            <li>
                                <xsl:apply-templates />
                            </li>&lf;
                        </xsl:for-each>
                        <xsl:if test="not($is-chm or $is-zip or $metafile/basename = 'index')">
                            <li><a href="#comments_section"><xsl:value-of
                                    select="$message[@id='comments']" /></a>
                            </li>
                        </xsl:if>
                        </ul>
                    </xsl:if>
                </div> <!-- /#quickview -->
            </xsl:if>&lf; <!-- have sidebar -->

            <div id="override-list">
                <xsl:variable name="root" select="." />

                <xsl:for-each select="httpd:override-classes($directives)">
                    <xsl:sort select="." />

                    <xsl:call-template name="override-section">
                        <xsl:with-param name="name" select="." />
                        <xsl:with-param name="directives" select="$directives" />
                        <xsl:with-param name="root" select="$root" />
                    </xsl:call-template>

                </xsl:for-each>
            </div> <!-- /#override-list -->
        </div> <!-- /#page-content -->

        <xsl:call-template name="bottom" />&lf;
    </body>
</html>
</xsl:template>
<!-- /overrideindex -->

<!-- ======================================================================= -->
<!-- <overridesummary>                                                       -->
<!-- Pass-through template for the overridesummary contents.                 -->
<!-- ======================================================================= -->
<xsl:template match="overridesummary">
    <xsl:apply-templates />
</xsl:template>

<!-- Generates an overridesummary index, used in the quickview. -->
<xsl:template match="overridesummary" mode="index">
<xsl:if test="@class">
    <li>
        <img src="{$path}/images/down.gif" alt="" />
        <xsl:text> </xsl:text>
        <a href="#override-{translate(@class, $uppercase, $lowercase)}">
            <xsl:apply-templates select="@class" mode="print" />
        </a>
    </li>&lf;
</xsl:if>
</xsl:template>

<!--
    Generates a section for an Override class, including the section header,
    the class description, and the table of directives belonging to that class.
-->
<xsl:template name="override-section">
    <xsl:param name="name" />       <!-- the name of the Override class -->
    <xsl:param name="directives" /> <!-- the directive nodes -->
    <xsl:param name="root" />       <!-- the root of the overrideindex element -->

    <!-- The "up" arrow link. -->
    <div class="top">
        <a href="#page-header">
            <img alt="top" src="{$path}/images/up.gif" />
        </a>
    </div>

    <div class="section">
        <!-- Section header -->
        <h2>
            <a name="override-{translate($name, $uppercase, $lowercase)}">
                <xsl:value-of select="$name" />
            </a>
        </h2>

        <!--
            Search the input document for the overridesummary element
            corresponding to this Override class, and put its description into
            the document here. If there isn't one, use the fallback element
            (which should alert users/committers to a problem).
        -->
        <xsl:apply-templates select="($root//overridesummary[@class=$name]
                                      | $root//overridesummary[@fallback])[1]" />

        <!-- Directive table -->
        <table class="qref">
        <xsl:for-each select="$directives[contains(override, $name)]">
            <xsl:sort select="name" />

            <!--
                Partially duplicated from quickreference.xsl. Generate a row
                containing the directive name, its description, and its parent
                module. Zebra-stripe every second row.
            -->
            <tr>
                <xsl:if test="position() mod 2 = 0">
                    <xsl:attribute name="class">odd</xsl:attribute>
                </xsl:if>

                <td>
                <a href="{../name}.html#{translate(name, $uppercase, $lowercase)}">
                    <xsl:if test="@type = 'section'">&lt;</xsl:if>
                    <xsl:value-of select="name" />
                    <xsl:if test="@type = 'section'">&gt;</xsl:if>
                </a>
                </td>

                <td class="module">
                <a href="{../name}.html">
                    <xsl:value-of select="../name" />
                </a>
                </td>
            </tr>&lf;

            <tr>
                <xsl:if test="position() mod 2 = 0">
                    <xsl:attribute name="class">odd</xsl:attribute>
                </xsl:if>

                <td class="descr" colspan="2">
                    <xsl:choose>
                    <xsl:when test="string-length(normalize-space(description)) > 0">
                        <xsl:apply-templates select="description" />
                    </xsl:when>
                    <xsl:otherwise>
                        <xsl:text>-</xsl:text>
                    </xsl:otherwise>
                    </xsl:choose>
                </td>
            </tr>&lf;
        </xsl:for-each>
        </table>
    </div>
</xsl:template>
<!-- /override-section -->

<!--
    Returns the set of distinct Override classes reported by the passed set of
    directives.
-->
<func:function name="httpd:override-classes">
    <xsl:param name="directives" />

    <xsl:variable name="overrideValues">
        <xsl:for-each select="$directives/override">
            <xsl:for-each select="str:split(., ',')">
                <value><xsl:value-of select="normalize-space(.)" /></value>
            </xsl:for-each>
        </xsl:for-each>
    </xsl:variable>

    <func:result select="set:distinct(exslt:node-set($overrideValues)/*)" />
</func:function>

</xsl:stylesheet>
