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
<!-- <modulesynopsis>                                                     -->
<!-- Process an entire document into an HTML page                         -->
<!-- ==================================================================== -->
<xsl:template match="modulesynopsis">
<html xml:lang="{$doclang}" lang="{$doclang}">
    <xsl:call-template name="head" />&lf;

    <body>&lf;
        <xsl:call-template name="top" />&lf;

        <div id="page-content">&lf;
            <div id="preamble">
                <h1>
                    <xsl:choose>
                    <xsl:when test="status='Core'">
                        <xsl:value-of select="$message
                                              [@id='apachecore']" />
                    </xsl:when>
                    <xsl:when test="name='mpm_common'">
                        <xsl:value-of select="$message
                                              [@id='apachempmcommon']" />
                    </xsl:when>
                    <xsl:when test="status='MPM'">
                        <xsl:value-of select="$message
                                              [@id='apachempm']" />
                        <xsl:text> </xsl:text>
                        <xsl:call-template name="module-translatename">
                            <xsl:with-param name="name" select="name" />
                        </xsl:call-template>
                    </xsl:when>
                    <xsl:otherwise>
                        <xsl:value-of select="$message
                                              [@id='apachemodule']" />
                        <xsl:text> </xsl:text>
                        <xsl:value-of select="name" />
                    </xsl:otherwise>
                    </xsl:choose>
                </h1>&lf;

                <xsl:call-template name="langavail" />&lf;

                <!-- Description and module-headers -->
                <table class="module">
                <tr>
                    <th>
                        <a href="module-dict.html#Description">
                            <xsl:value-of select="$message
                                                  [@id='description']" />
                            <xsl:text>:</xsl:text>
                        </a>
                    </th>
                    <td>
                        <xsl:apply-templates select="description" />
                    </td>
                </tr>&lf;
                <tr>
                    <th>
                        <a href="module-dict.html#Status">
                            <xsl:value-of select="$message
                                                  [@id='status']" />
                            <xsl:text>:</xsl:text>
                        </a>
                    </th>
                    <td>
                        <xsl:variable name="status" select="translate(
                            status, $uppercase, $lowercase)"/>
                        <xsl:choose>
                        <xsl:when test="status = 'External' and status/@href">
                            <a href="{status/@href}">
                                <xsl:value-of select="$message[@id=$status]"/>
                            </a>
                        </xsl:when>
                        <xsl:otherwise>
                            <xsl:value-of
                                select="$message[@id=$status]"/>
                        </xsl:otherwise>
                        </xsl:choose>
                    </td>
                </tr>

                <xsl:if test="identifier">&lf;
                <tr>
                    <th>
                        <a href="module-dict.html#ModuleIdentifier">
                            <xsl:value-of select="$message
                                                  [@id='moduleidentifier']" />
                            <xsl:text>:</xsl:text>
                        </a>
                    </th>
                    <td>
                        <xsl:value-of select="identifier" />
                    </td>
                </tr>
                </xsl:if>

                <xsl:if test="sourcefile">&lf;
                <tr>
                    <th>
                        <a href="module-dict.html#SourceFile">
                            <xsl:value-of select="$message
                                                  [@id='sourcefile']" />
                            <xsl:text>:</xsl:text>
                        </a>
                    </th>
                    <td>
                        <xsl:value-of select="sourcefile" />
                    </td>
                </tr>
                </xsl:if>

                <xsl:if test="compatibility">&lf;
                <tr>
                    <th>
                        <a href="module-dict.html#Compatibility">
                            <xsl:value-of select="$message
                                                  [@id='compatibility']" />
                            <xsl:text>:</xsl:text>
                        </a>
                    </th>
                    <td>
                        <xsl:apply-templates select="compatibility" />
                    </td>
                </tr>
                </xsl:if>
                </table>&lf;

                <!-- Summary of module features/usage (1 to 3 paragraphs, -->
                <!-- optional)                                            -->
                <xsl:if test="summary">
                    <h3>
                        <xsl:value-of select="$message
                                              [@id='summary']" />
                    </h3>&lf;

                    <xsl:apply-templates select="summary" />
                </xsl:if>
            </div>&lf; <!-- /#preamble -->

            <xsl:if test="not($is-chm) or seealso">
                <div id="quickview">
                    <xsl:if test="not($is-chm)">
                        <h3 class="directives">
                            <xsl:value-of select="$message
                                                  [@id='directives']" />
                        </h3>&lf;

                        <xsl:choose>
                        <xsl:when test="document($metafile/@reference)
                                        /modulesynopsis/directivesynopsis">
                            <ul id="toc">&lf;
                            <xsl:for-each
                            select="document($metafile/@reference)
                                    /modulesynopsis/directivesynopsis">
                            <xsl:sort select="name" />
                                <xsl:variable name="lowername"
                                    select="translate(name, $uppercase,
                                                      $lowercase)" />

                                <xsl:choose>
                                <xsl:when test="not(@location)">
                                    <li>
                                        <img src="{$path}/images/down.gif"
                                            alt="" />
                                        <xsl:text> </xsl:text>
                                        <a href="#{$lowername}">
                                            <xsl:if test="@type='section'"
                                                >&lt;</xsl:if>
                                            <xsl:value-of select="name" />
                                            <xsl:if test="@type='section'"
                                                >&gt;</xsl:if>
                                        </a>
                                    </li>&lf;
                                </xsl:when>
                                <xsl:otherwise>
                                    <xsl:variable name="lowerlocation"
                                        select="translate(@location, $uppercase,
                                                          $lowercase)" />
                                    <li>
                                        <img src="{$path}/images/right.gif"
                                            alt="" />
                                        <xsl:text> </xsl:text>
                                        <a href="{$lowerlocation}.html#{
                                                                   $lowername}">
                                            <xsl:if test="@type='section'"
                                                >&lt;</xsl:if>
                                            <xsl:value-of select="name" />
                                            <xsl:if test="@type='section'"
                                                >&gt;</xsl:if>
                                        </a>
                                    </li>&lf;
                                </xsl:otherwise>
                                </xsl:choose>
                            </xsl:for-each>
                            </ul>&lf; <!-- /toc -->
                        </xsl:when> <!-- have directives -->

                        <xsl:otherwise>
                            <p>
                                <xsl:value-of select="$message
                                                      [@id='nodirectives']" />
                            </p>&lf;
                        </xsl:otherwise>
                        </xsl:choose>

                        <xsl:if test="section">
                            <h3>
                                <xsl:value-of select="$message
                                                      [@id='topics']" />
                            </h3>&lf;

                            <ul id="topics">&lf;
                            <xsl:apply-templates
                                select="section" mode="index" />
                            </ul>
                        </xsl:if>
                    </xsl:if> <!-- /!is-chm -->

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
                        </ul>
                    </xsl:if>
                </div> <!-- /#quickview -->
            </xsl:if>&lf; <!-- have sidebar -->

            <!-- Sections of documentation about the module as a whole -->
            <xsl:apply-templates select="section" />&lf;

            <xsl:variable name="this" select="directivesynopsis" />

            <!-- Directive documentation -->
            <xsl:for-each select="document($metafile/@reference)
                                  /modulesynopsis/directivesynopsis">
            <xsl:sort select="name" />
                <xsl:choose>
                <xsl:when test="$this[name=current()/name]">
                    <xsl:apply-templates select="$this[name=current()/name]" />
                </xsl:when>
                <xsl:otherwise>
                    <xsl:apply-templates select=".">
                        <xsl:with-param name="translated" select="'no'" />
                    </xsl:apply-templates>
                </xsl:otherwise>
                </xsl:choose>
            </xsl:for-each>
        </div>&lf; <!-- /#page-content -->

        <xsl:call-template name="bottom" />&lf;
    </body>
</html>
</xsl:template>
<!-- /modulesynopsis -->


<!-- ==================================================================== -->
<!-- Directivesynopsis                                                    -->
<!-- ==================================================================== -->
<xsl:template match="directivesynopsis">
<xsl:param name="translated" select="'yes'" />

<xsl:if test="not(@location)">
    <xsl:call-template name="toplink" />&lf;

    <div class="directive-section">
        <xsl:variable name="lowername"
            select="translate(name, $uppercase, $lowercase)" />

        <!-- Directive heading gets both mixed case and lowercase      -->
        <!-- anchors, and includes lt/gt only for "section" directives -->
        <h2>
            <a id="{name}" name="{name}">
                <xsl:if test="@type='section'">&lt;</xsl:if>
                <xsl:value-of select="name" />
                <xsl:if test="@type='section'">&gt;</xsl:if>
            </a>

            <xsl:choose>
            <xsl:when test="$message
                            [@id='directive']/@replace-space-with">
                <xsl:value-of select="$message
                                      [@id='directive']/@replace-space-with"/>
            </xsl:when>
            <xsl:otherwise>
                <xsl:text> </xsl:text>
            </xsl:otherwise>
            </xsl:choose>

            <a id="{$lowername}" name="{$lowername}">
                <xsl:value-of select="$message[@id='directive']" />
            </a>
        </h2>&lf;

        <!-- Directive header -->
        <table class="directive">&lf;
        <tr>
            <th>
                <a href="directive-dict.html#Description">
                    <xsl:value-of select="$message
                                          [@id='description']" />
                    <xsl:text>:</xsl:text>
                </a>
            </th>
            <td>
                <xsl:apply-templates select="description" />
            </td>
        </tr>&lf;

        <tr>
            <th>
                <a href="directive-dict.html#Syntax">
                    <xsl:value-of select="$message[@id='syntax']" />
                    <xsl:text>:</xsl:text>
                </a>
            </th>
            <td>
                <code>
                    <xsl:apply-templates select="syntax" />
                </code>
            </td>
        </tr>

        <xsl:if test="default">&lf;
        <tr>
            <th>
                <a href="directive-dict.html#Default">
                    <xsl:value-of select="$message[@id='default']" />
                    <xsl:text>:</xsl:text>
                </a>
            </th>
            <td>
                <code>
                    <xsl:apply-templates select="default" />
                </code>
            </td>
        </tr>
        </xsl:if>&lf;

        <tr>
            <th>
                <a href="directive-dict.html#Context">
                    <xsl:value-of select="$message[@id='context']" />
                    <xsl:text>:</xsl:text>
                </a>
            </th>
            <td>
                <xsl:apply-templates select="contextlist" />
            </td>
        </tr>

        <xsl:if test="override">&lf;
        <tr>
            <th>
                <a href="directive-dict.html#Override">
                    <xsl:value-of select="$message[@id='override']"/>
                    <xsl:text>:</xsl:text>
                </a>
            </th>
            <td>
                <xsl:value-of select="override" />
            </td>
        </tr>
        </xsl:if>&lf;

        <tr>
            <th>
                <a href="directive-dict.html#Status">
                    <xsl:value-of select="$message[@id='status']" />
                    <xsl:text>:</xsl:text>
                </a>
            </th>
            <td>
                <xsl:variable name="status" select="translate(
                    ../status, $uppercase, $lowercase)"/>
                <xsl:value-of select="$message[@id=$status]"/>
            </td>
        </tr>&lf;

        <tr>
            <th>
                <a href="directive-dict.html#Module">
                    <xsl:value-of select="$message[@id='module']" />
                    <xsl:text>:</xsl:text>
                </a>
            </th>
            <td>
                <xsl:choose>
                <xsl:when test="modulelist">
                    <xsl:apply-templates select="modulelist" />
                </xsl:when>
                <xsl:otherwise>
                    <xsl:value-of select="../name" />
                </xsl:otherwise>
                </xsl:choose>
            </td>
        </tr>

        <xsl:if test="compatibility">&lf;
        <tr>
            <th>
                <a href="directive-dict.html#Compatibility">
                    <xsl:value-of select="$message
                                          [@id='compatibility']" />
                    <xsl:text>:</xsl:text>
                </a>
            </th>
            <td>
                <xsl:apply-templates select="compatibility" />
            </td>
        </tr>
        </xsl:if>&lf;
        </table>

        <xsl:choose>
        <xsl:when test="$translated = 'yes'">
            <xsl:apply-templates select="usage" />&lf;
        </xsl:when>
        <xsl:otherwise>
            <p><xsl:value-of select="$message[@id='nottranslated']" /></p>
        </xsl:otherwise>
        </xsl:choose>

        <xsl:if test="seealso">
            <h3>
                <xsl:value-of select="$message[@id='seealso']" />
            </h3>&lf;

            <ul>&lf;
            <xsl:for-each select="seealso">
                <li>
                    <xsl:apply-templates />
                </li>&lf;
            </xsl:for-each>
            </ul>&lf;
        </xsl:if>
    </div>&lf; <!-- /.directive-section -->
</xsl:if>
</xsl:template>
<!-- /directivesynopsis -->


<!-- ==================================================================== -->
<!-- <contextlist>                                                        -->
<!-- ==================================================================== -->
<xsl:template match="contextlist">
<xsl:apply-templates select="context" />
</xsl:template>
<!-- /contextlist -->


<!-- ==================================================================== -->
<!-- <context>                                                            -->
<!-- Each entry is separeted with a comma                                 -->
<!-- ==================================================================== -->
<xsl:template match="context">
<xsl:choose>
<xsl:when test="normalize-space(.) = 'server config'">
    <xsl:value-of select="$message[@id='serverconfig']" />
</xsl:when>
<xsl:when test="normalize-space(.) = 'virtual host'">
    <xsl:value-of select="$message[@id='virtualhost']" />
</xsl:when>
<xsl:when test="normalize-space(.) = 'directory'">
    <xsl:value-of select="$message[@id='directory']" />
</xsl:when>
<xsl:when test="normalize-space(.) = '.htaccess'">
    <xsl:value-of select="$message[@id='htaccess']" />
</xsl:when>
<xsl:otherwise> <!-- error -->
    <xsl:message terminate="yes">
        unknown context: <xsl:value-of select="." />
    </xsl:message>
</xsl:otherwise>
</xsl:choose>

<xsl:if test="position() != last()">
    <xsl:text>, </xsl:text>
</xsl:if>
</xsl:template>
<!-- /context -->


<!-- ==================================================================== -->
<!-- <modulelist>                                                         -->
<!-- ==================================================================== -->
<xsl:template match="modulelist">
<xsl:for-each select="module">
    <xsl:call-template name="module" />
    <xsl:if test="position() != last()">
        <xsl:text>, </xsl:text>
    </xsl:if>
</xsl:for-each>
</xsl:template>
<!-- /modulelist -->


<!-- ==================================================================== -->
<!-- modulesynopsis/compatibility                                         -->
<!-- ==================================================================== -->
<xsl:template match="modulesynopsis/compatibility">
<xsl:apply-templates />
</xsl:template>


<!-- ==================================================================== -->
<!-- directivesynopsis/compatibility                                      -->
<!-- ==================================================================== -->
<xsl:template match="directivesynopsis/compatibility">
<xsl:apply-templates />
</xsl:template>

</xsl:stylesheet>
