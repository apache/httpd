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

<!-- ==================================================================== -->
<!-- <modulesynopsis>                                                     -->
<!-- Process an entire document into an HTML page                         -->
<!-- ==================================================================== -->
<xsl:template match="modulesynopsis">
<html xml:lang="{$messages/@lang}" lang="{$messages/@lang}">
    <xsl:call-template name="head" />&lf;

    <body>&lf;
        <xsl:call-template name="top" />&lf;

        <div id="page-content">&lf;
            <div id="preamble">
                <h1>
                    <xsl:choose>
                    <xsl:when test="status='Core'">
                        <xsl:value-of select="$messages/message
                                              [@name='apachecore']" />
                    </xsl:when>
                    <xsl:when test="name='mpm_common'">
                        <xsl:value-of select="$messages/message
                                              [@name='apachempmcommon']" />
                    </xsl:when>
                    <xsl:when test="status='MPM'">
                        <xsl:value-of select="$messages/message
                                              [@name='apachempm']" />
                        <xsl:text> </xsl:text>
                        <xsl:call-template name="module-translatename">
                            <xsl:with-param name="name" select="name" />
                        </xsl:call-template>
                    </xsl:when>
                    <xsl:otherwise>
                        <xsl:value-of select="$messages/message
                                              [@name='apachemodule']" />
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
                            <xsl:value-of select="$messages/message
                                                  [@name='description']" />
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
                            <xsl:value-of select="$messages/message
                                                  [@name='status']" />
                            <xsl:text>:</xsl:text>
                        </a>
                    </th>
                    <td>
                        <xsl:value-of select="status" />
                    </td>
                </tr>

                <xsl:if test="identifier">&lf;
                <tr>
                    <th>
                        <a href="module-dict.html#ModuleIdentifier">
                            <xsl:value-of select="$messages/message
                                                  [@name='moduleidentifier']" />
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
                            <xsl:value-of select="$messages/message
                                                  [@name='sourcefile']" />
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
                            <xsl:value-of select="$messages/message
                                                  [@name='compatibility']" />
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
                        <xsl:value-of select="$messages/message
                                              [@name='summary']" />
                    </h3>&lf;

                    <xsl:apply-templates select="summary" />
                </xsl:if>
            </div>&lf; <!-- /#preamble -->

            <xsl:if test="not($is-chm) or seealso">
                <div id="quickview">
                    <xsl:if test="not($is-chm)">
                        <h3 class="directives">
                            <xsl:value-of select="$messages/message
                                                  [@name='directives']" />
                        </h3>&lf;

                        <xsl:choose>
                        <xsl:when test="directivesynopsis">
                            <ul id="toc">&lf;
                            <xsl:for-each select="directivesynopsis">
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
                                <xsl:value-of select="$messages/message
                                                      [@name='nodirectives']" />
                            </p>&lf;
                        </xsl:otherwise>
                        </xsl:choose>

                        <xsl:if test="section">
                            <h3>
                                <xsl:value-of select="$messages/message
                                                      [@name='topics']" />
                            </h3>&lf;

                            <ul id="topics">&lf;
                            <xsl:apply-templates
                                select="section" mode="index" />
                            </ul>
                        </xsl:if>
                    </xsl:if> <!-- /!is-chm -->

                    <xsl:if test="seealso">
	                    <h3>
                            <xsl:value-of select="$messages/message
                                                  [@name='seealso']" />
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

            <!-- Directive documentation -->
            <xsl:apply-templates select="directivesynopsis">
                <xsl:sort select="name" />
            </xsl:apply-templates>
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
            <xsl:when test="$messages/message
                            [@name='directive']/@replace-space-with">
                <xsl:value-of select="$messages/message
                                      [@name='directive']/@replace-space-with"/>
            </xsl:when>
            <xsl:otherwise>
                <xsl:text> </xsl:text>
            </xsl:otherwise>
            </xsl:choose>

            <a id="{$lowername}" name="{$lowername}">
                <xsl:value-of select="$messages/message[@name='directive']" />
            </a>
        </h2>&lf;

        <!-- Directive header -->
        <table class="directive">&lf;
        <tr>
            <th>
                <a href="directive-dict.html#Description">
                    <xsl:value-of select="$messages/message
                                          [@name='description']" />
                    <xsl:text>:</xsl:text>
                </a>
            </th>
            <td>
                <xsl:value-of select="description" />
            </td>
        </tr>&lf;

        <tr>
            <th>
                <a href="directive-dict.html#Syntax">
                    <xsl:value-of select="$messages/message[@name='syntax']" />
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
                    <xsl:value-of select="$messages/message[@name='default']" />
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
                    <xsl:value-of select="$messages/message[@name='context']" />
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
                    <xsl:value-of select="$messages/message[@name='override']"/>
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
                    <xsl:value-of select="$messages/message[@name='status']" />
                    <xsl:text>:</xsl:text>
                </a>
            </th>
            <td>
                <xsl:value-of select="../status" />
            </td>
        </tr>&lf;

        <tr>
            <th>
                <a href="directive-dict.html#Module">
                    <xsl:value-of select="$messages/message[@name='module']" />
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
                    <xsl:value-of select="$messages/message
                                          [@name='compatibility']" />
                    <xsl:text>:</xsl:text>
                </a>
            </th>
            <td>
                <xsl:apply-templates select="compatibility" />
            </td>
        </tr>
        </xsl:if>&lf;
        </table>

        <xsl:apply-templates select="usage" />&lf;

        <xsl:if test="seealso">
            <h3>
                <xsl:value-of select="$messages/message[@name='seealso']" />
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
    <xsl:value-of select="$messages/message[@name='serverconfig']" />
</xsl:when>
<xsl:when test="normalize-space(.) = 'virtual host'">
    <xsl:value-of select="$messages/message[@name='virtualhost']" />
</xsl:when>
<xsl:when test="normalize-space(.) = 'directory'">
    <xsl:value-of select="$messages/message[@name='directory']" />
</xsl:when>
<xsl:when test="normalize-space(.) = '.htaccess'">
    <xsl:value-of select="$messages/message[@name='htaccess']" />
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
