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
<!-- <quickreference>                                                     -->
<!-- Builds the directive quickreference page                             -->
<!-- ==================================================================== -->
<xsl:template match="quickreference">
<html xml:lang="{$doclang}" lang="{$doclang}">
    <xsl:call-template name="head"/>&lf;

    <body id="directive-index">&lf;
        <xsl:call-template name="top"/>&lf;

        <div id="preamble">
            <h1>
                <xsl:value-of select="title" />
            </h1>&lf;

            <xsl:call-template name="langavail" />&lf;

            <xsl:apply-templates select="summary" />
        </div>&lf; <!-- /#preamble -->

        <div id="directive-ref">
            <xsl:variable name="directives"
                select="document(document(document(
                            document($allmodules)/modulefilelist/modulefile
                        )/*/@metafile)/metafile/@reference)
                        /modulesynopsis/directivesynopsis[not(@location)]" />
            <xsl:variable name="modules"
                select="document(
                            document($allmodules)/modulefilelist/modulefile
                        )/modulesynopsis" />

            <xsl:variable name="start-letters">
                <xsl:call-template name="directive-startletters">
                    <xsl:with-param name="directives" select="$directives" />
                </xsl:call-template>
            </xsl:variable>

            <table id="legend">&lf;
            <tr>
                <td class="letters">
                    <span>
                        <xsl:call-template name="letter-bar">
                            <xsl:with-param name="letters"
                                select="$start-letters" />
                            <xsl:with-param name="first" select="true()" />
                        </xsl:call-template>
                    </span>
                </td>&lf;
                <td>
                    <table>
                    <tr>
                        <th>
                            <xsl:value-of
                                select="$message[@id='serverconfig']/@letter"/>
                        </th>
                        <td>
                            <xsl:value-of
                                select="$message[@id='serverconfig']"/>
                        </td>
                    </tr>&lf;
                    <tr>
                        <th>
                            <xsl:value-of
                                select="$message[@id='virtualhost']/@letter"/>
                        </th>
                        <td>
                            <xsl:value-of
                                select="$message[@id='virtualhost']"/>
                        </td>
                    </tr>&lf;
                    <tr>
                        <th>
                            <xsl:value-of
                                select="$message[@id='directory']/@letter"/>
                        </th>
                        <td>
                            <xsl:value-of
                                select="$message[@id='directory']"/>
                        </td>
                    </tr>&lf;
                    <tr>
                        <th>
                            <xsl:value-of
                                select="$message[@id='htaccess']/@letter"/>
                        </th>
                        <td>
                            <xsl:value-of
                                select="$message[@id='htaccess']"/>
                        </td>
                    </tr>&lf;
                    </table>
                </td>&lf;
                <td>
                    <table>
                    <tr>
                        <th>
                            <xsl:value-of
                                select="$message[@id='core']/@letter"/>
                        </th>
                        <td>
                            <xsl:value-of
                                select="$message[@id='core']"/>
                        </td>
                    </tr>&lf;
                    <tr>
                        <th>
                            <xsl:value-of
                                select="$message[@id='mpm']/@letter"/>
                        </th>
                        <td>
                            <xsl:value-of
                                select="$message[@id='mpm']"/>
                        </td>
                    </tr>&lf;
                    <tr>
                        <th>
                            <xsl:value-of
                                select="$message[@id='base']/@letter"/>
                        </th>
                        <td>
                            <xsl:value-of
                                select="$message[@id='base']"/>
                        </td>
                    </tr>&lf;
                    <tr>
                        <th>
                            <xsl:value-of
                                select="$message[@id='extension']/@letter"/>
                        </th>
                        <td>
                            <xsl:value-of
                                select="$message[@id='extension']"/>
                        </td>
                    </tr>&lf;
                    <tr>
                        <th>
                            <xsl:value-of
                                select="$message[@id='experimental']/@letter"/>
                        </th>
                        <td>
                            <xsl:value-of
                                select="$message[@id='experimental']"/>
                        </td>
                    </tr>&lf;
                    <tr>
                        <th>
                            <xsl:value-of
                                select="$message[@id='external']/@letter"/>
                        </th>
                        <td>
                            <xsl:value-of
                                select="$message[@id='external']"/>
                        </td>
                    </tr>&lf;
                    </table>
                </td>
            </tr>&lf;
            </table>&lf;

            <table class="qref">&lf;
            <xsl:call-template name="reference-of-letter">
                <xsl:with-param name="letters-todo" select="$start-letters" />
                <xsl:with-param name="offset" select="number(0)" />
                <xsl:with-param name="directives" select="$directives" />
                <xsl:with-param name="modules" select="$modules" />
            </xsl:call-template>
            </table>
        </div>&lf; <!-- /#directive-ref -->

        <xsl:call-template name="bottom"/>&lf;
    </body>
</html>
</xsl:template>
<!-- /quickreference -->


<!-- ==================================================================== -->
<!-- the working horse. builds rows of all directives starting with one   -->
<!-- letter when done, it calls itself to catch the next letter           -->
<!-- ==================================================================== -->
<xsl:template name="reference-of-letter">
<xsl:param name="letters-todo" />
<xsl:param name="offset" />
<xsl:param name="directives" />
<xsl:param name="modules" />

<xsl:variable name="letter" select="substring($letters-todo, 1, 1)" />

<xsl:for-each
    select="$directives[$letter=translate(substring(normalize-space(name), 1,1),
                                          $lowercase,$uppercase)]">
<xsl:sort select="name" />

    <xsl:choose>
    <xsl:when test="$modules[name=current()/../name]
                    /directivesynopsis[name=current()/name]">
        <xsl:call-template name="reference-of-letter-loop">
            <xsl:with-param name="letter" select="$letter" />
            <xsl:with-param name="directive"
                select="$modules[name=current()/../name]
                        /directivesynopsis[name=current()/name]" />
            <xsl:with-param name="offset" select="$offset" />
            <xsl:with-param name="position" select="position()" />
        </xsl:call-template>
    </xsl:when>
    <xsl:otherwise>
        <xsl:call-template name="reference-of-letter-loop">
            <xsl:with-param name="letter" select="$letter" />
            <xsl:with-param name="directive" select="." />
            <xsl:with-param name="offset" select="$offset" />
            <xsl:with-param name="position" select="position()" />
        </xsl:call-template>
    </xsl:otherwise>
    </xsl:choose>

</xsl:for-each> <!-- /directives -->

<!-- call next letter, if there is -->
<xsl:if test="string-length($letters-todo) &gt; 1">
    <xsl:call-template name="reference-of-letter">
        <xsl:with-param name="letters-todo"
            select="substring($letters-todo, 2)" />
        <xsl:with-param name="offset"
            select="(count($directives[$letter=translate(substring(
                        normalize-space(name), 1, 1),
                        $lowercase, $uppercase)])
                    + $offset) mod 2" />
        <xsl:with-param name="directives" select="$directives" />
        <xsl:with-param name="modules" select="$modules" />
    </xsl:call-template>
</xsl:if>
</xsl:template>
<!-- /reference-of-letter -->


<xsl:template name="reference-of-letter-loop">
<xsl:param name="directive" />
<xsl:param name="letter" />
<xsl:param name="offset" />
<xsl:param name="position" />

    <tr>
        <xsl:if test="$position mod 2 = $offset">
            <xsl:attribute name="class">odd</xsl:attribute>
        </xsl:if>

        <td>
            <a href="{$directive/../name}.html#{
                        translate($directive/name, $uppercase, $lowercase)}">
                <xsl:if test="$position = 1">
                    <xsl:attribute name="id">
                        <xsl:value-of select="$letter" />
                    </xsl:attribute>
                    <xsl:attribute name="name">
                        <xsl:value-of select="$letter" />
                    </xsl:attribute>
                </xsl:if>

                <xsl:apply-templates select="$directive/syntax" />
            </a>
        </td>
        <td>
            <!-- if the default value contains (at least) one <br />, -->
            <!-- this probably means that a short explanation follows -->
            <!-- the actual default value. We cut off the string      -->
            <!-- after the <br /> so it will not be shown here.       -->
            <!-- (add the + character instead)                        -->
            <xsl:variable name="default">
                <xsl:choose>
                <xsl:when test="count($directive/default[count(br) &gt; 0])
                                &gt; 0">
                    <xsl:value-of
                        select="$directive/default/child::node()
                                [count(preceding-sibling::*) = 0]" />
                </xsl:when>
                <xsl:otherwise>
                    <xsl:value-of select="$directive/default"/>
                </xsl:otherwise>
                </xsl:choose>
            </xsl:variable>

            <xsl:value-of select="substring(substring-after(concat($default,
                                  ' '), name),1,20)" />
            <xsl:if test="string-length(substring-after(concat($default, ' '),
                              name)) &gt; 20
                          or count($directive/default[count(br) &gt; 0])
                             &gt; 0">
                <xsl:text> +</xsl:text>
            </xsl:if>
        </td>
        <td>
            <xsl:if test="$directive/contextlist/context
                          [normalize-space(.)='server config']">
                <xsl:value-of select="$message[@id='serverconfig']/@letter"/>
            </xsl:if>
            <xsl:if test="$directive/contextlist/context
                          [normalize-space(.)='virtual host']">
                <xsl:value-of select="$message[@id='virtualhost']/@letter"/>
            </xsl:if>
            <xsl:if test="$directive/contextlist/context
                          [normalize-space(.)='directory']">
                <xsl:value-of select="$message[@id='directory']/@letter"/>
            </xsl:if>
            <xsl:if test="$directive/contextlist/context
                          [normalize-space(.)='.htaccess']">
                <xsl:value-of select="$message[@id='htaccess']/@letter"/>
            </xsl:if>
        </td>
        <td>
            <xsl:choose>
            <xsl:when test="$directive/../status='External'">
                <xsl:choose>
                <xsl:when test="$directive/../status/@href">
                    <a href="{$directive/../status/@href}">
                        <xsl:value-of
                            select="$message[@id='external']/@letter"/>
                    </a>
                </xsl:when>
                <xsl:otherwise>
                    <xsl:value-of select="$message[@id='external']/@letter"/>
                </xsl:otherwise>
                </xsl:choose>
            </xsl:when>
            <xsl:otherwise>
                <xsl:variable name="status" select="translate(
                    $directive/../status, $uppercase, $lowercase)"/>
                <xsl:value-of select="$message[@id=$status]/@letter"/>
            </xsl:otherwise>
            </xsl:choose>
        </td>
    </tr>
    <tr>
        <xsl:if test="$position mod 2 = $offset">
            <xsl:attribute name="class">odd</xsl:attribute>
        </xsl:if>

        <td colspan="4" class="descr">
            <xsl:choose>
            <xsl:when test="string-length(normalize-space(
                                $directive/description)) &gt; 0">
                <xsl:apply-templates select="$directive/description" />
            </xsl:when>
            <xsl:otherwise>
                <xsl:text>-</xsl:text>
            </xsl:otherwise>
            </xsl:choose>
        </td>
    </tr>&lf;
</xsl:template>

</xsl:stylesheet>
