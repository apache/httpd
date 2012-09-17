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
<!-- <directiveindex>                                                     -->
<!-- Builds the directive index page                                      -->
<!-- ==================================================================== -->
<xsl:template match="directiveindex">
<html xml:lang="{$doclang}" lang="{$doclang}">
    <xsl:call-template name="head"/>&lf;

    <body id="directive-index">
        <xsl:call-template name="top"/>

        <xsl:variable name="directives"
            select="document(
                        document(document(document(
                            $allmodules)/modulefilelist/modulefile
                        )/*/@metafile)
                        /metafile/@reference
                    )
                    /modulesynopsis[status!='Obsolete']
                    /directivesynopsis[not(@location)]" />

        <!-- collect the start letters -->
        <xsl:variable name="start-letters">
            <xsl:call-template name="directive-startletters">
                <xsl:with-param name="directives" select="$directives" />
            </xsl:call-template>
        </xsl:variable>

        <div id="preamble">
            <h1>
                <xsl:value-of select="title" />
            </h1>&lf;

            <xsl:call-template name="langavail" />&lf;

            <xsl:apply-templates select="summary" />&lf;

            <!-- letter bar -->
            <p class="letters">
                <xsl:call-template name="letter-bar">
                    <xsl:with-param name="letters" select="$start-letters" />
                    <xsl:with-param name="first" select="true()" />
                </xsl:call-template>
            </p>&lf; <!-- /.letters -->
        </div>&lf; <!-- /preamble -->

        <div id="directive-list">
            <ul>&lf;
                <xsl:call-template name="dindex-of-letter">
                    <xsl:with-param name="letters-todo"
                        select="$start-letters" />
                    <xsl:with-param name="directives" select="$directives" />
                </xsl:call-template>
            </ul>
        </div>&lf; <!-- /#directive-list -->

        <xsl:call-template name="bottom" />&lf;
    </body>
</html>
</xsl:template>
<!-- /directiveindex -->


<!-- ==================================================================== -->
<!-- the working horse. builds list items of all directives starting with -->
<!-- one letter when done, it calls itself to catch the next letter       -->
<!-- ==================================================================== -->
<xsl:template name="dindex-of-letter">
<xsl:param name="letters-todo" />
<xsl:param name="directives" />

<xsl:variable name="letter" select="substring($letters-todo, 1, 1)"/>

<xsl:for-each
    select="$directives
                [$letter = translate(substring(normalize-space(name), 1, 1),
                                     $lowercase, $uppercase)]">
<xsl:sort select="name" />
    <li>
        <a href="{../name}.html#{translate(name, $uppercase, $lowercase)}">
            <xsl:if test="position() = 1">
                <xsl:attribute name="id">
                    <xsl:value-of select="$letter" />
                </xsl:attribute>
                <xsl:attribute name="name">
                    <xsl:value-of select="$letter" />
                </xsl:attribute>
            </xsl:if>

            <xsl:if test="@type = 'section'">&lt;</xsl:if>
            <xsl:value-of select="name" />
            <xsl:if test="@type = 'section'">&gt;</xsl:if>
        </a>
    </li>&lf;
</xsl:for-each>

<!-- call next letter, if there is -->
<xsl:if test="string-length($letters-todo) &gt; 1">
    <xsl:call-template name="dindex-of-letter">
        <xsl:with-param name="letters-todo"
            select="substring($letters-todo, 2)" />
        <xsl:with-param name="directives" select="$directives" />
    </xsl:call-template>
</xsl:if>

</xsl:template>
<!-- /dindex-of-letter -->

</xsl:stylesheet>
