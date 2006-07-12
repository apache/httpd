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
<!-- <manualpage>                                                         -->
<!-- Process an entire document into an HTML page                         -->
<!-- ==================================================================== -->
<xsl:template match="manualpage">
<html xml:lang="{$doclang}" lang="{$doclang}">
    <xsl:call-template name="head" />&lf;

    <body id="manual-page">
        <!-- unsqueeze if there's no sidebar -->
        <xsl:if test="not(count(section) > 1 or seealso)">
          <xsl:attribute name="class">no-sidebar</xsl:attribute>
        </xsl:if>

        <xsl:call-template name="top"/>          

        <div id="page-content">
            <div id="preamble">        
                <h1>
                    <xsl:value-of select="title"/>
                </h1>&lf;

                <xsl:call-template name="langavail" />&lf;

                <xsl:apply-templates select="summary" />
            </div>&lf; <!-- /#preamble -->
          
            <xsl:if test="(not($is-chm) and count(section) > 1) or seealso">
                <div id="quickview">
                    <xsl:if test="not($is-chm) and count(section) > 1">
                        <ul id="toc">
                        <xsl:apply-templates select="section" mode="index" />
                        </ul>
                    </xsl:if>

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
            </xsl:if>

            <xsl:apply-templates select="section" />
        </div>&lf; <!-- /#page-content -->

        <xsl:call-template name="bottom" />&lf;
    </body>
</html>
</xsl:template>
<!-- /manualpage -->

</xsl:stylesheet>
