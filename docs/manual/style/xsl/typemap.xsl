<?xml version="1.0"?>

<!--
 Copyright 2003-2004 The Apache Software Foundation

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

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
                  xmlns="">

<xsl:output 
  method="text"
  encoding="utf-8"
  indent="no"
/>

<!-- create nodeset for referencing later                                 -->
<xsl:variable name="design" select="document('')/xsl:stylesheet
                                    /xsl:template[@name='designations']/item" />

<!-- Constants used for case translation -->
<xsl:variable name="lowercase" select="'abcdefghijklmnopqrstuvwxyz'" />
<xsl:variable name="uppercase" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'" />

<!-- ==================================================================== -->
<!-- <metafile>                                                           -->
<!-- build typemap                                                        -->
<!-- ==================================================================== -->
<xsl:template match="/metafile">
<xsl:apply-templates select="variants/variant" />
</xsl:template>
<!-- /metafile -->

<!-- ==================================================================== -->
<!-- <variant>                                                            -->
<!-- ==================================================================== -->
<xsl:template match="variant">
<xsl:variable name="lang" select="translate(., $uppercase, $lowercase)" />
<xsl:if test="not($design[translate(@lang, $uppercase, $lowercase) = $lang])">
    <xsl:message terminate="yes">
FATAL: missing designation data for language <xsl:value-of select="." />.
The XSLT-Stylesheet won't work without modification.
    </xsl:message>
</xsl:if>

<xsl:text>URI: </xsl:text>
<xsl:value-of select="/metafile/basename" />
<xsl:text>.html</xsl:text>
<xsl:value-of select="$design[translate(@lang, $uppercase, $lowercase)
                              = $lang]" />&lf;

<xsl:text>Content-Language: </xsl:text>
<xsl:value-of select="$design[translate(@lang, $uppercase, $lowercase)
                              = $lang]/@lang" />&lf;

<xsl:text>Content-type: text/html; charset=</xsl:text>
<xsl:value-of select="$design[translate(@lang, $uppercase, $lowercase)
                              = $lang]/@charset" />&lf;

<xsl:if test="position() != last()">&lf;</xsl:if>
</xsl:template>
<!-- /variant -->

<!-- ==================================================================== -->
<!-- do NOT call this template, it's referenced automagically via         -->
<!-- document() function and acts as simple data container.               -->
<!-- ==================================================================== -->
<xsl:template name="designations">
<item lang="de"    charset="ISO-8859-1" >.de</item>
<item lang="en"    charset="ISO-8859-1" >.en</item>
<item lang="es"    charset="ISO-8859-1" >.es</item>
<item lang="fr"    charset="ISO-8859-1" >.fr</item>
<item lang="ja"    charset="ISO-2022-JP">.ja.jis</item>
<item lang="ko"    charset="EUC-KR"     >.ko.euc-kr</item>
<item lang="ru"    charset="KOI8-R"     >.ru.koi8-r</item>
<item lang="zh-CN" charset="GB2312"     >.zh-cn.gb2312</item>
</xsl:template>

</xsl:stylesheet>
