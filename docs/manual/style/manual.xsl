<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE xsl:stylesheet [ <!ENTITY nbsp "&#160;"> ]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/TR/xhtml1/strict">

<!-- Include constants, variables, and macros -->
<xsl:import href="settings.xsl" />

<xsl:output method="html" encoding="iso-8859-1" indent="no"/>

<xsl:template match="directiveindex">
<html>
<head><title><xsl:value-of select="title"/> - Apache HTTP Server</title>
<link rel="stylesheet" type="text/css" href="../style/manual.css" />
</head>
<body>
  <blockquote>
   <div align="center">
    <img src="../images/sub.gif" alt="[APACHE DOCUMENTATION]" /> 
    <h3>Apache HTTP Server Version 2.0</h3>
   </div>
   <h1 align="center"><xsl:value-of select="title"/></h1>
<xsl:apply-templates select="summary" />
<ul>
<xsl:for-each select="document(modulelist/modulefile)/modulesynopsis/directivesynopsis">
<xsl:sort select="name"/>
<li><a href="{/modulesynopsis/name}.html#{name}"><xsl:value-of select="name"/></a></li>
</xsl:for-each>
</ul>
</blockquote>
</body>
</html>
</xsl:template>

 <!-- Process an entire document into an HTML page -->
 <xsl:template match="modulesynopsis">
<html>
 <head>
<xsl:comment>
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
     This file is generated from xml source: DO NOT EDIT
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
</xsl:comment>
  <xsl:apply-templates select="meta"/>
  <title><xsl:value-of select="name"/> - Apache HTTP Server</title>
  <link rel="stylesheet" type="text/css" href="../style/manual.css" />
 </head>
 <body>
  <blockquote>
   <div align="center">
    <img src="../images/sub.gif" alt="[APACHE DOCUMENTATION]" /> 
    <h3>Apache HTTP Server Version 2.0</h3>
   </div>
   <h1 align="center"><xsl:value-of select="$messages/message[@name='apachemodule']"/><xsl:text> </xsl:text> <xsl:value-of select="name"/></h1>
   <!-- Description and module-headers -->
   <table bgcolor="#cccccc" cellpadding="0" cellspacing="1"><tr><td>
    <table bgcolor="#ffffff">
     <tr><td valign="top"><span class="help"><xsl:value-of select="$messages/message[@name='description']"/>:</span> </td>
         <td><xsl:apply-templates select="description"/></td></tr>
     <tr><td><a class="help" href="module-dict.html#Status"><xsl:value-of select="$messages/message[@name='status']"/>:</a> </td>
         <td><xsl:value-of select="status"/></td></tr>
  <xsl:if test="identifier">
     <tr><td><a class="help" href="module-dict.html#ModuleIdentifier"><xsl:value-of select="$messages/message[@name='moduleidentifier']"/>:</a> </td>
         <td><xsl:value-of select="identifier"/></td></tr>
  </xsl:if>
  <xsl:if test="compatibility">
     <tr><td valign="top" align="left"><a class="help" href="module-dict.html#Compatibility"
       ><xsl:value-of select="$messages/message[@name='compatibility']"/>:</a> </td>
         <td><xsl:apply-templates select="compatibility"/></td>
     </tr>
    </xsl:if>
   </table>
 </td></tr></table>

<!-- Summary of module features/usage (1 to 3 paragraphs, optional) -->

<xsl:if test="summary">
  <h2>Summary</h2>
  <xsl:apply-templates select="summary"/>
</xsl:if>

<xsl:if test="seealso">
 <p><strong><xsl:value-of select="$messages/message[@name='seealso']"/></strong></p>
 <ul>
  <xsl:for-each select="seealso">
   <li><xsl:apply-templates/></li>
  </xsl:for-each>
 </ul>
</xsl:if>

<!-- Index of directives, automatically generated from
     directivesynopsis/name -->

<h2>Directives</h2>

<xsl:if test="directivesynopsis">
  <ul>
     <xsl:for-each select="directivesynopsis">
       <xsl:sort select="name"/>
       <xsl:variable name="name">
         <xsl:value-of select="name"/>
       </xsl:variable>
       <xsl:variable name="lowername" 
         select="translate($name, $uppercase, $lowercase)" />
       <xsl:if test="not(@location)">
         <li><a href="#{$lowername}"><xsl:value-of select="name"/></a></li>
       </xsl:if>
       <xsl:if test="./@location">
         <xsl:variable name="location">
           <xsl:value-of select="./@location"/>
         </xsl:variable>
         <xsl:variable name="lowerlocation" 
           select="translate($location, $uppercase, $lowercase)" />
         <li><a href="{$lowerlocation}.html#{$lowername}"><xsl:value-of select="name"/></a></li>
       </xsl:if>
     </xsl:for-each>
  </ul>
</xsl:if>
<xsl:if test="not(directivesynopsis)">
  <p>This module provides no directives.</p>
</xsl:if>

<!-- Sections of documentation about the module as a whole -->

<xsl:apply-templates select="section"/>

<hr />

<!-- Directive documentation -->

<xsl:apply-templates select="directivesynopsis">
  <xsl:sort select="name"/>
</xsl:apply-templates> 

<!-- Page footer -->

<h3 align="center">Apache HTTP Server Version 2.0</h3>
<a href="./"><img src="../images/index.gif" alt="Index" /></a>
<a href="../"><img src="../images/home.gif" alt="Home" /></a>

</blockquote>
</body>
</html>
</xsl:template> <!-- /modulesynopsis -->


<!-- Subsections: get a lower level heading -->
  <xsl:template match="section/section">
   <xsl:variable name="href">
      <xsl:value-of select="@id"/>
    </xsl:variable>
      <!-- Section heading -->
    <xsl:if test="@id">
      <h3><a name="{$href}"><xsl:apply-templates select="./title" mode="print"/></a></h3>
    </xsl:if>
    <xsl:if test="not(@id)">
      <h3><xsl:apply-templates select="./title" mode="print"/></h3>
    </xsl:if>
      <!-- Section body -->
        <xsl:apply-templates/>
  </xsl:template>

<!-- Process a documentation section -->
  <xsl:template match="section">
    <xsl:variable name="href">
      <xsl:value-of select="@id"/>
    </xsl:variable>
      <!-- Section heading -->
    <xsl:if test="@id">
      <h2><a name="{$href}"><xsl:apply-templates select="./title" mode="print"/></a></h2>
    </xsl:if>
    <xsl:if test="not(@id)">
      <h2><xsl:apply-templates select="./title" mode="print"/></h2>
    </xsl:if>
      <!-- Section body -->
        <xsl:apply-templates/>
  </xsl:template>

  <xsl:template match="section/title" mode="print">
    <xsl:apply-templates/>
  </xsl:template>

  <!-- Don't print the title twice -->
  <xsl:template match="section/title"></xsl:template>

  <xsl:template match="directivesynopsis">

  <xsl:if test="not(@location)">
  <xsl:variable name="name">
    <xsl:value-of select="./name"/>
  </xsl:variable>
  <xsl:variable name="lowername" 
     select="translate($name, $uppercase, $lowercase)" />
  <!-- Directive heading gets both mixed case and lowercase anchors,
       and includes lt/gt only for "section" directives -->
  <h2><a name="{$name}"><xsl:if test="./@type='section'">&lt;</xsl:if
      ><xsl:value-of select="./name"/><xsl:if test="./@type='section'"
      >&gt;</xsl:if></a><xsl:text> </xsl:text><a 
      name="{$lowername}">Directive</a></h2>

<!-- Directive header -->
<table bgcolor="#cccccc" border="0" cellspacing="0" cellpadding="1">
<tr><td>
<table bgcolor="#ffffff">
  <tr><td><strong><xsl:value-of select="$messages/message[@name='description']"/>: </strong></td>
    <td><xsl:value-of select="description"/></td></tr>
  <tr><td><a class="help" href="directive-dict.html#Syntax"><xsl:value-of select="$messages/message[@name='syntax']"/>:</a> </td>
    <td><xsl:apply-templates select="syntax"/></td></tr>
  <xsl:if test="default">
    <tr><td><a class="help" href="directive-dict.html#Default"
      ><xsl:value-of select="$messages/message[@name='default']"/>:</a> </td>
      <td><code><xsl:value-of select="default"/></code></td></tr>
  </xsl:if>
  <tr><td><a class="help" href="directive-dict.html#Context"><xsl:value-of select="$messages/message[@name='context']"/>:</a> </td>
    <td><xsl:apply-templates select="contextlist"/></td></tr>
  <xsl:if test="override">
    <tr><td><a class="help" href="directive-dict.html#Override"
    ><xsl:value-of select="$messages/message[@name='override']"/>:</a> </td>
    <td><xsl:value-of select="override"/></td></tr>
  </xsl:if>
  <tr><td><a class="help" href="directive-dict.html#Status"><xsl:value-of select="$messages/message[@name='status']"/>:</a> </td>
    <td><xsl:value-of select="/modulesynopsis/status"/></td></tr>
  <tr><td><a class="help" href="directive-dict.html#Module"><xsl:value-of select="$messages/message[@name='module']"/>:</a> </td>
    <td>
    <xsl:if test="modulelist"><xsl:apply-templates select="modulelist"/>
      </xsl:if>
    <xsl:if test="not(modulelist)">
      <xsl:value-of select="/modulesynopsis/name"/>
    </xsl:if>
    </td></tr>
  <xsl:if test="compatibility">
    <tr><td valign="top" align="left"><a class="help" href="directive-dict.html#Compatibility"
      ><xsl:value-of select="$messages/message[@name='compatibility']"/>:</a> </td>
      <td><xsl:value-of select="compatibility"/></td></tr>
  </xsl:if>
</table>
</td></tr></table>

<xsl:apply-templates select="usage"/>
<xsl:if test="seealso">
  <p><strong><xsl:value-of select="$messages/message[@name='seealso']"/></strong></p>
  <ul>
    <xsl:for-each select="seealso">
      <li><xsl:apply-templates/></li>
    </xsl:for-each>
  </ul>
</xsl:if>

<hr />
</xsl:if> <!-- not(@location) -->
</xsl:template> <!-- /directivesynopsis -->

  <xsl:template match="contextlist">
    <xsl:apply-templates select="context"/>
  </xsl:template>

  <xsl:template match="context">
    <xsl:value-of select="." />
    <xsl:if test="not(position()=last())">, </xsl:if>
  </xsl:template>

  <xsl:template match="modulelist">
    <xsl:apply-templates select="module"/>
  </xsl:template>

  <xsl:template match="example">
  <blockquote>
  <table cellpadding="10"><tr><td bgcolor="#eeeeee">
     <xsl:apply-templates select="title" mode="print"/>
     <code><xsl:apply-templates/></code>
  </td></tr></table>
  </blockquote>
  </xsl:template>

  <xsl:template match="example/title" mode="print">
     <p align="center"><strong><xsl:apply-templates/></strong></p>
  </xsl:template>
  <xsl:template match="example/title"></xsl:template>

  <xsl:template match="note">
  <blockquote>
  <table><tr><td>
   <xsl:choose>
    <xsl:when test="@type='warning'">
     <xsl:attribute name="bgcolor">#ffe5f5</xsl:attribute>
    </xsl:when>
    <xsl:otherwise>
     <xsl:attribute name="bgcolor">#e0e5f5</xsl:attribute>
    </xsl:otherwise>
   </xsl:choose>
     <xsl:apply-templates/>
  </td></tr></table>
  </blockquote>
  </xsl:template>
  <xsl:template match="note/title">
     <p align="center"><strong><xsl:apply-templates/></strong></p>
  </xsl:template>

  <xsl:template match="directive">
    <xsl:if test="@module">
      <xsl:variable name="module">
        <xsl:value-of select="./@module"/>
      </xsl:variable>
      <xsl:variable name="directive">
        <xsl:value-of select="."/>
      </xsl:variable>
      <xsl:variable name="lowerdirective" select="translate($directive, $uppercase, $lowercase)" />
      <xsl:if test="@module=/modulesynopsis/name">
        <a class="directive" href="#{$lowerdirective}"><code class="directive"><xsl:if test="./@type='section'">&lt;</xsl:if><xsl:value-of select="."/><xsl:if test="./@type='section'">&gt;</xsl:if></code></a>
      </xsl:if>
      <xsl:if test="@module!=/modulesynopsis/name">
        <a class="directive" href="{$module}.html#{$lowerdirective}"><code class="directive"><xsl:if test="./@type='section'">&lt;</xsl:if><xsl:value-of select="."/><xsl:if test="./@type='section'">&gt;</xsl:if></code></a>
      </xsl:if>
    </xsl:if>
    <xsl:if test="not(@module)">
       <code class="directive"><xsl:if test="./@type='section'">&lt;</xsl:if><xsl:value-of select="."/><xsl:if test="./@type='section'">&gt;</xsl:if></code>
    </xsl:if>
  </xsl:template>

  <xsl:template match="module">
    <code><a href="{.}.html"><xsl:value-of select="."/></a></code><xsl:if test="parent::modulelist"><xsl:if test="not(position()=last())">, </xsl:if>
    </xsl:if>
  </xsl:template>

  <!-- Process everything else by just passing it through -->
  <xsl:template match="*|@*">
    <xsl:copy>
      <xsl:apply-templates select="@*|*|text()"/>
    </xsl:copy>
  </xsl:template>

</xsl:stylesheet>
