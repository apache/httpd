<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output
  method="xml"
  encoding="KOI8-R"
  indent="no"
  doctype-public="-//W3C//DTD XHTML 1.0 Strict//EN"
  doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"
/>

<!-- Read the localized messages from the specified language file -->
<xsl:variable name="messages" select="document('lang/ru.xml')/messages"/>
<xsl:variable name="output-encoding" select="'KOI8-R'" />

<!-- Now get the real guts of the stylesheet -->
<xsl:include href="xsl/common.xsl"/>

</xsl:stylesheet>
