<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output 
  method="text"
  encoding="SHIFT_JIS"
  indent="no"
/>

<!-- Read the localized messages from the specified language file -->
<xsl:variable name="messages" select="document('../lang/ja.xml')/messages"/>

<!-- some meta information have to be passed to the transformation -->
<xsl:variable name="hhp-lang" select="'0x411 Japanese'" /> <!-- MS magic ... -->

<!-- Now get the real guts of the stylesheet -->
<xsl:include href="hhp.xsl"/>

</xsl:stylesheet>

