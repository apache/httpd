<?xml version="1.0" encoding="ISO-8859-1"?>
<!-- English revision: 1.1 -->
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output 
  method="text"
  encoding="EUC-KR"
  indent="no"
/>

<!-- Read the localized messages from the specified language file -->
<xsl:variable name="messages" select="document('../lang/ko.xml')/messages"/>

<!-- some meta information have to be passed to the transformation -->
<xsl:variable name="output-encoding" select="'EUC-KR'" />
<xsl:variable name="toc-font" select="'Gulim,9,129'" /> <!-- MS magic ... -->
<xsl:variable name="xml-ext" select="'.xml.ko'" />

<!-- Now get the real guts of the stylesheet -->
<xsl:include href="hhc.xsl"/>

</xsl:stylesheet>

