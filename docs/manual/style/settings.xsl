<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE xsl:stylesheet [ <!ENTITY nbsp "&#160;"> ]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/TR/xhtml1/strict">

 <!-- Constants used for case translation -->
 <xsl:variable name="lowercase" select="'abcdefghijklmnopqrstuvwxyz'" />
 <xsl:variable name="uppercase" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'" />

 <!-- Defined parameters (overrideable) -->
 <xsl:param name="relative-path" select="'.'"/>

 <!-- Macros, variables, and stuff for the localization -->

 <!-- English is the default language -->
 <xsl:variable name="language">
  <xsl:if test="modulesynopsis/language">
   <xsl:value-of select="modulesynopsis/language"/>
  </xsl:if>
  <xsl:if test="not(modulesynopsis/language)">en</xsl:if>
 </xsl:variable>

 <!-- Read the localized messages from the specified language file -->
 <xsl:variable name="messages" select="document(concat($language, '.xml'))/messages"/>

</xsl:stylesheet>

