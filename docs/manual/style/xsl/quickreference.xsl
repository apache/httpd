<?xml version="1.0"?>
<!DOCTYPE xsl:stylesheet [ <!ENTITY nbsp "&#160;"> ]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/1999/xhtml">

  <!--                                                    -->
  <!-- <directiveindex>                                   -->
  <!-- Builds the directive index page                    -->
  <!--                                                    -->
  <xsl:template match="quickreference">
    <html xml:lang="{$messages/@lang}" lang="{$messages/@lang}">
      <xsl:call-template name="head"/>

      <body id="directive-index">
        <xsl:call-template name="top"/>

        <div id="preamble">
          <h1>
            <xsl:value-of select="title"/>
          </h1>

          <xsl:apply-templates select="summary" />


        </div>

        <div id="directive-list">
        <table class="qref">
        <tr><th><a href="directive-dict.html#Syntax"><xsl:value-of select="$messages/message[@name='syntax']"/></a></th>
           <th><a href="directive-dict.html#Default"><xsl:value-of select="$messages/message[@name='default']"/></a></th>
           <th></th><th></th></tr>
         <xsl:for-each select="document(/*/modulefilelist/modulefile)/modulesynopsis/directivesynopsis[not(@location)]">
         <xsl:sort select="name"/>


            <xsl:variable name="rowpos">
              <xsl:choose>
                <xsl:when test="position() mod 2 = 0">
                  even
                </xsl:when>
                <xsl:otherwise>
                  odd
                </xsl:otherwise>
              </xsl:choose>
           </xsl:variable>


             <tr class="{$rowpos}">
               <td>
                 <a style="text-decoration: none" 
                   href="{../name}.html#{translate(name,$uppercase,$lowercase)}">
                   <xsl:apply-templates select="syntax"/>
                 </a>
               </td>


               <td>
                 <xsl:value-of select="substring(substring-after(concat(default,' '),name),1,20)"/>
                 <xsl:if test="string-length(substring-after(concat(default,' '),name)) &gt; 20">
                   +
                 </xsl:if>
               </td>

               <td>
                 <xsl:choose>
                   <xsl:when test="../status='Base'">B</xsl:when>
                   <xsl:when test="../status='MPM'">M</xsl:when>
                   <xsl:when test="../status='Core'">C</xsl:when>
                   <xsl:when test="../status='Extension'">E</xsl:when>
                   <xsl:when test="../status='Experimental'">X</xsl:when>
                 </xsl:choose>
               </td>

              <td>
               <xsl:if test="contextlist/* = 'server config'">s</xsl:if>
               <xsl:if test="contextlist/* = 'virtual host'">v</xsl:if>
               <xsl:if test="contextlist/* = 'directory'">d</xsl:if>
               <xsl:if test="contextlist/* = '.htaccess'">h</xsl:if>
              </td>

           </tr>

           <tr class="{$rowpos}">
             <td>
               &nbsp;&nbsp;
               <xsl:apply-templates select="description"/>
             </td>
          </tr>            
          <xsl:text>
</xsl:text><!-- insert a line break -->
        </xsl:for-each>
        </table>
       </div>

        <xsl:call-template name="bottom"/>
      </body>
    </html>
  </xsl:template> 



</xsl:stylesheet>
