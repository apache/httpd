<?xml version="1.0"?>
<!DOCTYPE xsl:stylesheet [ <!ENTITY nbsp "&#160;"> ]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/1999/xhtml">

  <!--                              -->
  <!-- Builds the moduleindex page  -->
  <!--                              -->
  <xsl:template match="moduleindex">
    <html xml:lang="{$messages/@lang}" lang="{$messages/@lang}">
      <xsl:call-template name="head"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

      <body id="module-index">
        <xsl:call-template name="top"/>  

        <div id="page-content">
        <div id="preamble">
          <h1>
            <xsl:value-of select="title"/>
          </h1>
          
<xsl:text>
</xsl:text> <!-- insert line break -->

          <xsl:apply-templates select="summary" />
        </div>
        <!-- /preamble -->

<xsl:text>
</xsl:text> <!-- insert line break -->

        <div id="quickview">
          <ul id="toc">

<xsl:text>
</xsl:text> <!-- insert line break -->

            <li>
              <img src="{$path}/images/down.gif" alt="" />
              <xsl:text> </xsl:text>
              <a href="#core">
                <xsl:value-of select="$messages/message[@name='corefeatures']"/>
              </a>
            </li>

            <li>
              <img src="{$path}/images/down.gif" alt="" />
              <xsl:text> </xsl:text>
              <a href="#other">
                <xsl:value-of select="$messages/message[@name='othermodules']"/>
              </a>
            </li>
          </ul>

          <xsl:if test="seealso">
            <h3>
              <xsl:value-of select="$messages/message[@name='seealso']"/>
            </h3>
            
<xsl:text>
</xsl:text> <!-- insert line break -->

            <ul class="seealso">

<xsl:text>
</xsl:text> <!-- insert line break -->

              <xsl:for-each select="seealso">
                <li>
                  <xsl:apply-templates/>
                </li>

<xsl:text>
</xsl:text> <!-- insert line break -->

              </xsl:for-each>
            </ul>
          </xsl:if>
        </div> <!-- /quickview -->

<xsl:text>
</xsl:text> <!-- insert line break -->

        <xsl:call-template name="toplink"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

        <div class="section">
          <h2>
            <a name="core" id="core">
              <xsl:value-of select="$messages/message[@name='corefeatures']"/>
            </a>
          </h2>

<xsl:text>
</xsl:text> <!-- insert line break -->

          <!--                                -->
          <!-- put core and mpm_common on top -->
          <!--                                -->
          <dl>

<xsl:text>
</xsl:text> <!-- insert line break -->

            <dt>
              <a href="{document(modulefilelist/modulefile[starts-with(.,'core.xml')])/modulesynopsis/name}.html">
                <xsl:value-of select="document(modulefilelist/modulefile[starts-with(.,'core.xml')])/modulesynopsis/name"/>
              </a>
            </dt>
            <dd>
              <xsl:apply-templates select="document(modulefilelist/modulefile[starts-with(.,'core.xml')])/modulesynopsis/description"/>
            </dd>

<xsl:text>
</xsl:text> <!-- insert line break -->

            <dt>
              <a href="{document(modulefilelist/modulefile[starts-with(.,'mpm_common.xml')])/modulesynopsis/name}.html">
                <xsl:value-of select="document(modulefilelist/modulefile[starts-with(.,'mpm_common.xml')])/modulesynopsis/name"/>
              </a>
            </dt>
            <dd class="separate">
              <xsl:apply-templates select="document(modulefilelist/modulefile[starts-with(.,'mpm_common.xml')])/modulesynopsis/description"/>
            </dd>
          <!-- /core, mpm_common -->

<xsl:text>
</xsl:text> <!-- insert line break -->

            <xsl:variable name="mpmmodules" select="document(modulefilelist/modulefile)/modulesynopsis[status='MPM' and name != 'mpm_common']"/>
            <xsl:variable name="translist">
              <xsl:call-template name="module-translist">
                <xsl:with-param name="modules" select="$mpmmodules"/>
              </xsl:call-template>
            </xsl:variable>

            <xsl:for-each select="$mpmmodules">
            <xsl:sort select="substring-before(substring-after($translist, concat('- ', translate(normalize-space(name),$lowercase,$uppercase), ' ')), ' -')"/>

              <dt>
                <a href="{name}.html">
                  <xsl:value-of select="name"/>
                </a>
              </dt>
              <dd>
                <xsl:apply-templates select="description"/>
              </dd>

<xsl:text>
</xsl:text> <!-- insert line break -->

            </xsl:for-each>
            <!-- /mpm -->
          </dl>
        </div>
        <!-- /core section -->

<xsl:text>
</xsl:text> <!-- insert line break -->

        <xsl:call-template name="toplink"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

        <div class="section">
          <h2>
            <a name="other" id="other">
              <xsl:value-of select="$messages/message[@name='othermodules']"/>
            </a>
          </h2>
            
<xsl:text>
</xsl:text> <!-- insert line break -->

          <xsl:variable name="modules" select="document(modulefilelist/modulefile)/modulesynopsis[status!='MPM' and status!='Core' and status!='Obsolete']"/>

          <!-- collect the start letters -->
          <xsl:variable name="start-letters">
            <xsl:call-template name="module-startletters">
              <xsl:with-param name="modules" select="$modules"/>
            </xsl:call-template>
          </xsl:variable>

          <!-- letter line -->
          <p class="letters">
            <xsl:call-template name="letter-bar">
              <xsl:with-param name="letters" select="$start-letters"/>
              <xsl:with-param name="first" select="true()"/>
            </xsl:call-template>
          </p>
          <!-- /letter line -->

<xsl:text>
</xsl:text> <!-- insert line break -->

          <dl>
            <xsl:call-template name="mindex-of-letter">
              <xsl:with-param name="letters-todo" select="$start-letters"/>
              <xsl:with-param name="modules" select="$modules"/>
            </xsl:call-template>
          </dl>
        </div>
        <!-- /modules section -->
        
        </div>
        <!-- /page-content -->

<xsl:text>
</xsl:text> <!-- insert line break -->

        <xsl:call-template name="bottom"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

      </body>
    </html>
  </xsl:template> 
  <!-- /moduleindex -->


  <!--                                                     -->
  <!-- the working horse. builds list items of all         -->
  <!-- modules starting with one letter                    -->
  <!-- when done, it calls itself to catch the next letter -->
  <!--                                                     -->
  <xsl:template name="mindex-of-letter">
  <xsl:param name="letters-todo"/>
  <xsl:param name="modules"/>

    <xsl:variable name="letter" select="substring($letters-todo,1,1)"/>
    <xsl:variable name="translist">
      <xsl:call-template name="module-translist">
        <xsl:with-param name="modules" select="$modules"/>
      </xsl:call-template>
    </xsl:variable>

    <xsl:for-each select="$modules[$letter=substring(substring-before(substring-after($translist, concat('- ', translate(normalize-space(name),$lowercase,$uppercase), ' ')), ' -'), 1, 1)]">
    <xsl:sort select="substring-before(substring-after($translist, concat('- ', translate(normalize-space(name),$lowercase,$uppercase), ' ')), ' -')"/>

      <dt>
        <a href="{name}.html">
          <xsl:if test="position()=1">
            <xsl:attribute name="id"><xsl:value-of select="$letter"/></xsl:attribute>
            <xsl:attribute name="name"><xsl:value-of select="$letter"/></xsl:attribute>
          </xsl:if>

          <xsl:value-of select="name"/>
        </a>
      </dt>
      <dd>
        <xsl:apply-templates select="description"/>
      </dd>

<xsl:text>
</xsl:text> <!-- insert a line break -->

    </xsl:for-each> <!-- /directives -->

    <!-- call next letter, if there is -->
    <xsl:if test="string-length($letters-todo) &gt; 1">
      <xsl:call-template name="mindex-of-letter">
        <xsl:with-param name="letters-todo" select="substring($letters-todo,2)"/>
        <xsl:with-param name="modules" select="$modules"/>
      </xsl:call-template>
    </xsl:if>

  </xsl:template>
  <!-- /mindex-of-letter -->


  <!--                                                    -->
  <!-- collect start letters of modules                   -->
  <!--                                                    -->
  <xsl:template name="module-startletters">
  <xsl:param name="modules"/>

    <xsl:variable name="translist">
      <xsl:call-template name="module-translist">
        <xsl:with-param name="modules" select="$modules"/>
      </xsl:call-template>
    </xsl:variable>

    <xsl:call-template name="_squeeze-letters">
      <xsl:with-param name="lastletter" select="''"/>

      <xsl:with-param name="letters">
        <xsl:for-each select="$modules">
        <xsl:sort select="substring-before(substring-after($translist, concat('- ', translate(normalize-space(name),$lowercase,$uppercase), ' ')), ' -')"/>
          <xsl:value-of select="substring(substring-before(substring-after($translist, concat('- ', translate(normalize-space(name),$lowercase,$uppercase), ' ')), ' -'), 1, 1)"/>
        </xsl:for-each>
      </xsl:with-param>
    </xsl:call-template>

  </xsl:template>
  <!-- /module-startletters -->


  <!--                                                     -->
  <!-- define module name translations for sorting         -->
  <!--                                                     -->
  <!-- it's a kind of a hack...                            -->
  <!-- we build a string that contains the following data: -->
  <!-- "- modulename sortname - modulename sortname - ..." -->
  <!-- (with all data in uppercase)                        -->
  <!--                                                     -->
  <!-- So, the translation from modulename to sortname     -->
  <!-- can be done with the expression below:              -->
  <!--
       substring-before(
           substring-after($translist, 
                           concat('- ',
                                  translate(modulename,
                                            $lowercase,
                                            $uppercase),
                                  ' ')
                           ),
           ' -')
                                                           -->
  <!--                                                     -->
  <xsl:template name="module-translist">
  <xsl:param name="modules"/>

    <xsl:text>-</xsl:text>
    <xsl:for-each select="$modules">
      <xsl:variable name="sname" select="translate(normalize-space(name),$lowercase,$uppercase)"/>

      <xsl:text> </xsl:text>
      <xsl:value-of select="$sname"/>
      <xsl:text> </xsl:text>
      <xsl:call-template name="module-translatename">
        <xsl:with-param name="name" select="$sname"/>
      </xsl:call-template>
      <xsl:text> -</xsl:text>
    </xsl:for-each>

  </xsl:template>
  <!-- /module-translist -->

  </xsl:stylesheet>
