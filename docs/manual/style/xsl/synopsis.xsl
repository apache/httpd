<?xml version="1.0"?>
<!DOCTYPE xsl:stylesheet [ <!ENTITY nbsp "&#160;"> ]>
<xsl:stylesheet version="1.0"
              xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                  xmlns="http://www.w3.org/1999/xhtml">

  <!--                                                    -->
  <!-- <modulesynopsis>                                   -->
  <!-- Process an entire document into an HTML page       -->
  <!--                                                    -->
  <xsl:template match="modulesynopsis">
    <html xml:lang="{$messages/@lang}" lang="{$messages/@lang}">
      <xsl:call-template name="head"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

      <body>

<xsl:text>
</xsl:text> <!-- insert line break -->

        <xsl:call-template name="top"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

        <div id="page-content">

<xsl:text>
</xsl:text> <!-- insert line break -->

          <div id="preamble">
            <h1>
              <xsl:choose>
                <xsl:when test="status='Core'">
                  <xsl:value-of select="$messages/message[@name='apachecore']"/>
                </xsl:when>

                <xsl:when test="name='mpm_common'">
                  <xsl:value-of select="$messages/message[@name='apachempmcommon']"/>
                </xsl:when>

                <xsl:when test="status='MPM'">
                  <xsl:value-of select="$messages/message[@name='apachempm']"/>
                  <xsl:text> </xsl:text>
                  <xsl:call-template name="module-translatename">
                    <xsl:with-param name="name" select="name" />
                  </xsl:call-template>
                </xsl:when>

                <xsl:otherwise>
                  <xsl:if test="status='Obsolete'">
                    <xsl:value-of select="$messages/message[@name='obsoleteapachemodule']"/>
                  </xsl:if>
                  <xsl:if test="status!='Obsolete'">
                    <xsl:value-of select="$messages/message[@name='apachemodule']"/>
                  </xsl:if>
                  <xsl:text> </xsl:text>
                  <xsl:value-of select="name"/>
                </xsl:otherwise>
              </xsl:choose>
            </h1>

<xsl:text>
</xsl:text> <!-- insert line break -->

            <!-- Description and module-headers -->
            <table class="module">
              <tr>
                <th>
                  <a href="module-dict.html#Description">
                    <xsl:value-of select="$messages/message[@name='description']"/>
                    <xsl:text>:</xsl:text>
                  </a>
                </th>
                <td>
                  <xsl:apply-templates select="description"/>
                </td>
              </tr>

<xsl:text>
</xsl:text> <!-- insert line break -->

              <tr>
                <th>
                  <a href="module-dict.html#Status">
                    <xsl:value-of select="$messages/message[@name='status']"/>
                    <xsl:text>:</xsl:text>
                  </a>
                </th>
                <td>
                  <xsl:value-of select="status"/>

                  <xsl:if test="hint">
                    <em>
                      <xsl:text> (</xsl:text>
                      <xsl:apply-templates select="hint"/>
                      <xsl:text>)</xsl:text>
                    </em>
                    <br />
                  </xsl:if>
                </td>
              </tr>

              <xsl:if test="identifier">

<xsl:text>
</xsl:text> <!-- insert line break -->

              <tr>
                <th>
                  <a href="module-dict.html#ModuleIdentifier">
                    <xsl:value-of select="$messages/message[@name='moduleidentifier']"/>
                    <xsl:text>:</xsl:text>
                  </a>
                </th>
                <td>
                  <xsl:value-of select="identifier"/>
                </td>
              </tr>
              </xsl:if>

              <xsl:if test="sourcefile">

<xsl:text>
</xsl:text> <!-- insert line break -->

              <tr>
                <th>
                  <a href="module-dict.html#SourceFile">
                    <xsl:value-of select="$messages/message[@name='sourcefile']"/>
                    <xsl:text>:</xsl:text>
                  </a>
                </th>
                <td>
                  <xsl:value-of select="sourcefile"/>
                </td>
              </tr>
              </xsl:if>

              <xsl:if test="compatibility">

<xsl:text>
</xsl:text> <!-- insert line break -->

              <tr>
                <th>
                  <a href="module-dict.html#Compatibility">
                    <xsl:value-of select="$messages/message[@name='compatibility']"/>
                    <xsl:text>:</xsl:text>
                  </a>
                </th>
                <td>
                  <xsl:apply-templates select="compatibility"/>
                </td>
              </tr>
              </xsl:if>
            </table>

<xsl:text>
</xsl:text> <!-- insert line break -->

            <!-- Summary of module features/usage (1 to 3 paragraphs, optional) -->
            <xsl:if test="summary">
              <h3>
                <xsl:value-of select="$messages/message[@name='summary']"/>
              </h3>

<xsl:text>
</xsl:text> <!-- insert line break -->

              <xsl:apply-templates select="summary"/>
            </xsl:if>
          </div> <!-- /preamble -->

<xsl:text>
</xsl:text> <!-- insert line break -->

          <div id="quickview">

            <!-- Index of directives, automatically generated from
                 directivesynopsis/name -->
            <h3 class="directives">
              <xsl:value-of select="$messages/message[@name='directives']"/>
            </h3>

<xsl:text>
</xsl:text> <!-- insert line break -->

            <xsl:if test="directivesynopsis">
              <ul id="toc">

<xsl:text>
</xsl:text> <!-- insert line break -->

                <xsl:for-each select="directivesynopsis">
                  <xsl:sort select="name"/>
                  <xsl:variable name="lowername" select="translate(name, $uppercase, $lowercase)"/>

                  <xsl:if test="not(@location)">
                    <li>
                      <img src="{$path}/images/down.gif" alt="" />
                      <xsl:text> </xsl:text>
                      <a href="#{$lowername}">
                        <xsl:if test="@type='section'">&lt;</xsl:if>
                        <xsl:value-of select="name"/>
                        <xsl:if test="@type='section'">&gt;</xsl:if>
                      </a>
                    </li>

<xsl:text>
</xsl:text> <!-- insert linebreak -->

                  </xsl:if>

                  <xsl:if test="@location">
                    <xsl:variable name="lowerlocation" select="translate(@location, $uppercase, $lowercase)"/>

                    <li>
                      <img src="{$path}/images/right.gif" alt="" />
                      <xsl:text> </xsl:text>
                      <a href="{$lowerlocation}.html#{$lowername}">
                        <xsl:if test="@type='section'">&lt;</xsl:if>
                        <xsl:value-of select="name"/>
                        <xsl:if test="@type='section'">&gt;</xsl:if>
                      </a>
                    </li>

<xsl:text>
</xsl:text> <!-- insert linebreak -->

                  </xsl:if>
                </xsl:for-each>
              </ul> <!-- /toc -->

<xsl:text>
</xsl:text> <!-- insert line break -->

            </xsl:if>

            <xsl:if test="not(directivesynopsis)">
              <p>
                <xsl:value-of select="$messages/message[@name='nodirectives']"/>
              </p>

<xsl:text>
</xsl:text> <!-- insert line break -->

            </xsl:if>

            <xsl:if test="section">
              <h3>
                <xsl:value-of select="$messages/message[@name='topics']"/>
              </h3>

<xsl:text>
</xsl:text> <!-- insert line break -->

              <ul id="topics">

<xsl:text>
</xsl:text> <!-- insert line break -->

                <xsl:apply-templates select="section" mode="index"/>
              </ul>
            </xsl:if>

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

          <!-- Sections of documentation about the module as a whole -->
          <xsl:apply-templates select="section"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

          <!-- Directive documentation -->
          <xsl:apply-templates select="directivesynopsis">
            <xsl:sort select="name"/>
          </xsl:apply-templates>

        </div> <!-- /page-content -->

<xsl:text>
</xsl:text> <!-- insert line break -->

        <xsl:call-template name="bottom"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

      </body>
    </html>
  </xsl:template>
  <!-- /modulesynopsis -->


  <!--                                                            -->
  <!--    modulesynopsis/compatibility                            -->
  <!--                                                            -->
  <xsl:template match="modulesynopsis/compatibility">
    <xsl:apply-templates />
  </xsl:template>


  <!--                                                            -->
  <!--    Directivesynopsis                                       -->
  <!--                                                            -->
  <xsl:template match="directivesynopsis">
    <xsl:if test="not(@location)">

      <xsl:call-template name="toplink"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

      <div class="directive-section">
        <xsl:variable name="lowername" select="translate(name, $uppercase, $lowercase)"/>

        <!-- Directive heading gets both mixed case and lowercase anchors,
             and includes lt/gt only for "section" directives -->
        <h2>
          <a id="{name}" name="{name}">
            <xsl:if test="@type='section'">&lt;</xsl:if>
            <xsl:value-of select="name"/>
            <xsl:if test="@type='section'">&gt;</xsl:if>
          </a>
          <xsl:choose>
            <xsl:when test="$messages/message[@name='directive']/@replace-space-with">
              <xsl:value-of select="$messages/message[@name='directive']/@replace-space-with"/>
            </xsl:when>
            <xsl:otherwise>
              <xsl:text> </xsl:text>
            </xsl:otherwise>
          </xsl:choose>
          <a id="{$lowername}" name="{$lowername}">
            <xsl:value-of select="$messages/message[@name='directive']"/>
          </a>
        </h2>

<xsl:text>
</xsl:text> <!-- insert line break -->

        <!-- Directive header -->
        <table class="directive">

<xsl:text>
</xsl:text> <!-- insert line break -->

          <tr>
            <th>
              <a href="directive-dict.html#Description">
                <xsl:value-of select="$messages/message[@name='description']"/>
                <xsl:text>:</xsl:text>
              </a>
            </th>
            <td>
              <xsl:value-of select="description"/>
            </td>
          </tr>

<xsl:text>
</xsl:text> <!-- insert line break -->

          <tr>
            <th>
              <a href="directive-dict.html#Syntax">
                <xsl:value-of select="$messages/message[@name='syntax']"/>
                <xsl:text>:</xsl:text>
              </a>
            </th>
            <td>
              <code>
                <xsl:apply-templates select="syntax"/>
              </code>
            </td>
          </tr>

          <xsl:if test="default">

<xsl:text>
</xsl:text> <!-- insert line break -->

          <tr>
            <th>
              <a href="directive-dict.html#Default">
                <xsl:value-of select="$messages/message[@name='default']"/>
                <xsl:text>:</xsl:text>
              </a>
            </th>
            <td>
              <code>
                <xsl:apply-templates select="default"/>
              </code>
            </td>
          </tr>
          </xsl:if>

<xsl:text>
</xsl:text> <!-- insert line break -->

          <tr>
            <th>
              <a href="directive-dict.html#Context">
                <xsl:value-of select="$messages/message[@name='context']"/>
                <xsl:text>:</xsl:text>
              </a>
            </th>
            <td>
              <xsl:apply-templates select="contextlist"/>
            </td>
          </tr>

          <xsl:if test="override">

<xsl:text>
</xsl:text> <!-- insert line break -->

          <tr>
            <th>
              <a href="directive-dict.html#Override">
                <xsl:value-of select="$messages/message[@name='override']"/>
                <xsl:text>:</xsl:text>
              </a>
            </th>
            <td>
              <xsl:value-of select="override"/>
            </td>
          </tr>
          </xsl:if>

<xsl:text>
</xsl:text> <!-- insert line break -->

          <tr>
            <th>
              <a href="directive-dict.html#Status">
                <xsl:value-of select="$messages/message[@name='status']"/>
                <xsl:text>:</xsl:text>
              </a>
            </th>
            <td>
              <xsl:value-of select="../status"/>
            </td>
          </tr>

<xsl:text>
</xsl:text> <!-- insert line break -->

          <tr>
            <th>
              <a href="directive-dict.html#Module">
                <xsl:value-of select="$messages/message[@name='module']"/>
                <xsl:text>:</xsl:text>
              </a>
            </th>
            <td>
              <xsl:if test="modulelist">
                <xsl:apply-templates select="modulelist"/>
              </xsl:if>

              <xsl:if test="not(modulelist)">
                <xsl:value-of select="../name"/>
              </xsl:if>
            </td>
          </tr>

          <xsl:if test="compatibility">

<xsl:text>
</xsl:text> <!-- insert line break -->

          <tr>
            <th>
              <a href="directive-dict.html#Compatibility">
                <xsl:value-of select="$messages/message[@name='compatibility']"/>
                <xsl:text>:</xsl:text>
              </a>
            </th>
            <td>
              <xsl:apply-templates select="compatibility"/>
            </td>
          </tr>
          </xsl:if>

<xsl:text>
</xsl:text> <!-- insert line break -->

        </table>

        <xsl:apply-templates select="usage"/>

<xsl:text>
</xsl:text> <!-- insert line break -->

        <xsl:if test="seealso">
          <h3>
            <xsl:value-of select="$messages/message[@name='seealso']"/>
          </h3>

<xsl:text>
</xsl:text> <!-- insert line break -->

          <ul>

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

<xsl:text>
</xsl:text> <!-- insert line break -->

        </xsl:if>

      </div> <!-- /directive-section -->

<xsl:text>
</xsl:text> <!-- insert line break -->

    </xsl:if>
  </xsl:template>
  <!-- /directivesynopsis -->


  <!--                                                    -->
  <!-- <contextlist>                                      -->
  <!-- Passes through content                             -->
  <!--                                                    -->
  <xsl:template match="contextlist">
    <xsl:apply-templates select="context"/>
  </xsl:template>
  <!-- /contextlist -->


  <!--                                                    -->
  <!-- <context>                                          -->
  <!-- Each entry is separeted with a comma               -->
  <!--                                                    -->
  <xsl:template match="context">
    <xsl:choose>
      <xsl:when test="normalize-space(.) = 'server config'">
        <xsl:value-of select="$messages/message[@name='serverconfig']"/>
      </xsl:when>
      <xsl:when test="normalize-space(.) = 'virtual host'">
        <xsl:value-of select="$messages/message[@name='virtualhost']"/>
      </xsl:when>
      <xsl:when test="normalize-space(.) = 'directory'">
        <xsl:value-of select="$messages/message[@name='directory']"/>
      </xsl:when>
      <xsl:when test="normalize-space(.) = '.htaccess'">
        <xsl:value-of select="$messages/message[@name='htaccess']"/>
      </xsl:when>

      <xsl:otherwise> <!-- error -->
        <xsl:message terminate="yes">
          unknown context: <xsl:value-of select="." />
        </xsl:message>
      </xsl:otherwise>
    </xsl:choose>

    <xsl:if test="position() != last()">
      <xsl:text>, </xsl:text>
    </xsl:if>
  </xsl:template>
  <!-- /context -->


  <!--                                                    -->
  <!-- <modulelist>                                       -->
  <!-- Passes through content                             -->
  <!--                                                    -->
  <xsl:template match="modulelist">
    <xsl:for-each select="module">
      <xsl:call-template name="module"/>
      <xsl:if test="position() != last()">
        <xsl:text>, </xsl:text>
      </xsl:if>
    </xsl:for-each>
  </xsl:template>
  <!-- /modulelist -->

</xsl:stylesheet>