##
## ssl_template.inc -- mod_ssl User Manual: The Heart
## Copyright (c) 1998-2001 Ralf S. Engelschall, All Rights Reserved. 
##

#use wml::std::page
#use wml::des::space
#use wml::des::rollover
#use wml::des::typography
#use wml::std::box

<page 
   title="mod_ssl: $(title)"
   bgcolor="#ffffff"
>
<head>\
<protect>
<!--
  Copyright (c) 1998-2001 Ralf S. Engelschall. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above
     copyright notice, this list of conditions and the following
     disclaimer. 
 
  2. Redistributions in binary form must reproduce the above
     copyright notice, this list of conditions and the following
     disclaimer in the documentation and/or other materials
     provided with the distribution.
 
  3. All advertising materials mentioning features or use of this
     software must display the following acknowledgment: 
     "This product includes software developed by 
      Ralf S. Engelschall <rse@engelschall.com> for use in the
      mod_ssl project (http://www.modssl.org/)."
 
  4. The name "mod_ssl" must not be used to endorse or promote
     products derived from this software without prior written
     permission.  

  5. Redistributions of any form whatsoever must retain the
     following acknowledgment:
     "This product includes software developed by 
      Ralf S. Engelschall <rse@engelschall.com> for use in the
      mod_ssl project (http://www.modssl.org/)."
 
  THIS SOFTWARE IS PROVIDED BY RALF S. ENGELSCHALL ``AS IS'' AND ANY
  EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
  PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL RALF S. ENGELSCHALL OR
  HIS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
  OF THE POSSIBILITY OF SUCH DAMAGE.
-->
</protect>\
<style type="text/css"><!--
A:link { 
    text-decoration: none; 
    color: #6666cc;
}
A:active {
    text-decoration: none; 
    color: #6666cc;
}
A:visited {
    text-decoration: none; 
    color: #6666cc;
}
\#sf {
    font-family: arial,helvetica;
    font-variant: normal;
    font-style: normal;
}
H1 {
    font-weight: bold;
    font-size: 24pt;
    line-height: 24pt;
    font-family: arial,helvetica;
    font-variant: normal;
    font-style: normal;
}
H2 {
    font-weight: bold;
    font-size: 18pt;
    line-height: 18pt;
    font-family: arial,helvetica;
    font-variant: normal;
    font-style: normal;
}
H3 {
    font-weight: bold;
    font-size: 14pt;
    line-height: 14pt;
    font-family: arial,helvetica;
    font-variant: normal;
    font-style: normal;
}
H4 {
    font-weight: bold;
    font-size: 12pt;
    line-height: 12pt;
    font-family: arial,helvetica;
    font-variant: normal;
    font-style: normal;
}
\#H {
# background-color: #e0e0e0;
}
\#D {
    background-color: #f0f0f0;
}
\#faq {
    font-weight: bold;
    font-size: 16pt;
    line-height: 16pt;
    font-family: arial,helvetica;
    font-variant: normal;
    font-style: normal;
}
\#howto {
    font-weight: bold;
    font-size: 16pt;
    line-height: 16pt;
    font-family: arial,helvetica;
    font-variant: normal;
    font-style: normal;
}
\#term {
    font-weight: bold;
    font-size: 16pt;
    line-height: 16pt;
    font-family: arial,helvetica;
    font-variant: normal;
    font-style: normal;
}
--></style>
</head>

<center>
<table width=600 cellspacing=0 cellpadding=0 border=0>
<tr>
  <td>
    <ifeq "$(tag)" "title" "" "
      <imgdot height=1 width=600><br>
      <table width=600 cellspacing=0 cellpadding=0>
      <tr>
        <td>

        <table width=600>
        <tr>
            <td align=left valign=bottom>
            <font face="Arial,Helvetica" size=+2><b>mod_ssl</b></font>
            </td>
            <td <ifeq "$(num)" "0" "align=left" "align=right">>
              <ifeq "$(num)" "0" "
                  <br>
                  <img src="ssl_template.title-$(tag).gif" alt="$(title)">
              " "
              <img src="ssl_template.head-chapter.gif"    alt="Chapter"> \
              <img src="ssl_template.head-num-$(num).gif" alt="$(num)">
              ">
            </td>
        </tr>
        </table>

        </td>
      </tr>
      <tr>
        <td>\
          <imgdot color="#000000" width=600 height=2>\
        </td>
      </tr>
      <tr>
        <td>
           <table width=600 border=0>
           <tr>
            <td valign=top align=left width=250>\
              {#NAVBUT_TOP_PREV#}
            </td>
            <td valign=top align=right width=250>\
              {#NAVBUT_TOP_NEXT#}
            </td>
           </tr>
           </table>
         </td>
      </tr>
      <tr>
        <td>
          <ifeq "$(num)" "0" "" "
          <br>
          <img src="ssl_template.title-$(tag).gif" alt="$(title)">
          ">
        </td>
      </tr>
      </table>
     ">
     {#BODY#}
    <ifeq "$(tag)" "title" "" "
      <p>
      <br>
      <table>
      <tr>
        <td>
           <table width=600 border=0>
           <tr>
            <td valign=top align=left width=250>\
              {#NAVBUT_BOT_PREV#}
            </td>
            <td valign=top align=right width=250>\
              {#NAVBUT_BOT_NEXT#}
            </td>
           </tr>
           </table>
         </td>
      </tr>
      <tr>
        <td>\
          <imgdot color="#000000" width=600 height=2>\
        </td>
      </tr>
      <tr>
        <td>\
        <table width=598>
        <tr>
        <td align=left>\
        <font face="Arial,Helvetica"> 
        <a href="http://www.modssl.org/">mod_ssl</a> 2.8, User Manual<br>
        The Apache Interface to OpenSSL
        </font>
        </td>
        <td align=right>\
        <font face="Arial,Helvetica"> 
        Copyright &copy; 1998-2001
        <a href="http://www.engelschall.com/">Ralf S. Engelschall</a><br>
        All Rights Reserved<br>
        </font>
        </td>
        </tr>
        </table>
        </td>
      </tr>
      </table>
      ">
  </td>
</tr>
</table>
</center>
{#BODY#:

<define-tag page_prev>
<preserve name>
<preserve url>
<set-var %attributes>
{#NAVBUT_TOP_PREV#:
<rollover
name="prev_top"
src="ssl_template.navbut-prev-n.gif"
oversrc="ssl_template.navbut-prev-s.gif" 
href="<get-var url>" alt="previous page"
><br><font color="#000000"><get-var name></font>
:##}
{#NAVBUT_BOT_PREV#:
<rollover
name="prev_bot"
src="ssl_template.navbut-prev-n.gif"
oversrc="ssl_template.navbut-prev-s.gif" 
href="<get-var url>" alt="previous page"
><br><font color="#000000"><get-var name></font>
:##}
<restore url>
<restore name>
</define-tag>

<define-tag page_next>
<preserve name>
<preserve url>
<set-var %attributes>
{#NAVBUT_TOP_NEXT#:
<rollover
name="next_top"
src="ssl_template.navbut-next-n.gif"
oversrc="ssl_template.navbut-next-s.gif" 
href="<get-var url>" alt="next page"
><br><font color="#000000"><get-var name></font>
:##}
{#NAVBUT_BOT_NEXT#:
<rollover
name="next_bot"
src="ssl_template.navbut-next-n.gif"
oversrc="ssl_template.navbut-next-s.gif" 
href="<get-var url>" alt="next page"
><br><font color="#000000"><get-var name></font>
:##}
<restore url>
<restore name>
</define-tag>

<define-tag float endtag=required>
<preserve name>
<preserve caption>
<set-var %attributes>
<center>
<a name="<get-var name>"></a>
<table width=600 cellspacing=0 cellpadding=1 border=0>
<caption align=bottom id="sf"><get-var caption></caption>
<tr><td bgcolor="#cccccc">
<table width=598 cellpadding=5 cellspacing=0 border=0>
<tr>\
<td valign=top align=center bgcolor="#ffffff">\
%body\
</td>
</tr></table>
</td></tr></table>
</center>
<restore caption>
<restore name>
</define-tag>

<define-tag directive>
<preserve name>
<preserve description>
<preserve syntax>
<preserve default>
<preserve context>
<preserve override>
<preserve compat>
<set-var %attributes>
<box bdcolor="#cccccc" bdwidth=1 bdspace=5 bgcolor=white width=600>
<table cellspacing=0 cellpadding=1 border=0>
<tr><td>
<font face="Arial,Helvetica"><b>Name:</b></font></a> </td><td> <b><get-var name></b></td></tr>
<tr><td>
<font face="Arial,Helvetica"><b>Description:</b></font></a> </td><td> <get-var description></td></tr>
<tr><td><a
 href="../directive-dict.html#Syntax"
 rel="Help"
><font face="Arial,Helvetica"><b>Syntax:</b></font></a> </td><td> <get-var syntax></td></tr>
<tr><td><a
 href="../directive-dict.html#Default"
 rel="Help"
><font face="Arial,Helvetica"><b>Default:</b></font></a> </td><td> <get-var default></td></tr>
<tr><td><a
 href="../directive-dict.html#Context"
 rel="Help"
><font face="Arial,Helvetica"><b>Context:</b></font></a> </td><td> <get-var context></td></tr>
<tr><td><a
 href="../directive-dict.html#Override"
 rel="Help"
><font face="Arial,Helvetica"><b>Override:</b></font></a> </td><td> <get-var override></td></tr>
<tr><td><a
 href="../directive-dict.html#Status"
 rel="Help"
><font face="Arial,Helvetica"><b>Status:</b></font></a> </td><td> Extension</td></tr>
<tr><td><a
 href="../directive-dict.html#Module"
 rel="Help"
><font face="Arial,Helvetica"><b>Module:</b></font></a> </td><td> mod_ssl</td></tr>
<tr><td><a
 href="../directive-dict.html#Compatibility"
 rel="Help"
><font face="Arial,Helvetica"><b>Compatibility:</b></font></a> </td><td> <get-var compat> </td></tr>
</table>
</box>
<restore compat>
<restore override>
<restore context>
<restore default>
<restore syntax>
<restore description>
<restore name>
</define-tag>

<define-tag quotation endtag=required>
<preserve width>
<preserve author>
<set-var %attributes>
<div align=right>
<table cellspacing=0 cellpadding=0 width=<get-var width>>
<tr>
<td>
<em>%body</em>
</td>
</tr>
<ifeq "<get-var author>" "" "" "
<tr>
<td align=right>
<font size=-1>
<get-var author>
</font>
</td>
</tr>
">
</table>
</div>
<restore author>
<restore width>
</define-tag>
