<?xml version="1.0"?>
<!DOCTYPE modulesynopsis SYSTEM "../style/modulesynopsis.dtd">
<?xml-stylesheet type="text/xsl" href="../style/manual.en.xsl"?>
<!-- English Revision: 106090:151405 (outdated) -->

<!--
 Copyright 2004 The Apache Software Foundation

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

<modulesynopsis metafile="leader.xml.meta">
<name>leader</name>
<description>Variante experimental del MPM est&#225;ndar
<module>worker</module></description>
<status>MPM</status>
<sourcefile>leader.c</sourcefile>
<identifier>mpm_leader_module</identifier>

<summary>
    <note type="warning"><title>Warning</title>
      <p>Este m&#243;dulo es todav&#237;a experimental, lo que
      significa que podr&#237;a no funcionar como es debido.</p>
    </note>
    
    <p>Este m&#243;dulo es una variante experimental del m&#243;dulo
    de multiprocesamiento est&#225;ndar <module>worker</module>. Usa
    un patr&#243;n de dise&#241;o Leader/Followers para coordinar el
    trabajo entre las hebras. Para m&#225;s informaci&#243;n, consulte
    <a href="http://deuce.doc.wustl.edu/doc/pspdfs/lf.pdf"
    >http://deuce.doc.wustl.edu/doc/pspdfs/lf.pdf</a>.</p>

    <p>Para usar el MPM <module>leader</module>, a&#241;ada
      <code>--with-mpm=leader</code> como argumento al script
      <code>configure</code> en el momento de compilar
      <code>httpd</code>.</p>
  
    <p>Este m&#243;dulo de multiprocesamiento depende de operaciones
    at&#243;micas compare-and-swap del APR para sicronizar las
    hebras. Si est&#225; compilando el servidor para una m&#225;quina
    x86 y no necesita soportar la arquitectura 386, o est&#225;
    compilando para una m&#225;quina SPARC y no necesita ejecutar el
    servidor en chips pre-UltraSPARC, a&#241;ada
    <code>--enable-nonportable-atomics=yes</code> como argumento al
    script <code>configure</code>. Esto har&#225; que APR implemente
    las operaciones at&#243;micas usando opciones m&#225;s eficientes
    que no est&#225;n presentes en CPUs antiguas.</p>
</summary>

<directivesynopsis location="mpm_common"><name>AcceptMutex</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>CoreDumpDirectory</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>EnableExceptionHook</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>Group</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>Listen</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ListenBacklog</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>SendBufferSize</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>LockFile</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxClients</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxMemFree</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxRequestsPerChild</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MaxSpareThreads</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>MinSpareThreads</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>PidFile</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ScoreBoardFile</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ServerLimit</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>StartServers</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ThreadLimit</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>ThreadsPerChild</name>
</directivesynopsis>
<directivesynopsis location="mpm_common"><name>User</name>
</directivesynopsis>

</modulesynopsis>




