/*------------------------------------------------------------------
  These functions are to be called when the shared NLM starts and
  stops.  By using these functions instead of defining a main()
  and calling ExitThread(TSR_THREAD, 0), the load time of the
  shared NLM is faster and memory size reduced.
   
  You may also want to override these in your own Apache module
  to do any cleanup other than the mechanism Apache modules
  provide.
------------------------------------------------------------------*/
#include <netware.h>
//#include "stddef.h"
#include "novsock2.h"

int _NonAppStart
(
    void        *NLMHandle,
    void        *errorScreen,
    const char  *cmdLine,
    const char  *loadDirPath,
    size_t      uninitializedDataLength,
    void        *NLMFileHandle,
    int         (*readRoutineP)( int conn, void *fileHandle, size_t offset,
                    size_t nbytes, size_t *bytesRead, void *buffer ),
    size_t      customDataOffset,
    size_t      customDataSize,
    int         messageCount,
    const char  **messages
)
{
#pragma unused(cmdLine)
#pragma unused(loadDirPath)
#pragma unused(uninitializedDataLength)
#pragma unused(NLMFileHandle)
#pragma unused(readRoutineP)
#pragma unused(customDataOffset)
#pragma unused(customDataSize)
#pragma unused(messageCount)
#pragma unused(messages)

    WSADATA wsaData;
    
    return WSAStartup((WORD) MAKEWORD(2, 0), &wsaData);
}

void _NonAppStop( void )
{
    WSACleanup();
}

int  _NonAppCheckUnload( void )
{
	return 0;
}
