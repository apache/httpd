/*
 * Tester for the Apache Install DLL
 */

#include <windows.h>
#include <direct.h>

#include "test.h"

#define APPNAME "Test"

HINSTANCE hInst;      // current instance
char szAppName[100];  // Name of the app
char szTitle[100];    // The title bar text

// This is imported from the Apache INSTALL.DLL
extern CHAR WINAPI BeforeExit(HWND, LPSTR,LPSTR,LPSTR,LPSTR);

BOOL InitApplication(HINSTANCE);
BOOL InitInstance(HINSTANCE, int);
BOOL CenterWindow (HWND hwndChild, HWND hwndParent);
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK About(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK SetDirectory(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

char szInstDir[MAX_PATH];

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
   MSG msg;
   HANDLE hAccelTable;

   lstrcpy (szAppName, APPNAME);
   lstrcpy (szTitle, APPNAME);

   getcwd(szInstDir, sizeof(szInstDir));

   if (!hPrevInstance) {
      if (!InitApplication(hInstance)) {
         return (FALSE);
      }
   }

   if (!InitInstance(hInstance, nCmdShow)) {
      return (FALSE);
   }

   hAccelTable = LoadAccelerators (hInstance, szAppName);

   while (GetMessage(&msg, NULL, 0, 0)) {
      if (!TranslateAccelerator (msg.hwnd, hAccelTable, &msg)) {
         TranslateMessage(&msg);
         DispatchMessage(&msg);
      }
   }

   return (msg.wParam);

   lpCmdLine; // This will prevent 'unused formal parameter' warnings
}

BOOL InitApplication(HINSTANCE hInstance)
{
    WNDCLASS  wc;
    HWND      hwnd;

    hwnd = FindWindow (szAppName, szTitle);

    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = (WNDPROC)WndProc;
    wc.cbClsExtra    = 0;
    wc.cbWndExtra    = 0;
    wc.hInstance     = hInstance;
    wc.hIcon         = LoadIcon (hInstance, MAKEINTRESOURCE(IDI_TEST));
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    wc.lpszMenuName  = MAKEINTRESOURCE(IDM_TEST);
    wc.lpszClassName = szAppName;

    return RegisterClass(&wc);
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   HWND hWnd;

   hInst = hInstance;

   hWnd = CreateWindow(szAppName, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT,	// x
      0,		// y
      400,		// width
      100, 		// height
      NULL,		// parent
      NULL,		// menu
      hInstance,	// instance handle
      NULL);

   if (!hWnd) {
      return (FALSE);
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return (TRUE);
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
   int wmId, wmEvent;

   switch (message) {

      case WM_COMMAND:
         wmId    = LOWORD(wParam);
         wmEvent = HIWORD(wParam);

         switch (wmId) {

            case IDM_ABOUT:
               DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUT), hWnd, (DLGPROC)About);
               break;

	    case IDM_CONFIGURE:
	    {
		int rc;

		if (DialogBox(hInst, MAKEINTRESOURCE(IDD_SETDIRECTORY), hWnd, (DLGPROC)SetDirectory) == FALSE)
		    break;
		rc = BeforeExit(hWnd, szInstDir, szInstDir, szInstDir, NULL);
		if (rc == 1) {
		    MessageBox(hWnd, "Configuration successful",
			"Configuration successful",
			MB_OK);
		}
		break;
	    }
            case IDM_EXIT:
               DestroyWindow (hWnd);
               break;

            default:
               return (DefWindowProc(hWnd, message, wParam, lParam));
         }
         break;

      case WM_DESTROY:
         PostQuitMessage(0);
         break;

      default:
         return (DefWindowProc(hWnd, message, wParam, lParam));
   }
   return (0);
}

LRESULT CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{

   switch (message) {
        case WM_INITDIALOG:
        CenterWindow (hDlg, GetWindow (hDlg, GW_OWNER));
         return (TRUE);

      case WM_COMMAND:
         if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, TRUE);
            return (TRUE);
         }
         break;
   }

    return FALSE;
}

LRESULT CALLBACK SetDirectory(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{

   switch (message) {
        case WM_INITDIALOG:
        CenterWindow (hDlg, GetWindow (hDlg, GW_OWNER));

	SetDlgItemText(hDlg, IDC_DIRECTORY, szInstDir);
	//SetFocus(GetDlgItem(hDlg, IDC_DIRECTORY));
        return (TRUE);

      case WM_COMMAND:
	  switch(LOWORD(wParam)) {
	  case IDCANCEL:
              EndDialog(hDlg, FALSE);
	      return TRUE;
	  case IDOK:
	      GetDlgItemText(hDlg, IDC_DIRECTORY, szInstDir, sizeof(szInstDir));
	      EndDialog(hDlg, TRUE);
	      return TRUE;
	  }
         break;
   }

    return FALSE;
}

//
//   FUNCTION: CenterWindow(HWND, HWND)
//
//   PURPOSE: Centers one window over another.
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
//       This functionwill center one window over another ensuring that
//    the placement of the window is within the 'working area', meaning
//    that it is both within the display limits of the screen, and not
//    obscured by the tray or other framing elements of the desktop.
BOOL CenterWindow (HWND hwndChild, HWND hwndParent)
{
   RECT    rChild, rParent, rWorkArea;
   int     wChild, hChild, wParent, hParent;
   int     xNew, yNew;
   BOOL  bResult;

   // Get the Height and Width of the child window
   GetWindowRect (hwndChild, &rChild);
   wChild = rChild.right - rChild.left;
   hChild = rChild.bottom - rChild.top;

   // Get the Height and Width of the parent window
   GetWindowRect (hwndParent, &rParent);
   wParent = rParent.right - rParent.left;
   hParent = rParent.bottom - rParent.top;

   // Get the limits of the 'workarea'
   bResult = SystemParametersInfo(
      SPI_GETWORKAREA,  // system parameter to query or set
      sizeof(RECT),
      &rWorkArea,
      0);
   if (!bResult) {
      rWorkArea.left = rWorkArea.top = 0;
      rWorkArea.right = GetSystemMetrics(SM_CXSCREEN);
      rWorkArea.bottom = GetSystemMetrics(SM_CYSCREEN);
   }

   // Calculate new X position, then adjust for workarea
   xNew = rParent.left + ((wParent - wChild) /2);
   if (xNew < rWorkArea.left) {
      xNew = rWorkArea.left;
   } else if ((xNew+wChild) > rWorkArea.right) {
      xNew = rWorkArea.right - wChild;
   }

   // Calculate new Y position, then adjust for workarea
   yNew = rParent.top  + ((hParent - hChild) /2);
   if (yNew < rWorkArea.top) {
      yNew = rWorkArea.top;
   } else if ((yNew+hChild) > rWorkArea.bottom) {
      yNew = rWorkArea.bottom - hChild;
   }

   // Set it, and return
   return SetWindowPos (hwndChild, NULL, xNew, yNew, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

