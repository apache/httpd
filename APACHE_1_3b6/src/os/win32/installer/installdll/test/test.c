/*
 * Tester for the Apache Install DLL
 */

#include <windows.h>

#include "test.h"

#define APPNAME "Test"

HINSTANCE hInst;      // current instance
char szAppName[100];  // Name of the app
char szTitle[100];    // The title bar text

extern CHAR WINAPI BeforeExit(HWND, LPSTR,LPSTR,LPSTR,LPSTR);

BOOL InitApplication(HINSTANCE);
BOOL InitInstance(HINSTANCE, int);
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK About(HWND, UINT, WPARAM, LPARAM);

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
   MSG msg;
   HANDLE hAccelTable;

   lstrcpy (szAppName, APPNAME);
   lstrcpy (szTitle, APPNAME);

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
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0,
      NULL, NULL, hInstance, NULL);

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

	    case IDM_BEFOREEXIT:
		BeforeExit(hWnd, "C:\\", "C:\\", "C:\\Apache", NULL);
		break;

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

