#include <windows.h>
#include <stdio.h>

void showMines();

void __stdcall (*StartGame)();
void __stdcall (*FLocalButton)(int);
void __stdcall (*DrawButton)(HDC, int);
int  __stdcall (*DrawBorder)(HDC, int, int, int, int, int, char);
void __stdcall (*DisplayBombCount)();
void __stdcall (*DisplayGrid)();

HWND *hwndMain;
int *dxWindow;

unsigned char *minefield;
int *mineCount;

void __stdcall ButtonHook(HDC hdc, int button)
{
	int center = ((*dxWindow - 0x18) >> 1) - 1;

	DrawBorder(hdc, center - 0x0C, 0x0F, center + 0x19 + 0x0C, 0x28, 1, 2);
	DrawBorder(hdc, center + 0x0C, 0x0F, center + 0x19 + 0x0C, 0x28, 1, 2);
	*dxWindow += 0x18;
	DrawButton(hdc, 3);
	*dxWindow -= 0x18;
	*dxWindow -= 0x18;
	DrawButton(hdc, button);
	*dxWindow += 0x18;
}

void __stdcall ClickHook(int click)
{
	RECT button1;
	button1.left = ((*dxWindow - 23) >> 1) - 0x0C;
	button1.right = button1.left + 0x18;
	button1.top = 0x10;
	button1.bottom = 0x28;

	RECT button2;
	button2.left = ((*dxWindow - 23) >> 1) + 0x0C;
	button2.right = button2.left + 0x18;
	button2.top = 0x10;
	button2.bottom = 0x28;

	POINT p;
	p.x = click & 0xFFFF,
	p.y = click >> 0x10;

	if(PtInRect(&button1, p))
		StartGame();
	else if(PtInRect(&button2, p))
		showMines();
	else
		FLocalButton(click);
}

void showMines()
{
	for(int i = 0;i < 0x300;i++)
	{
		if(minefield[i] == 0x8F)
		{
			minefield[i] = 0x8E;
			(*mineCount)--;
			DisplayBombCount();
			DisplayGrid();
		}

		else if(*((unsigned int *) (minefield + i)) == 0x10101010)
			break;
	}
	DisplayGrid();
}

void patch()
{
	HANDLE base = GetModuleHandle(NULL);
	HANDLE process = GetCurrentProcess();

	StartGame = base + 0x367A;
	FLocalButton = base + 0x140C;
	DrawButton = base + 0x28D9;
	DrawBorder = base + 0x2971;
	DisplayBombCount = base + 0x2801;
	DisplayGrid = base + 0x272E;

	hwndMain = base + 0x5B24;
	dxWindow = base + 0x5B2C;

	minefield = base + 0x5360;
	mineCount = base + 0x5194;

	// ingame FLocalButton() call
	int *call_address = base + 0x1FB1 + 1; // the 4 bytes after E8
	int call_patch = (int) &ClickHook - (int) (call_address + 1);
	WriteProcessMemory(process, call_address, &call_patch, 4, 0);

	// StartGame()s DrawButton() call
	call_address = base + 0x2ADB + 1;
	call_patch = (int) &ButtonHook - (int) (call_address + 1);
	WriteProcessMemory(process, call_address, &call_patch, 4, 0);

	// ingame DrawButton() call
	call_address = base + 0x2927 + 1;
	call_patch = (int) &ButtonHook - (int) (call_address + 1);
	WriteProcessMemory(process, call_address, &call_patch, 4, 0);

	ButtonHook(GetDC(*hwndMain), 0);
}

INT APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved)
{
	if(Reason == DLL_PROCESS_ATTACH)
		patch();

	return 1;
}