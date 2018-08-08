// TaintedEIP.cpp : 콘솔 응용 프로그램에 대한 진입점을 정의합니다.
//

#include "stdafx.h"
#include <Windows.h>


char g_buf[256];
int _tmain(int argc, _TCHAR* argv[])
{
	void (*buf)();
	char fsb_buf[2560];
	unsigned short size;
	FILE *fp;
	char *s;
	int c;
	s = (char*) malloc(1);
	HANDLE h = CreateFile(L"a.txt", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	ReadFile(h, g_buf, sizeof(buf), (LPDWORD)&size, 0);
	memcpy(&s, g_buf, 2);
	ReadFile(h, (char*)&c, sizeof(c) - 2, (LPDWORD)&size, 0);
	for(int i = 0; i < 100; i++)
		s[c + i] = 1;

	return 0;
}

