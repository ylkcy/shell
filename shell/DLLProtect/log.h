#ifndef _LOG_H
#define _LOG_H

#include <ctime>
#include <cstdarg>
#include <cstdio>
#include <cstring>

#define MAX_BUF_SIZE 4096

#ifndef ERRORCODE
#define ERRORCODE GetLastError()
#endif

#ifdef _DEBUG
	#define LOG(format, ...) do{writelog(format, ##__VA_ARGS__);} while (0)
#else
	#define LOG(format, ...)
#endif


void writelog(char* format, ...)
{
	char buf[MAX_BUF_SIZE] = "";
	time_t now;
	struct tm* _tm;
	time(&now);
	_tm = localtime(&now);
	strftime(buf, MAX_BUF_SIZE, "%Y-%m-%d %I:%M:%S ", _tm);
	va_list va;
	va_start(va, format);
	vsnprintf(buf + strlen(buf), MAX_BUF_SIZE - strlen(buf) - 1, format, va);
	va_end(va);
	buf[MAX_BUF_SIZE - 1] = '\0';
	FILE* fp = fopen("./log.log", "a+");
	if (fp == NULL)
	{
		return;
	}
	fwrite(buf, strlen(buf), 1, fp);
	fflush(fp);
	if (fp != NULL)
	{
		fclose(fp);
		fp = NULL;
	}
}

#endif