// Antitrojan.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h> 
#include <winsock2.h>
#include "iphlpapi.h"
#include <assert.h>
#include <psapi.h>
#include "global_structure.h"
#include "PORTLIST.H"
#include "Trojan.h"
#include "Antitrojan.h"

#pragma comment ( lib, "ws2_32.lib" ) 
#pragma comment ( lib, "Iphlpapi.lib" ) 
#pragma comment ( lib, "psapi.lib" )
#define MAXLINE 1024

/////global list to store open port////////////
CPortList g_OpenPortList;
/////global list to store infect trojan name///
CTrojanList g_InfectList;
/////global list to store trojan database//////
CTrojanList g_TroInfo;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////main funtion, start here, yeah/////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int main(int argc, char* argv[])
{
	TROJAN Ttest;
	unsigned short nCurPort;
	int nNumOfInfo;
	int i;//used in recursive
	int nNumOfInfect;
	Welcome();

	WORD wVersionRequested;
	WSADATA wsaData;
	int err;
	 
	wVersionRequested = MAKEWORD( 2, 2 );
	 
	err = WSAStartup( wVersionRequested, &wsaData );


	if(!GetOpenPort())
	{
		printf("Error with getting the open ports\n");
		return 0;
	}
	
	if(GetTrojanInfo())
	{
		nNumOfInfect = 0;
		nNumOfInfo = g_TroInfo.GetNum();
		printf("***Can find %d Trojans***\n", nNumOfInfo);
		while(g_OpenPortList.GetNum())
		{
			nCurPort = g_OpenPortList.Pop();
			for(i=0 ; i<nNumOfInfo; i++)
			{
				Ttest = g_TroInfo.GetN(i);
				if(nCurPort == Ttest.nPort)
				{
					printf("Port %hd open, may infect %s Trojan.\n", Ttest.nPort, Ttest.TroName);
					g_InfectList.Push(Ttest.nPort, Ttest.TroName, Ttest.nKillno);
					nNumOfInfect++;
				}
			}
		}
		if(nNumOfInfect)
		{
			printf("***May %d Trojan infected***\n", nNumOfInfect);
			while(g_InfectList.GetNum())
			{
				Ttest = g_InfectList.Pop();
				if(Ttest.nKillno)
					if(RemoveTrojan(Ttest.nKillno))
						printf("%s cleaned successfully\r\n", Ttest.TroName);
					else
						printf("fail in cleaning %s\r\n", Ttest.TroName);
			}
		}
		else
			printf("***Lucky, no Trojan found***\n");
	}

	WSACleanup();

	system("pause");

	return 0;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////Get open port in host mechine/////////////////////////////////////////////////////////////
//////////////////////////We call nestat and store the result in a temp file, then read them in turn////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool GetOpenPort()
{
	FILE *fp;
	WSADATA wsd;
	//IPAddr nRemoteAddr;
	HOSTENT* remoteHostent;
	char szMechineName[MAXLINE];
	char szfLine[MAXLINE];
	size_t stLineLen, stMNLen;
	char *pName;
	char *pPort;
	char szPort[6];
	unsigned short tempPort;
	system("netstat -a >c:\\log.txt");
	fp = fopen("c:\\log.txt","r");
	if(fp == NULL)
	{
		printf("Cannot get log file\n");
	//	return false;
	//}stError());
		fclose(fp);
		return false;
	}
	
	unsigned int nRemoteAddr;

	in_addr ina;
	ina.S_un.S_addr=inet_addr("127.0.0.1");

	//get host name in order to get each prefix(host name) before open port	
	//remoteHostent = gethostbyaddr( (char*)&nRemoteAddr,4, AF_INET ); 
	
	/*remoteHostent = gethostbyaddr( (char*)&ina.S_un.S_addr,4, AF_INET ); 
	
	if ( remoteHostent ) 
	{ 
		printf( "HostName  : %s\n",remoteHostent->h_name ); 
		memset(szMechineName,0,MAXLINE);
		strcpy(szMechineName,remoteHostent->h_name);
		stMNLen = strlen(szMechineName);
	}
	else  
	{
		printf( "gethostbyaddr Error:%d\n", GetLastError()); 
		fclose( fp );
		WSACleanup();
	    return false;
	}*/

	//this is for test
	//做试验的时候，请把“war”改为试验用机的名字
	//strcpy( szMechineName , "war" );
//	strcpy( szMechineName , "PC-201603151028" );
	strcpy( szMechineName , "0.0.0.0" );
	
	stMNLen = 3;

	while(1)
	{
		memset(szfLine,0,MAXLINE);
		stLineLen = fscanf(fp, "%s", szfLine);
		if(stLineLen == EOF)
			break;
		
		//printf("%s\n", szfLine);
		

		if((pName = strstr(szfLine, szMechineName)) != NULL)
		{

			for(int i=0;i<1024;i++)
				if(szfLine[i]==':')
				{
					pPort=szfLine+i+1;
					break;
				}
			//pPort = pName + stMNLen + 1;//because there is a ":" between MechineName and open port
			memset(szPort, 0, 6);
			strncpy(szPort, pPort, 5);
			if(isdigit(szPort[0]) == 0)
				continue;
			tempPort = atoi(szPort);
			if(tempPort != 0)
				g_OpenPortList.Push(tempPort);
		}


		//if((pName = strstr(szfLine, szMechineName)) != NULL)
		//{
		//	pPort = pName + stMNLen + 1;//because there is a ":" between MechineName and open port
		//	memset(szPort, 0, 6);
		//	strncpy(szPort, pPort, 5);
		//	if(isdigit(szPort[0]) == 0)
		//		continue;
		//	tempPort = atoi(szPort);
		//	if(tempPort != 0)
		//		g_OpenPortList.Push(tempPort);
		//}
	}
	fclose( fp );
	WSACleanup();
	if(g_OpenPortList.GetNum())
		return true;
	else 
		return false;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////Get Trojan database from the data file//////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool GetTrojanInfo()
{
	FILE *fp;
	char szTroName[MAXNAME];
	char szPort[7];
	unsigned short nPort;
	unsigned int nKillno;
	size_t tNameSize;
	fp = fopen("Trojan.txt","r");
	if(fp == NULL)
	{
		printf("Cannot get Trojan data file\n");
		return false;
	}
	while(1)
	{
		memset(szTroName, 0, MAXNAME);
		tNameSize = fscanf(fp, "%s", szTroName);
		if(tNameSize == EOF)
			break;
		tNameSize = fscanf(fp, "%s", szPort);
		if(tNameSize == EOF)
			break;
		nPort = atoi(szPort);
		tNameSize = fscanf(fp, "%s", szPort);
		if(tNameSize == EOF)
			break;
		nKillno = atoi(szPort);
		g_TroInfo.Push(nPort, szTroName, nKillno);
	}
	fclose( fp );
	if(g_TroInfo.GetNum())
		return true;
	else 
		return false;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////Kill the trojan process main function//////////////////////////////////////////////
/////////////////////after enhance privilege and enum the active processes, we take action, HOHO////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool ProcessVXER (char* szName)
{
	DWORD lpidProcess[1024],cbNeeded_1,cbNeeded_2;
	HANDLE hProc;
	HMODULE hMod[1024];
	char ProcFile[MAXLINE];
	bool returnvalue=false;
	int Pcount=0;
	int i;

	EnablePrivilege(SE_DEBUG_NAME); //提升权限

//枚举进程
	if (!(EnumProcesses(lpidProcess,sizeof(lpidProcess),&cbNeeded_1)))
	{
		printf("EnumProcesses() GetLastError reports %d\n",GetLastError());
		return 0;
	}

	for (i=0; i<(int)cbNeeded_1/4 ;i++)
	{
		//打开找到的第一个进程
		hProc=OpenProcess(PROCESS_ALL_ACCESS,FALSE,lpidProcess[i]);
		if (hProc)
		{
			//枚举进程模块
			if (EnumProcessModules(hProc,hMod,sizeof(hMod),&cbNeeded_2))	
			{
				//枚举进程模块文件名，包含全路径
				if (GetModuleFileNameEx(hProc,hMod[0],ProcFile,sizeof(ProcFile)))
				{
					//printf("%5d\t%s\n",lpidProcess[i],ProcFile); //输出进程
					//可以考虑将其注释掉，这样就不会输出进程列表了
					Pcount++;
					//查找进程中是否包含FileName
					if (strstr(ProcFile, szName) != 0)
					{
						//如果包含，则杀掉。KillProc为自定义的杀进程函数
						if (!(KillProc(lpidProcess[i])))
						{
							printf("KillProc() GetLastError reports %d\n",GetLastError());
							CloseHandle(hProc);
							exit(0);
						}
						else
							printf("Kill %s successfully.\n", szName); 
					}
				}
			}
		}//	if (hProc)
	}//for

	CloseHandle(hProc); //关闭进程句柄
	printf("\nProcess total:%d\n",Pcount); //打印进程各数
	returnvalue=false;
	return 0;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////enhance the privilage, used by process-killing function/////////////////////////////
////////////////////////////////////if we neglect this procedure, we may fail in manuveur/////////////////////////////// 
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool EnablePrivilege(PCHAR PrivilegeName)
{
	HANDLE hProc,hToken;
	TOKEN_PRIVILEGES TP; 
	hProc=GetCurrentProcess(); //打开进程的一个伪句柄

	if(!OpenProcessToken(hProc,TOKEN_ADJUST_PRIVILEGES,&hToken))
	{
		return false;
	}

	if(!LookupPrivilegeValue(NULL,PrivilegeName,&TP.Privileges[0].Luid))
	{
		CloseHandle(hToken);
		return false;
	}

	TP.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
	TP.PrivilegeCount=1;

	if(!AdjustTokenPrivileges(hToken,FALSE,&TP,sizeof(TP),0,0))
	{
		CloseHandle(hToken);
		return false;
	}

	CloseHandle(hToken);
	return true;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////kill the process by process ID, use after enum process if ID fit process name/////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool KillProc (DWORD ProcessID)
{
	HANDLE hProc;
	bool returnvalue=false;

	//打开由ProcessVXER传递的进程PID
	hProc=OpenProcess(PROCESS_ALL_ACCESS,FALSE,ProcessID);

	if (hProc)
	{
		//终止进程
		if (!(TerminateProcess(hProc,0)))
		{
			printf("TerminateProcess GetLastError reports %d\n", GetLastError());
			return returnvalue;
		}
	}
	CloseHandle(hProc);
	returnvalue=true;
	return returnvalue;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////Modify the self-start content of a file//////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool ModifyFile(char* szPath, char* szFileName, char* szSInfo, char* szDInfo)
{
	char* szPathName;
	FILE* openfp;
	FILE* savefp;
	char szLine[MAXLINE];
	char* pRet;
	bool bRet;
	szPathName = (char*)malloc((strlen(szPath)+strlen(szFileName)+2)*sizeof(char));
	strcpy(szPathName, szPath);
	strcat(szPathName, "\\");
	strcat(szPathName, szFileName);
	openfp = fopen(szPathName, "r");
	if(openfp == NULL)
	{
		printf("Cannot open %s\n", szPathName);
		return false;
	}
	savefp = fopen("temp001.tmp","w");
	if(savefp == NULL)
	{
		printf("Cannot modify %s\n", szPathName);
		fclose(openfp);
		return false;
	}
	while( fgets( szLine, MAXLINE-1, openfp ) != NULL)
    {
		pRet = strstr(szLine, szSInfo);
		if(pRet == NULL)
			fputs(szLine, savefp);
		else
		{
			strncpy(szLine, szDInfo, MAXLINE);
			strcat(szLine, "\r\n");
			szLine[MAXLINE-1] = NULL;
			fputs(szLine, savefp);
		}
	}
	fclose(openfp);
	fclose(savefp);
	if(DeleteFile(szPathName) == TRUE)
	{
		strcpy(szLine, "copy temp001.tmp ");
		strcat(szLine, szPathName);
		system(szLine);
		printf("%s modified\n", szPathName);
		bRet = true;
	}
	else
	{
		printf("Cannot modify %s\n", szPathName);
		bRet = false;
	}
	DeleteFile("temp001.tmp");
	free(szPathName);
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////To Remove Trojans//////////////////////////////////////////////////////////////////////////
/////////////////////////every kill funtion is called here, simply a switch structure////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool RemoveTrojan(int n)
{
	bool bRet;
	switch(n)
	{
	case 0:
		printf("Can not remove Trojan.\n");
		bRet = false;
		break;
	case 1:
		bRet = Kill_ATTACKFTP();
		break;
	case 2:
		bRet = Kill_BACKDOOR();
		break;
	case 3:
		bRet = Kill_BLADERUNNER();
		break;
	case 4:
		bRet = Kill_DEEPTHROAT();
		break;
	case 5:
		bRet = Kill_DOLY();
		break;
	case 6:
		bRet = Kill_GATECRASHER();
		break;
	case 7:
		bRet = Kill_GIRLFRIEND();
		break;
	case 8:
		bRet = Kill_HACK99KEYLOGGER();
		break;
	case 9:
		bRet = Kill_INIKILLER();
		break;
	case 10:
		bRet = Kill_MASTERPARADISE();
		break;
	case 11:
		bRet = Kill_NETSPHERE();
		break;
	case 12:
		bRet = Kill_NETSPY();
		break;
	case 13:
		bRet = Kill_MILLENIUM();
		break;
	case 14:
		bRet = Kill_PRIORITY();
		break;
	case 15:
		bRet = Kill_PROSIAK();
		break;
	case 16:
		bRet = Kill_RIPPER();
		break;
	case 17:
		bRet = Kill_SATANSBACKDOOR();
		break;
	case 18:
		bRet = Kill_TELECOMMANDO();
		break;
	case 19:
		bRet = Kill_TROJANCOW();
		break;
	case 20:
		bRet = Kill_WEBEX();
		break;
	case 21:
		bRet = Kill_WINCRASH();
		break;
	case 22:
		bRet = Kill_WINCRASHV2();
		break;
	case 23:
		bRet = Kill_SockListener();
		break;


	default:
		printf("Can not remove Trojan.\n");
		bRet = false;
		break;
	}
	return bRet;
}

bool Kill_SockListener()
{
	bool bRet = true;
	if(ProcessVXER("SockListener.exe"))
		bRet=false;
	
	long nRet;
	HKEY hd=HKEY_LOCAL_MACHINE;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run";

	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	
	unsigned char strv[255];
	DWORD dwType;
	DWORD vl=254;
	char szTrojanPath[256];
	char szWinPath[256];

	if(nRet == ERROR_SUCCESS)
	{		
		nRet = RegQueryValueEx(hd, "crossbow", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "Tapi32.exe"))
		{
			if(!ProcessVXER ((char*)strv))
			{
				printf("Tapi32.exe is not running.\n");
				//bRet = false;
			}
			GetWindowsDirectory(szWinPath, 256);
			strcpy(szTrojanPath, szWinPath);
			strcat(szTrojanPath, "\\System32\\Tapi32.exe");
			if(!DeleteFile(szTrojanPath))
				bRet = false;
			nRet = RegDeleteValue(hd, "crossbow");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		else
			bRet = false;
		RegCloseKey(hd);
	}

	return bRet;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///the functions below aim to kill a variety of trojans respectively/////////////////////////////////////////////////////////////
///kill trojan process, manipulate registry, modify files such as win.ini and delete the trojan file are included in operations//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////// 

/////////////////////////////////////////////No1 kill attackftp//////////////////////////////////////////////////////////////////
bool Kill_ATTACKFTP()
{
	bool bRet = true;
	HKEY hd;
	long nRet;
	unsigned char strv[255];
	char szTrojanPath[256];
	char szWinPath[256];
	DWORD vl=254;
	DWORD dwType;
	hd=HKEY_LOCAL_MACHINE;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run";
	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{		
		nRet = RegQueryValueEx(hd, "Reminder", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "wscan.exe"))
		{
			if(!ProcessVXER ((char*)strv))
			{
				printf("cannot kill process\n");
				bRet = false;
			}
			GetWindowsDirectory(szWinPath, 256);
			strcpy(szTrojanPath, szWinPath);
			strcat(szTrojanPath, "\\system\\wscan.exe");
			if(!DeleteFile(szTrojanPath))
				bRet = false;
			nRet = RegDeleteValue(hd, "Reminder");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		else
			bRet = false;
		RegCloseKey(hd);
	}
	if(!ModifyFile(szWinPath, "win.ini", "load=wscan.exe", "load="))
		bRet = false;
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////No2 kill backdoor///////////////////////////////////////////////////////////////////
bool Kill_BACKDOOR()
{
	HKEY hd;
	long nRet;
	bool bRet;
	char pWinPath[256];
	char szTrojanPath[256];
	unsigned char strv[255];
	DWORD dwvl = 254;
	char szVName[30];
	DWORD dwVNamNum = 29;
	DWORD dwType;
	UINT nNum;
	GetWindowsDirectory(pWinPath, 256);
	if(!ProcessVXER ("notpa.exe"))
	{
		bRet = false;
		printf("cannot kill process\n");
	}
	strcpy(szTrojanPath, pWinPath);
	strcat(szTrojanPath, "\\notpa.exe");
	if(!DeleteFile(szTrojanPath))
		bRet = false;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run";
	hd=HKEY_LOCAL_MACHINE; 
	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{	
		nNum = 0;
		dwType = REG_SZ;
		while(1)
		{
			nRet = RegEnumValue(hd, nNum++, szVName, &dwVNamNum, NULL, &dwType, strv, &dwvl);
			if(nRet == ERROR_SUCCESS)
			{
				if(strstr((char*)strv, "notpa.exe"))
				{
					nRet = RegDeleteValue(hd, szVName);
					if(nRet == ERROR_SUCCESS)
						bRet = true;
					else
						bRet = false;
				}
			}
			else
			{
				bRet = false;
				break;
			}
		}
		RegCloseKey(hd);
	}
	else
		bRet = false;
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////No3 kill bladerunner////////////////////////////////////////////////////////////////
bool Kill_BLADERUNNER()
{
	HKEY hd;
	long nRet;
	bool bRet;
	unsigned char strv[255];
	DWORD vl=254;
	DWORD dwtype;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run";
	char* deletestr = "System-Tray";
	hd=HKEY_LOCAL_MACHINE; 
	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{
		nRet = RegQueryValueEx(hd, deletestr, NULL, &dwtype, (LPBYTE)strv, &vl); 
		if(nRet == ERROR_SUCCESS)
		{
			if(!ProcessVXER ((char*)strv))
			{
				bRet = false;
				printf("cannot kill process\n");
			}
			else
			{
				DeleteFile((char*)strv);
				nRet = RegDeleteValue(hd, deletestr);
				if(nRet == ERROR_SUCCESS)
					bRet = true;
				else
					bRet = false;
			}		
		}
		RegCloseKey(hd);
	}
	else 
		bRet = false;
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////No4 kill deepthroat/////////////////////////////////////////////////////////////////
bool Kill_DEEPTHROAT()
{
	bool bRet, bRet1, bRet2;
	HKEY hd;
	long nRet;
	char* szNameV1 = "system32.exe";
	char* szNameV2 = "Systray.exe";
	unsigned char strv[255];
	char szTrojanPath[256];
	DWORD vl=254;
	DWORD dwType;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run";
	char pWinPath[256];
	GetWindowsDirectory(pWinPath, 256);
	if(ProcessVXER (szNameV1))
	{
		bRet1 = true; 
		strcpy(szTrojanPath, pWinPath);
		strcat(szTrojanPath, "\\");
		strcat(szTrojanPath, szNameV1);
		if(!DeleteFile(szTrojanPath))
			bRet1 = false;
		hd=HKEY_LOCAL_MACHINE;
		nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
		if(nRet == ERROR_SUCCESS)
		{
			nRet = RegQueryValueEx(hd, "System32", NULL, &dwType, (LPBYTE)strv, &vl); 
			if(strstr((char*)strv, "system32.exe"))
			{
				nRet = RegDeleteValue(hd, "System32");
				if(nRet != ERROR_SUCCESS)
					bRet1 = false;
			}
			RegCloseKey(hd);
		}
	}
	else
		bRet1 = false;
	if(ProcessVXER (szNameV2))
	{
		bRet2 = true; 
		strcpy(szTrojanPath, pWinPath);
		strcat(szTrojanPath, "\\");
		strcat(szTrojanPath, szNameV2);
		if(!DeleteFile(szTrojanPath))
			bRet2 = false;
		hd=HKEY_LOCAL_MACHINE;
		nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
		if(nRet == ERROR_SUCCESS)
		{
			nRet = RegQueryValueEx(hd, "SystemTray", NULL, &dwType, (LPBYTE)strv, &vl); 
			if(strstr((char*)strv, "Systray.exe"))
			{
				nRet = RegDeleteValue(hd, "SystemTray");
				if(nRet != ERROR_SUCCESS)
					bRet2 = false;
			}
			RegCloseKey(hd);
		}
	}
	else
		bRet2 = false;
	bRet = bRet1|bRet2;
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////No5 kill doly///////////////////////////////////////////////////////////////////////
bool Kill_DOLY()		
{
	bool bRet = true;
	bool bTemp;
	BOOL BTEMP;
	HKEY hd;
	long nRet;
	unsigned char strv[255];
	char szTrojanPath[256];
	DWORD vl=254;
	DWORD dwType;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run";
	bTemp = ProcessVXER ("mstesk.exe");
	bTemp &= ProcessVXER ("Mdm.exe");
	bTemp &= ProcessVXER ("MStesk.exe");
	if(!bTemp)
	{
		return false;
	}
	char pWinPath[256];
	GetWindowsDirectory(pWinPath, 256);
	strcpy(szTrojanPath, pWinPath);
	strcat(szTrojanPath, "\\system\\tesk.sys");
	BTEMP = DeleteFile(szTrojanPath);
	strcpy(szTrojanPath, pWinPath);
	strcat(szTrojanPath, "\\Start Menu\\ProgramsStartup\\mstesk.exe");
	BTEMP &= DeleteFile(szTrojanPath);
	BTEMP &= DeleteFile("C:\\Program Files\\MStesk.exe");
	DeleteFile("C:\\Program Files\\Mdm.exe");
	if(BTEMP)
		bRet = true;
	else
		bRet = false;
	strcat(pWinPath, "\\system\\tesk.exe");
	strcpy(szTrojanPath, "load=");
	strcat(szTrojanPath, pWinPath);
	if(!ModifyFile(pWinPath, "win.ini", szTrojanPath, "load="))
		bRet = false;
	hd=HKEY_CURRENT_USER;
	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{
		nRet = RegQueryValueEx(hd, "MS tesk", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "MStesk.exe"))
		{
			nRet = RegDeleteValue(hd, "MS tesk");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		RegCloseKey(hd);
	}
	hd = HKEY_USERS;
	nRet = RegOpenKeyEx(hd, "./DEFAULT\\Software\\Microsoft\\Windows\\CurrentVersion",0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{
		nRet = RegQueryValueEx(hd, "MS tesk", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "MStesk.exe"))
		{
			nRet = RegDeleteValue(hd, "MS tesk");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		RegCloseKey(hd);
	}	
	hd=HKEY_CURRENT_USER;
	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{
		nRet = RegDeleteKey(hd, "ss");
		if(nRet != ERROR_SUCCESS)
			bRet = false;
		RegCloseKey(hd);
	}
	if(!ModifyFile("C:\\", "autoexec.bat", "@echo off copy c\\:sys.lon c\\:windows\\Start Menu\\Startup Items\r\ndel c\\:win.reg", ""))
		bRet = false;
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////No6 kill gate crasher///////////////////////////////////////////////////////////////
bool Kill_GATECRASHER()
{
	bool bRet = true;
	HKEY hd;
	long nRet;
	unsigned char strv[255];
	DWORD vl=254;
	DWORD dwType;
	hd=HKEY_LOCAL_MACHINE;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run";
	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{		
		nRet = RegQueryValueEx(hd, "Explore", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "explore.exe"))
		{
			if(!ProcessVXER ((char*)strv))
			{
				printf("cannot kill process\n");
				bRet = false;
			}
			if(!DeleteFile((char*)strv))
				bRet = false;
			nRet = RegDeleteValue(hd, "Explore.exe");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		else
			bRet = false;
		RegCloseKey(hd);
	}
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////No7 kill girlfriend/////////////////////////////////////////////////////////////////
bool Kill_GIRLFRIEND()
{
	bool bRet = true;
	HKEY hd;
	long nRet;
	unsigned char strv[255];
	DWORD vl=254;
	DWORD dwType;
	hd=HKEY_LOCAL_MACHINE;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run";
	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{		
		nRet = RegQueryValueEx(hd, "Windll.exe", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "windll.exe"))
		{
			if(!ProcessVXER ((char*)strv))
			{
				printf("cannot kill process\n");
				bRet = false;
			}
			if(!DeleteFile((char*)strv))
				bRet = false;
			nRet = RegDeleteValue(hd, "Windll.exe");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		else
			bRet = false;
		RegCloseKey(hd);
	}
	hd=HKEY_LOCAL_MACHINE;
	char *Regkeyname1 = "SoftWare\\Microsoft";
	nRet = RegOpenKeyEx(hd,Regkeyname1,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{
		nRet = RegDeleteKey(hd, "General");
		if(nRet != ERROR_SUCCESS)
			bRet = false;
		RegCloseKey(hd);
	}
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////No8 kill hack99 keylogger///////////////////////////////////////////////////////////
bool Kill_HACK99KEYLOGGER()
{
	bool bRet = true;
	HKEY hd;
	long nRet;
	unsigned char strv[255];
	DWORD vl=254;
	DWORD dwType;
	hd=HKEY_LOCAL_MACHINE;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run";
	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{		
		nRet = RegQueryValueEx(hd, "HKeyLog", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "HkeyLog.exe"))
		{
			if(!ProcessVXER ((char*)strv))
			{
				printf("cannot kill process\n");
				bRet = false;
			}
			if(!DeleteFile((char*)strv))
				bRet = false;
			nRet = RegDeleteValue(hd, "HKeyLog");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		else
			bRet = false;
		RegCloseKey(hd);
	}
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////No9 kill inikiller//////////////////////////////////////////////////////////////////
bool Kill_INIKILLER()
{
	bool bRet = true;
	HKEY hd;
	long nRet;
	unsigned char strv[255];
	DWORD vl=254;
	DWORD dwType;
	hd=HKEY_LOCAL_MACHINE;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run";
	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{		
		nRet = RegQueryValueEx(hd, "Explore", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "bad.exe"))
		{
			if(!ProcessVXER ((char*)strv))
			{
				bRet = false;
				printf("cannot kill process\n");
			}
			if(!DeleteFile((char*)strv))
				bRet = false;
			nRet = RegDeleteValue(hd, "Explore");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		else
			bRet = false;
		RegCloseKey(hd);
	}
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////No10 kill master paradise///////////////////////////////////////////////////////////
bool Kill_MASTERPARADISE()
{
	bool bRet = true;
	HKEY hd;
	long nRet;
	unsigned char strv[255];
	DWORD vl=254;
	DWORD dwType;
	hd=HKEY_LOCAL_MACHINE;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run";
	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{		
		nRet = RegQueryValueEx(hd, "SYSEDIT", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "sysedit.exe"))
		{
			if(!ProcessVXER ((char*)strv))
			{
				printf("cannot kill process\n");
				bRet = false;
			}
			if(!DeleteFile((char*)strv))
				bRet = false;
			nRet = RegDeleteValue(hd, "SYSEDIT");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		else
			bRet = false;
		RegCloseKey(hd);
	}
	hd=HKEY_CURRENT_USER;
	char* Regkeyname1="SoftWare\\Microsoft\\Windows\\CurrentVersion\\RunServices";
	nRet = RegOpenKeyEx(hd,Regkeyname1,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{		
		nRet = RegQueryValueEx(hd, "Explorer", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "agent.exe"))
		{
			if(!ProcessVXER ((char*)strv))
				bRet = false;
			if(!DeleteFile((char*)strv))
				bRet = false;
			nRet = RegDeleteValue(hd, "Explorer");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		else
			bRet = false;
		RegCloseKey(hd);
	}
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////No11 kill netsphere/////////////////////////////////////////////////////////////////
bool Kill_NETSPHERE()
{
	bool bRet = true;
	HKEY hd;
	long nRet;
	unsigned char strv[255];
	DWORD vl=254;
	DWORD dwType;
	hd=HKEY_LOCAL_MACHINE;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run";
	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{		
		nRet = RegQueryValueEx(hd, "NSSX", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "nssx.exe"))
		{
			if(!ProcessVXER ((char*)strv))
			{
				printf("cannot kill process\n");
				bRet = false;
			}
			if(!DeleteFile((char*)strv))
				bRet = false;
			nRet = RegDeleteValue(hd, "NSSX");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		else
			bRet = false;
		RegCloseKey(hd);
	}
	hd=HKEY_CURRENT_USER;
	char* Regkeyname1="SoftWare\\Microsoft\\Windows\\CurrentVersion\\RunServices";
	nRet = RegOpenKeyEx(hd,Regkeyname1,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{		
		nRet = RegQueryValueEx(hd, "Explorer", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "agent.exe"))
		{
			nRet = RegDeleteValue(hd, "Explorer");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		else
			bRet = false;
		RegCloseKey(hd);
	}
	hd=HKEY_USERS;
	char* Regkeyname2="./DEFAULT\\SoftWare\\Microsoft\\Windows\\CurrentVersion\\RunServices";
	nRet = RegOpenKeyEx(hd,Regkeyname2,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{		
		nRet = RegQueryValueEx(hd, "Explorer", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "agent.exe"))
		{
			nRet = RegDeleteValue(hd, "Explorer");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		else
			bRet = false;
		RegCloseKey(hd);
	}
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////No12 kill netspy////////////////////////////////////////////////////////////////////
bool Kill_NETSPY()
{
	bool bRet = true;
	HKEY hd;
	long nRet;
	unsigned char strv[255];
	DWORD vl=254;
	DWORD dwType;
	hd=HKEY_LOCAL_MACHINE;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run";
	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{		
		nRet = RegQueryValueEx(hd, "SysProtect", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "system.exe"))
		{
			if(!ProcessVXER ((char*)strv))
			{
				printf("cannot kill process\n");
				bRet = false;
			}
			if(!DeleteFile((char*)strv))
				bRet = false;
			nRet = RegDeleteValue(hd, "SysProtect");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		else
			bRet = false;
		RegCloseKey(hd);
	}
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////No13 kill millenium/////////////////////////////////////////////////////////////////
bool Kill_MILLENIUM()
{
	bool bRet = true;
	HKEY hd;
	long nRet;
	unsigned char strv[255];
	DWORD vl=254;
	DWORD dwType;
	hd=HKEY_LOCAL_MACHINE;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run";
	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{		
		nRet = RegQueryValueEx(hd, "Millenium", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "reg66.exe"))
		{
			if(!ProcessVXER ((char*)strv))
			{
				printf("cannot kill process\n");
				bRet = false;
			}
			if(!DeleteFile((char*)strv))
				bRet = false;
			nRet = RegDeleteValue(hd, "Millenium");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		else
			bRet = false;
		RegCloseKey(hd);
	}
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////No14 kill priority//////////////////////////////////////////////////////////////////
bool Kill_PRIORITY()
{
	bool bRet = true;
	HKEY hd;
	long nRet;
	unsigned char strv[255];
	DWORD vl=254;
	DWORD dwType;
	hd=HKEY_LOCAL_MACHINE;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\RunServices";
	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{		
		nRet = RegQueryValueEx(hd, "PServer", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "PServer.exe"))
		{
			if(!ProcessVXER ((char*)strv))
			{
				printf("cannot kill process\n");
				bRet = false;
			}
			if(!DeleteFile((char*)strv))
				bRet = false;
			nRet = RegDeleteValue(hd, "PServer");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		else
			bRet = false;
		RegCloseKey(hd);
	}
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////No15 kill prosiak////////////////////////////////////////////////////////////////////
bool Kill_PROSIAK()
{
	bool bRet = true;
	HKEY hd;
	long nRet;
	unsigned char strv[255];
	DWORD vl=254;
	DWORD dwType;
	hd=HKEY_LOCAL_MACHINE;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\RunServices";
	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{		
		nRet = RegQueryValueEx(hd, "Microsoft DLL Loader", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "windll32.exe"))
		{
			if(!ProcessVXER ((char*)strv))
			{
				printf("cannot kill process\n");
				bRet = false;
			}
			if(!DeleteFile((char*)strv))
				bRet = false;
			nRet = RegDeleteValue(hd, "Microsoft DLL Loader");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		else
			bRet = false;
		RegCloseKey(hd);
	}
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////No16 kill ripper////////////////////////////////////////////////////////////////////
bool Kill_RIPPER()
{
	bool bRet = true;
	char szWinPath[256];
	char szTrojanPath[256];
	if(!ProcessVXER ("sysrunt.exe"))
	{
		bRet = false;
		printf("cannot kill process\n");
	}
	GetWindowsDirectory(szWinPath, 256);
	if(!ModifyFile(szWinPath, "system.ini", "sysrunt.exe", ""))
		bRet = false;
	strcpy(szTrojanPath, szWinPath);
	strcat(szTrojanPath, "\\sysrunt.exe");
	if(!DeleteFile(szTrojanPath))
		bRet = false;
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////No17 kill satans backdoor///////////////////////////////////////////////////////////
bool Kill_SATANSBACKDOOR()
{
	bool bRet = true;
	HKEY hd;
	long nRet;
	unsigned char strv[255];
	DWORD vl=254;
	DWORD dwType;
	hd=HKEY_LOCAL_MACHINE;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\RunServices";
	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{		
		nRet = RegQueryValueEx(hd, "sysprot protection", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "sysprot.exe"))
		{
			if(!ProcessVXER ((char*)strv))
			{
				printf("cannot kill process\n");
				bRet = false;
			}
			if(!DeleteFile((char*)strv))
				bRet = false;
			nRet = RegDeleteValue(hd, "sysprot protection");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		else
			bRet = false;
		RegCloseKey(hd);
	}
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////No18 kill telecommando//////////////////////////////////////////////////////////////
bool Kill_TELECOMMANDO()
{
	bool bRet = true;
	HKEY hd;
	long nRet;
	unsigned char strv[255];
	char szTrojanPath[256];
	DWORD vl=254;
	DWORD dwType;
	hd=HKEY_LOCAL_MACHINE;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run";
	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{		
		nRet = RegQueryValueEx(hd, "SystemApp", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "ODBC.exe"))
		{
			if(!ProcessVXER ("ODBC.exe"))
			{
				printf("cannot kill process\n");
				bRet = false;
			}
			GetWindowsDirectory(szTrojanPath, 256);
			strcat(szTrojanPath, "\\system\\ODBC.exe");
			if(!DeleteFile(szTrojanPath))
				bRet = false;
			nRet = RegDeleteValue(hd, "SystemApp");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		else
			bRet = false;
		RegCloseKey(hd);
	}
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////No19 kill trojan cow////////////////////////////////////////////////////////////////
bool Kill_TROJANCOW()
{
	bool bRet = true;
	HKEY hd;
	long nRet;
	unsigned char strv[255];
	DWORD vl=254;
	DWORD dwType;
	hd=HKEY_LOCAL_MACHINE;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run";
	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{		
		nRet = RegQueryValueEx(hd, "SysWindow", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "SysWindow.exe"))
		{
			if(!ProcessVXER ((char*)strv))
			{
				printf("cannot kill process\n");
				bRet = false;
			}
			if(!DeleteFile((char*)strv))
				bRet = false;
			nRet = RegDeleteValue(hd, "SysWindow");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		else
			bRet = false;
		RegCloseKey(hd);
	}
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////No20 kill webex/////////////////////////////////////////////////////////////////////
bool Kill_WEBEX()
{
	bool bRet = true;
	HKEY hd;
	long nRet;
	unsigned char strv[255];
	char szTrojanPath[256];
	DWORD vl=254;
	DWORD dwType;
	hd=HKEY_LOCAL_MACHINE;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run";
	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{		
		nRet = RegQueryValueEx(hd, "RunDl32", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "task_bar.exe"))
		{
			if(!ProcessVXER ((char*)strv))
			{
				printf("cannot kill process\n");
				bRet = false;
			}
			if(!DeleteFile((char*)strv))
				bRet = false;
			GetWindowsDirectory(szTrojanPath, 256);
			strcat(szTrojanPath, "\\system\\msinet.ocx");
			if(!DeleteFile(szTrojanPath))
				bRet = false;
			nRet = RegDeleteValue(hd, "RunDl32");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		else
			bRet = false;
		RegCloseKey(hd);
	}
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////No21 kill wincrash//////////////////////////////////////////////////////////////////
bool Kill_WINCRASH()
{
	bool bRet = true;
	HKEY hd;
	long nRet;
	unsigned char strv[255];
	DWORD vl=254;
	DWORD dwType;
	hd=HKEY_LOCAL_MACHINE;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run";
	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{		
		nRet = RegQueryValueEx(hd, "MsManager", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "SERVER.exe"))
		{
			if(!ProcessVXER ((char*)strv))
			{
				printf("cannot kill process\n");
				bRet = false;
			}
			if(!DeleteFile((char*)strv))
				bRet = false;
			nRet = RegDeleteValue(hd, "MsManager");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		else
			bRet = false;
		RegCloseKey(hd);
	}
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////No22 kill wincrash2/////////////////////////////////////////////////////////////////
bool Kill_WINCRASHV2()
{
	bool bRet = true;
	HKEY hd;
	long nRet;
	unsigned char strv[255];
	char szTrojan[256];
	char szWinPath[256];
	DWORD vl=254;
	DWORD dwType;
	hd=HKEY_LOCAL_MACHINE;
	char* Regkeyname="SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run";
	nRet = RegOpenKeyEx(hd,Regkeyname,0,KEY_ALL_ACCESS,&hd);
	if(nRet == ERROR_SUCCESS)
	{		
		nRet = RegQueryValueEx(hd, "WinManager", NULL, &dwType, (LPBYTE)strv, &vl); 
		if(strstr((char*)strv, "server.exe"))
		{
			if(!ProcessVXER ((char*)strv))
			{
				printf("cannot kill process\n");
				bRet = false;
			}
			if(!DeleteFile((char*)strv))
				bRet = false;
			nRet = RegDeleteValue(hd, "MsManager");
			if(nRet != ERROR_SUCCESS)
				bRet = false;
		}
		else
			bRet = false;
		RegCloseKey(hd);
	}
	GetWindowsDirectory(szWinPath, 256);
	strcpy(szTrojan, "run=");
	strcat(szTrojan, szWinPath);
	strcat(szTrojan, "\\server.exe");
	if(!ModifyFile(szWinPath, "win.ini", szTrojan, "run="))
		bRet = false;
	return bRet;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void Welcome()
{
	printf("***********************************\r\n");
	printf("**********AntiTrojan V1.0**********\r\n");
	printf("***********************************\r\n\r\n");
}
