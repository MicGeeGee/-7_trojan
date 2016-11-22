#ifndef ANTITROJAN_H
#define ANTITROJAN_H

#define NONE			0
#define ATTACKFTP		1
#define BACKDOOR		2
#define BLADERUNNER		3
#define DEEPTHROAT		4
#define DOLY			5
#define GATECRASHER		6
#define GIRLFRIEND		7
#define HACK99KEYLOGGER	8
#define INIKILLER		9
#define MASTERPARADISE	10
#define NETSPHERE		11
#define NETSPY			12
#define MILLENIUM		13
#define PRIORITY		14
#define PROSIAK			15
#define RIPPER			16
#define SATANSBACKDOOR	17
#define TELECOMMANDO	18
#define TROJANCOW		19
#define WEBEX			20
#define WINCRASH		21
#define WINCRASHV2		22

////Get Open Port either TCP or UDP///////////////////////////
////we store the results of netstat into a file and get them//
bool GetOpenPort();
//////////////////////////////////////////////////////////////

////Get Trojan information known from specific file///////////
////the info pair will be stored in a global class element////
bool GetTrojanInfo();
//////////////////////////////////////////////////////////////

////Remove specific Trojan by Parameter///////////////////////
bool RemoveTrojan(int n);
//////////////////////////////////////////////////////////////

////get process id by process name////////////////////////////
bool ProcessVXER (char* szname);
//////////////////////////////////////////////////////////////

////kill the trojan process before delete the trojan file///// 
bool KillProc (DWORD ProcessID);
//////////////////////////////////////////////////////////////

////enhance privilege before kill process/////////////////////
bool EnablePrivilege(PCHAR PrivilegeName);
//////////////////////////////////////////////////////////////

////Modify specific content in a file(not in Binary mode)/////
bool ModifyFile(char* szPath, char* szFileName, char* szSInfo, char* szDInfo);
//////////////////////////////////////////////////////////////

////functions to kill Trojan respectively/////////////////////
bool Kill_ATTACKFTP();
bool Kill_BACKDOOR();
bool Kill_BLADERUNNER();
bool Kill_DEEPTHROAT();
bool Kill_DOLY();			
bool Kill_GATECRASHER();
bool Kill_GIRLFRIEND();
bool Kill_HACK99KEYLOGGER();
bool Kill_INIKILLER();
bool Kill_MASTERPARADISE();
bool Kill_NETSPHERE();
bool Kill_NETSPY();
bool Kill_MILLENIUM();
bool Kill_PRIORITY();
bool Kill_PROSIAK();
bool Kill_RIPPER();
bool Kill_SATANSBACKDOOR();
bool Kill_TELECOMMANDO();
bool Kill_TROJANCOW();
bool Kill_WEBEX();
bool Kill_WINCRASH();
bool Kill_WINCRASHV2();
//////////////////////////////////////////////////////////////

////to show hello message/////////////////////////////////////
void Welcome();
//////////////////////////////////////////////////////////////
#endif