#include "stdafx.h"
#include <stdio.h>
#include <string.h>
#include "global_structure.h"
#include "Trojan.h"

CTrojanList::CTrojanList()
{
	Head.pnext = NULL;
	pFirst = &Head;
	pLast = pFirst;
	nNumofTro = 0;
}

int CTrojanList::Push(unsigned short nin_port, char *szName, unsigned int nin_Killno)
{
	TROJAN* pTemp;
	pTemp = new TROJAN;
	memset(pTemp->TroName, 0, MAXNAME);
	strncpy(pTemp->TroName, szName, MAXNAME);
	pTemp->nPort = nin_port;
	pTemp->nKillno = nin_Killno;
	pTemp->pnext = pLast;
	pLast = pTemp;
	nNumofTro++;
	return nNumofTro;
}

TROJAN CTrojanList::Pop(void)
{
	TROJAN Ttemp;
	TROJAN* pTemp;
	if(nNumofTro == 0)
	{
		Ttemp.pnext = NULL;
		return Ttemp;
	}
	memset(Ttemp.TroName, 0, MAXNAME);
	strcpy(Ttemp.TroName, pLast->TroName);
	Ttemp.nPort = pLast->nPort;
	Ttemp.nKillno = pLast->nKillno;
	Ttemp.pnext = pLast->pnext;
	pTemp = pLast->pnext;
	delete pLast;
	pLast = pTemp;
	nNumofTro--;
	return Ttemp;
}

int CTrojanList::GetNum(void)
{
	return nNumofTro;
}

CTrojanList::~CTrojanList()
{
	TROJAN* pTemp;
	while(nNumofTro--)
	{
		pTemp = pLast->pnext;
		delete pLast;
		pLast = pTemp;
	}
}

TROJAN CTrojanList::GetN(int n)
{
	int i;
	TROJAN Treturn;
	TROJAN *pCurrent;
	if(GetNum() <= n)
	{
		Treturn.pnext = NULL;
		return Treturn;
	}
	for(i=0,pCurrent = pLast; i<n; i++)
		pCurrent = pCurrent->pnext;
	Treturn.nPort = pCurrent->nPort;
	Treturn.nKillno = pCurrent->nKillno;
	strcpy(Treturn.TroName, pCurrent->TroName);
	return Treturn;
}

