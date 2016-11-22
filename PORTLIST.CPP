#include "stdafx.h"
#include <stdio.h>
#include <string.h>
#include "global_structure.h"
#include "PortList.h"

CPortList::CPortList()
{
	Head.pnext = NULL;
	pFirst = &Head;
	pLast = pFirst;
	nNumofPort = 0;
}

int CPortList::Push(unsigned short nin_port)
{
	Container* pTemp;
	pTemp = new Container;
	pTemp->nPort = nin_port;
	pTemp->pnext = pLast;
	pLast = pTemp;
	nNumofPort++;
	return nNumofPort;
}

unsigned short CPortList::Pop(void)
{
	Container IPtemp;
	Container* pTemp;
	if(nNumofPort == 0)
	{
		IPtemp.pnext = NULL;
		return 0;
	}
	IPtemp.nPort = pLast->nPort;
	IPtemp.pnext = pLast->pnext;
	pTemp = pLast->pnext;
	delete pLast;
	pLast = pTemp;
	nNumofPort--;
	return IPtemp.nPort;
}

int CPortList::GetNum(void)
{
	return nNumofPort;
}

CPortList::~CPortList()
{
	Container* pTemp;
	while(nNumofPort--)
	{
		pTemp = pLast->pnext;
		delete pLast;
		pLast = pTemp;
	}
}


