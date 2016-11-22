#ifndef IPOKLIST_H
#define IPOKLIST_H

class CPortList
{
private:
	Container* pFirst;
	Container* pLast;
	Container Head;
	int nNumofPort;

public:
	CPortList(void);
	~CPortList(void);
	int Push(unsigned short nin_port);
	unsigned short Pop(void);
	int GetNum(void);
};

#endif