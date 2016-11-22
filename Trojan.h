#ifndef TROJAN_H
#define TROJAN_H

class CTrojanList
{
private:
	TROJAN* pFirst;
	TROJAN* pLast;
	TROJAN Head;
	int nNumofTro;

public:
	CTrojanList(void);
	~CTrojanList(void);
	int Push(unsigned short nin_port, char* szName, unsigned int nin_Killno);
	TROJAN GetN(int n);
	TROJAN Pop(void);
	int GetNum(void);
};


#endif