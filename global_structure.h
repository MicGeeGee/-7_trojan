#ifndef GLOBAL_STRUCTURE_H
#define GLOBAL_STRUCTURE_H

#ifndef MAXNAME
#define MAXNAME 30
#endif

typedef struct Portcon{
	unsigned short nPort;
	Portcon* pnext;
}Container;

typedef struct Trojancon{
	unsigned short nPort;
	char TroName[MAXNAME];
	unsigned int nKillno;
	Trojancon* pnext;
}TROJAN;

#endif