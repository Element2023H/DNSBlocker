#include "DNSParse.h"

#pragma pack(push, 1) 
typedef struct _DNS_HEADER 
{
	UINT16 Id;  
	UINT16 Rd : 1;
	UINT16 Tc : 1;
	UINT16 Aa : 1;
	UINT16 OpCode : 4;
	UINT16 Qr : 1;			// 等于0为请求包，等于1为响应包
	UINT16 RcCode : 4;
	UINT16 Zero : 3;
	UINT16 Ra : 1;
	UINT16 QdCount;			// 问题数
	UINT16 AnCount;			// 答案数
	UINT16 NsCount;			// 权威记录数
	UINT16 ArCount;			// 附加记录数
}DNS_HEADER, *PDNS_HEADER;
#pragma pack(pop)


// 参考书《万径寻踪：Windows入侵检测与防御编程（卷一）》中代码
// 
BOOLEAN 
DNSParse::ParseDns(
	_In_ const PCHAR data, 
	_In_ SIZE_T len, 
	_In_ SIZE_T headerlen,
	_Out_ char* pHostName,
	_Out_ USHORT* pHostNameLength)
{
	if (len < sizeof(DNS_HEADER) || !data)
	{
		return FALSE;
	}
	PDNS_HEADER pDnsHeader = reinterpret_cast<PDNS_HEADER>(data);
	if (1 == pDnsHeader->Qr)
	{
		return FALSE;
	}

	PCHAR pDnsData = data + sizeof(DNS_HEADER) + headerlen;
	SIZE_T nDnsLength = strlen(pDnsData);
	if (nDnsLength > 256)
	{
		return FALSE;
	}
	*pHostNameLength = static_cast<USHORT>(nDnsLength);
	for (int i = 0; i < nDnsLength; i++)
	{
		char domainItem = *(pDnsData + i + 1);
		if (isprint(domainItem))
		{
			pHostName[i] = domainItem;
		}
		else if (i == 0)
		{
			continue;
		}
		else 
		{
			pHostName[i] = '.';
		}
	}
	pHostName[nDnsLength] = '\0';

	return TRUE;
}
