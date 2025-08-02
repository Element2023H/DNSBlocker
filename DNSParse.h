#pragma once

#pragma warning(push)
#pragma warning(disable:4201) /* Unnamed struct/union. */
#include <stddef.h>
#include <ndis.h>
#include <fwpsk.h>

#pragma warning(pop)

namespace DNSParse
{
	BOOLEAN 
	FillPacket(
		_In_		const FWPS_INCOMING_VALUES* inFixedValues,
		_In_		const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
		_Inout_opt_ void* layerData);


	BOOLEAN
	ParseDns(
		_In_	const PCHAR data,
		_In_	SIZE_T		len,
		_In_	SIZE_T		headerlen,
		_Out_	char*		pHostName,
		_Out_	USHORT*		pHostNameLength);
}

