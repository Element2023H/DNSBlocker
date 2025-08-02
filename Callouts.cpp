#include "Callouts.h"
#include "Lazy.hpp"
#include "DNSParse.h"
#include <stdio.h>

using namespace DNSParse;

extern LazyInstance<GlobalData> g_pGlobalData;

constexpr ULONG STORAGE_TAG = 'GATs';


static
char* 
FindStrNoCase(char* pHostName, char* pTarget)
{
	if (!pHostName || 
		!pTarget || 
		strlen(pHostName) < strlen(pTarget))
	{
		return nullptr;
	}

	do
	{
		char* h = pHostName;
		char* t = pTarget;

		while (tolower(*h) == tolower(*t) && *t)
		{
			h++;
			t++;
		}

		if (*t == '\0')
		{
			return h;
		}
	} while (*pHostName++);

	return nullptr;
}

static
VOID 
UdpClassifyFn(
	IN const FWPS_INCOMING_VALUES* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	IN VOID* layerData, 
	IN const void* classifyContext, 
	IN const FWPS_FILTER* filter,
	IN UINT64 flowContext, 
	OUT FWPS_CLASSIFY_OUT* classifyOut)
{
	UNREFERENCED_PARAMETER(inFixedValues);
	UNREFERENCED_PARAMETER(inMetaValues);
	UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(classifyOut);


	BOOLEAN bIsSend{ FALSE };
	UINT16	uRemotePort{ 0 };

	if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
	{
		return;
	}

	classifyOut->actionType = FWP_ACTION_PERMIT;

	if (inFixedValues->layerId == FWPS_LAYER_DATAGRAM_DATA_V4)
	{
		bIsSend = (FWP_DIRECTION_OUTBOUND ==
			inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION].value.uint32);

		uRemotePort = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT].value.uint16;
	}
	else
	{
		bIsSend = (FWP_DIRECTION_OUTBOUND ==
			inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_DIRECTION].value.uint32);
		uRemotePort = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_PORT].value.uint16;
	}

	// filter dns
	if (bIsSend && 53 == uRemotePort)
	{
		/*
		*	TODO
		*/
		
		char szDomainName[260]{};
		RtlZeroMemory(szDomainName, 260);
		USHORT nDomainNameLength{ 0 };
		BOOLEAN bResult{ FALSE };
		
		NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB((NET_BUFFER_LIST*)layerData);
		auto nbLength = NET_BUFFER_DATA_LENGTH(nb);
		if (nbLength == 0 || 
			inMetaValues->transportHeaderSize == 0 ||
			nbLength < inMetaValues->transportHeaderSize)
		{
			return;
		}

		PVOID pStorage = ExAllocatePoolWithTag(NonPagedPoolNx, nbLength, STORAGE_TAG);
		if (!pStorage)
		{
			return;
		}
		RtlZeroMemory(pStorage, nbLength);
		PCHAR pPacketBuffer = reinterpret_cast<PCHAR>(NdisGetDataBuffer(nb, nbLength, pStorage, 1, NULL));
		if (!pPacketBuffer)
		{
			ExFreePoolWithTag(pStorage, STORAGE_TAG);
			return;
		}

		bResult = ParseDns(pPacketBuffer, 
						   nbLength, 
						   inMetaValues->transportHeaderSize,
						   szDomainName,
						   &nDomainNameLength);
		// test	
		char szBlock[] = ".baidu.com";
		if (bResult)
		{
			if (FindStrNoCase(szDomainName, szBlock))
			{
				// DbgBreakPoint();
				classifyOut->actionType = FWP_ACTION_BLOCK;
				classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
				classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
			}
		}
		
		if (pStorage)
		{
			ExFreePoolWithTag(pStorage, STORAGE_TAG);
			pStorage = nullptr;
		}
		

		
	}

}


static
NTSTATUS 
CalloutNotify(
	FWPS_CALLOUT_NOTIFY_TYPE  NotifyType,
	const GUID* FilterKey,
	FWPS_FILTER* Filter
) 
{
	UNREFERENCED_PARAMETER(NotifyType);
	UNREFERENCED_PARAMETER(FilterKey);
	UNREFERENCED_PARAMETER(Filter);

	return STATUS_SUCCESS;
}

static
NTSTATUS
AddUdpFilter(
	const GUID* calloutKey, 
	const GUID* applicableLayer,
	FWPM_SUBLAYER* subLayer)
{
	NTSTATUS			status{ STATUS_SUCCESS };
	FWPM_CALLOUT		mCallout{};
	FWPM_DISPLAY_DATA	displayData{};
	FWPM_FILTER			filter{};


	do
	{
		RtlZeroMemory(&mCallout, sizeof(mCallout));
		displayData.description			= BLOCK_UDP_CALLOUT_DESCRIPTION;
		displayData.name				= BLOCK_UDP_CALLOUT_NAME;

		mCallout.calloutKey				= *calloutKey;
		mCallout.displayData			= displayData;
		mCallout.applicableLayer		= *applicableLayer;
		mCallout.flags					= 0;

		status = FwpmCalloutAdd(g_pGlobalData->hEngine, &mCallout, NULL, NULL);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		RtlZeroMemory(&filter, sizeof(filter));

		filter.layerKey					= *applicableLayer;
		filter.displayData.name			= BLOCK_UDP_FILTER_NAME;
		filter.displayData.description	= BLOCK_UDP_FILTER_NAME;
		filter.action.type				= FWP_ACTION_CALLOUT_TERMINATING;
		filter.action.calloutKey		= *calloutKey;
		filter.filterCondition			= NULL;
		filter.subLayerKey				= subLayer->subLayerKey;
		filter.weight.type				= FWP_EMPTY; // auto-weight.
		filter.numFilterConditions		= 0;

		status = FwpmFilterAdd(g_pGlobalData->hEngine,
			&filter,
			NULL,
			NULL);

		if (!NT_SUCCESS(status))
		{
			break;
		}

		break;
	} while (FALSE);

	return status;
}


NTSTATUS 
Callouts::CalloutsInit(IN PDEVICE_OBJECT DeviceObject)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	if (m_bInitialized)
	{
		return STATUS_SUCCESS;
	}

	ExUuidCreate(&g_pGlobalData->guidProvider);
	ExUuidCreate(&g_pGlobalData->guidSublayer);

	for (size_t i = 0; i != CG_MAX; ++i)
	{
		ExUuidCreate(&g_pGlobalData->calloutGuids[i]);
	}

	NTSTATUS status{ STATUS_SUCCESS };

	FWPM_SESSION session{};
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;

	status = FwpmEngineOpen(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &g_pGlobalData->hEngine);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	do 
	{
		FWPM_PROVIDER provider{};
		RtlZeroMemory(&provider, sizeof(FWPM_PROVIDER));
		provider.displayData.description = BLOCK_PROVIDER_NAME;
		provider.displayData.name = BLOCK_PROVIDER_NAME;
		provider.providerKey = g_pGlobalData->guidProvider;

		status = FwpmProviderAdd(g_pGlobalData->hEngine, &provider, nullptr);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		status = this->RegisterCallouts(DeviceObject);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		status = this->AddFilters();
		if (!NT_SUCCESS(status))
		{
			break;
		}

		m_bInitialized = TRUE;
		break;

	} while (FALSE);

	if (!NT_SUCCESS(status))
	{
		this->CalloutsFree();
		m_bInitialized = FALSE;
	}
	
	return status;
}

void Callouts::CalloutsFree()
{
	if (!m_bInitialized)
	{
		return;
	}

	UnregisterCallouts();

	FwpmSubLayerDeleteByKey(g_pGlobalData->hEngine, &g_pGlobalData->guidSublayer);
	FwpmProviderContextDeleteByKey(g_pGlobalData->hEngine, &g_pGlobalData->guidProvider);
	
	if (g_pGlobalData->hEngine)
	{
		FwpmEngineClose(g_pGlobalData->hEngine);
		g_pGlobalData->hEngine = nullptr;
	}
}

NTSTATUS 
Callouts::RegisterCallouts(IN PDEVICE_OBJECT DeviceObject)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	DbgBreakPoint();

	NTSTATUS status{ STATUS_SUCCESS };

	status = FwpmTransactionBegin(g_pGlobalData->hEngine, 0);
	if (!NT_SUCCESS(status))
	{
		FwpmEngineClose(g_pGlobalData->hEngine);

		g_pGlobalData->hEngine = NULL;
		return status;
	}

	/*
	* Register Callout
	*/
	do 
	{
		// DATAGRAM
		status = RegisterCallout(DeviceObject,
					UdpClassifyFn,
					CalloutNotify,
					NULL,
					&g_pGlobalData->calloutGuids[CG_DATAGRAM_DATA_CALLOUT_V4],
					0,
					&g_pGlobalData->calloutIds[CG_DATAGRAM_DATA_CALLOUT_V4]);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		status = RegisterCallout(DeviceObject,
					UdpClassifyFn,
					CalloutNotify,
					NULL,
					&g_pGlobalData->calloutGuids[CG_DATAGRAM_DATA_CALLOUT_V6],
					0,
					&g_pGlobalData->calloutIds[CG_DATAGRAM_DATA_CALLOUT_V6]);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		// 
		status = FwpmTransactionCommit(g_pGlobalData->hEngine);
		if (!NT_SUCCESS(status))
		{
			break;
		}


	} while (FALSE);

	if (!NT_SUCCESS(status))
	{
		FwpmTransactionAbort(g_pGlobalData->hEngine);
		FwpmEngineClose(g_pGlobalData->hEngine);
		g_pGlobalData->hEngine = NULL;
		return status;
	}

	return status;
}

NTSTATUS 
Callouts::RegisterCallout(
	IN OUT PDEVICE_OBJECT					DeviceObject, 
	IN FWPS_CALLOUT_CLASSIFY_FN				ClassifyFn, 
	IN FWPS_CALLOUT_NOTIFY_FN				NotifyFn, 
	IN FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN	FlowDeleteFn, 
	IN GUID CONST*							CalloutKey, 
	IN UINT32								Flags,
	OUT UINT32* CalloutId)
{
	FWPS_CALLOUT sCallout{};
	RtlZeroMemory(&sCallout, sizeof(sCallout));

	sCallout.calloutKey		= *CalloutKey;
	sCallout.flags			= Flags;
	sCallout.classifyFn		= ClassifyFn;
	sCallout.notifyFn		= NotifyFn;
	sCallout.flowDeleteFn	= FlowDeleteFn;

	auto status = FwpsCalloutRegister(DeviceObject, &sCallout, CalloutId);

	return status;
}

NTSTATUS Callouts::AddFilters()
{
	NTSTATUS status{ STATUS_SUCCESS };
	
	FWPM_SUBLAYER subLayer{};
	do 
	{
		RtlZeroMemory(&subLayer, sizeof(FWPM_SUBLAYER));

		// set sublayer
		subLayer.subLayerKey				= g_pGlobalData->guidSublayer;
		subLayer.displayData.name			= BLOCK_UDP_SUBLAYER_NAME;
		subLayer.displayData.description	= BLOCK_UDP_SUBLAYER_NAME;
		subLayer.flags						= 0;
		subLayer.weight						= 65535;

		// add sublayer
		status = FwpmSubLayerAdd(g_pGlobalData->hEngine, &subLayer, NULL);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		// add filters
		status = AddUdpFilter(&g_pGlobalData->calloutGuids[CG_DATAGRAM_DATA_CALLOUT_V4],
							  &FWPM_LAYER_DATAGRAM_DATA_V4,
							  &subLayer);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		status = AddUdpFilter(&g_pGlobalData->calloutGuids[CG_DATAGRAM_DATA_CALLOUT_V6],
							  &FWPM_LAYER_DATAGRAM_DATA_V6,
							  &subLayer);
		if (!NT_SUCCESS(status))
		{
			break;
		}
	} while (FALSE);


	return status;
}

void 
Callouts::UnregisterCallouts()
{
	NTSTATUS status{ STATUS_SUCCESS };
	for (size_t i = 0; i != CG_MAX; i++)
	{
		status = FwpsCalloutUnregisterByKey0(&g_pGlobalData->calloutGuids[i]);
		if (!NT_SUCCESS(status))
		{
			//ASSERT(0);
		}
	}
}
