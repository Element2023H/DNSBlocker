#pragma once
#include "Headers.h"
#include "Lazy.hpp"

class Callouts
{
public:
	Callouts() = default;
	~Callouts()
	{
		this->CalloutsFree();
	}

	NTSTATUS	CalloutsInit(IN PDEVICE_OBJECT DeviceObject);
	void		CalloutsFree();

protected:
	NTSTATUS	
	RegisterCallouts(IN PDEVICE_OBJECT DeviceObject);

	NTSTATUS    
	RegisterCallout(
		IN OUT PDEVICE_OBJECT DeviceObject, 
		IN FWPS_CALLOUT_CLASSIFY_FN ClassifyFn,
		IN FWPS_CALLOUT_NOTIFY_FN NotifyFn,
		IN FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN FlowDeleteFn,
		IN GUID CONST* CalloutKey,
		IN UINT32 Flags,
		OUT UINT32* CalloutId);

	NTSTATUS	AddFilters();

	void		UnregisterCallouts();

	
private:
	BOOLEAN		m_bInitialized{ FALSE };
};

static LazyInstance<Callouts> lazyCallouts;