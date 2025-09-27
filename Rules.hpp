#pragma once
#include "Locks.hpp"
#include "Lazy.hpp"


struct RuleNode
{
	LIST_ENTRY	ListHeader;
	char*		BlackRule;
};

constexpr ULONG RuleNodeSize = sizeof(RuleNode);
constexpr ULONG RuleNodeTag  = 'gtNR';

class Rules
{
public:
	Rules();
	~Rules();


public:
	VOID AddRule(char* pHostName);
	VOID DelRule(char* pHostName);
	VOID ClearAllRules();
	BOOLEAN IsInRules(const char* pHostName);


private:
	kstd::spinlock_mutex	m_spinLock;

	LIST_ENTRY				m_listOfRules;

	NPAGED_LOOKASIDE_LIST	m_nlookasideOfRules;
};


static LazyInstance<Rules> rules;
