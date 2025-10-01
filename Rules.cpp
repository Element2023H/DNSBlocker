#include "Rules.hpp"

constexpr ULONG RULE_NODE_TAG = 'mmNR';


Rules::Rules()
{
	InitializeListHead(&m_listOfRules);

	ExInitializeNPagedLookasideList(&m_nlookasideOfRules,
		nullptr, nullptr, 0, RuleNodeSize, RuleNodeTag, 0);
}

Rules::~Rules()
{
	ClearAllRules();

	ExDeleteNPagedLookasideList(&m_nlookasideOfRules);
}

VOID 
Rules::AddRule(char* pHostName)
{
	kstd::UniqueLock<kstd::spinlock_mutex> _lock(m_spinLock);

	/*if (!IsInRules(pHostName))*/
	{
		RuleNode* pRuleNode = reinterpret_cast<RuleNode*>(ExAllocateFromNPagedLookasideList(&m_nlookasideOfRules));
		if (!pRuleNode)
		{
			return;
		}

		pRuleNode->BlackRule = reinterpret_cast<char*>(ExAllocatePoolWithTag(NonPagedPoolNx, strlen(pHostName) + 1, RULE_NODE_TAG));
		if (pRuleNode->BlackRule == nullptr)
		{
			ExFreeToNPagedLookasideList(&m_nlookasideOfRules, pRuleNode);
			return;
		}
		RtlZeroMemory(pRuleNode->BlackRule, strlen(pHostName) + 1);
		RtlCopyMemory(pRuleNode->BlackRule, pHostName, strlen(pHostName));

		InsertHeadList(&m_listOfRules, &pRuleNode->ListHeader);
	}
}

VOID
Rules::DelRule(char* pHostName)
{
	kstd::UniqueLock<kstd::spinlock_mutex> _lock(m_spinLock);

	if (IsListEmpty(&m_listOfRules))
	{
		return;
	}

	{
		RuleNode* pRuleNode{ nullptr };
		PLIST_ENTRY pEntry = m_listOfRules.Flink;
		while (pEntry != &m_listOfRules && pEntry)
		{
			pRuleNode = CONTAINING_RECORD(pEntry, RuleNode, ListHeader);
			if (pRuleNode && (pRuleNode->BlackRule != nullptr))
			{
				auto findNode{ [](char* pHostName, char* pTarget) ->char* {
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
				} };

				if (findNode(const_cast<char*>(pHostName), pRuleNode->BlackRule))
				{
					
					ExFreePoolWithTag(pRuleNode->BlackRule, RULE_NODE_TAG);
					RemoveHeadList(&pRuleNode->ListHeader);

					ExFreeToNPagedLookasideList(&m_nlookasideOfRules, pRuleNode);
					break;
				}
			}

			if (pEntry)
			{
				pEntry = pEntry->Flink;
			}
		}
	}
}

VOID 
Rules::ClearAllRules()
{
	kstd::UniqueLock<kstd::spinlock_mutex> _lock(m_spinLock);
	if (IsListEmpty(&m_listOfRules))
	{
		return;
	}

	RuleNode* pRuleNode{ nullptr };
	PLIST_ENTRY pEntry = m_listOfRules.Flink;
	while (pEntry != &m_listOfRules)
	{
		DbgBreakPoint();
		pRuleNode = CONTAINING_RECORD(pEntry, RuleNode, ListHeader);

		auto pNext = pEntry->Flink;
		
		if (pRuleNode->BlackRule)
		{
			ExFreePoolWithTag(pRuleNode->BlackRule, RULE_NODE_TAG);
			RemoveHeadList(&pRuleNode->ListHeader);

			ExFreeToNPagedLookasideList(&m_nlookasideOfRules, pRuleNode);
		}
		
	
		pEntry = pNext;	
	}

	/*while (!IsListEmpty(&m_listOfRules))
	{
		PLIST_ENTRY pEntry = m_listOfRules.Flink;
		RuleNode* pRuleNode = CONTAINING_RECORD(pEntry, RuleNode, ListHeader);

		if (pRuleNode)
		{
			if (pRuleNode->BlackRule)
			{
				ExFreePoolWithTag(pRuleNode->BlackRule, RULE_NODE_TAG);
			}

			RemoveHeadList(&pRuleNode->ListHeader);

			ExFreeToNPagedLookasideList(&m_nlookasideOfRules, pRuleNode);
		}
	}*/

}

BOOLEAN 
Rules::IsInRules(const char* pHostName)
{
	kstd::UniqueLock<kstd::spinlock_mutex> _lock(m_spinLock);

	if (IsListEmpty(&m_listOfRules))
	{
		return FALSE;
	}

	RuleNode* pRuleNode{nullptr};
	PLIST_ENTRY pEntry = m_listOfRules.Flink;
	while (pEntry != &m_listOfRules)
	{
		pRuleNode = CONTAINING_RECORD(pEntry, RuleNode, ListHeader);
		if (pRuleNode && (pRuleNode->BlackRule != nullptr))
		{
			auto findNode{ [](char* pHostName, char* pTarget) ->char*{
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
			} };

			if (findNode(const_cast<char*>(pHostName), pRuleNode->BlackRule))
			{
				return TRUE;
			}
		}

		if (pEntry)
		{
			pEntry = pEntry->Flink;
		}
	}



	return FALSE;
}
