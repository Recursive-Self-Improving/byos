package web

import "strings"

type modelAliasKey struct {
	provider     Provider
	accountID    string
	upstreamName string
}

type modelAliasItem struct {
	key         modelAliasKey
	name        string
	canonical   bool
	allowlisted bool
}

type modelAliasGroup struct {
	representative int
	aliases        string
	allowlisted    bool
}

func collapseModelAliasGroups(items []modelAliasItem) []modelAliasGroup {
	type groupState struct {
		representative int
		names          []string
		allowlisted    bool
	}

	groups := make([]groupState, 0, len(items))
	byKey := make(map[modelAliasKey]int, len(items))
	for index, item := range items {
		groupIndex, exists := byKey[item.key]
		if !exists {
			groupIndex = len(groups)
			byKey[item.key] = groupIndex
			groups = append(groups, groupState{representative: index})
		}

		group := &groups[groupIndex]
		group.names = append(group.names, item.name)
		if item.canonical {
			group.representative = index
		}
		group.allowlisted = group.allowlisted || item.allowlisted
	}

	collapsed := make([]modelAliasGroup, len(groups))
	for resultIndex, group := range groups {
		representativeName := items[group.representative].name
		aliases := make([]string, 0, len(group.names)-1)
		for _, name := range group.names {
			if name != representativeName {
				aliases = append(aliases, name)
			}
		}
		collapsed[resultIndex] = modelAliasGroup{
			representative: group.representative,
			aliases:        strings.Join(aliases, ", "),
			allowlisted:    group.allowlisted,
		}
	}
	return collapsed
}

func collapseAccountModelAliases(accountID string, models []AccountModel) []AccountModel {
	items := make([]modelAliasItem, len(models))
	for index, model := range models {
		items[index] = modelAliasItem{
			key: modelAliasKey{
				provider:     model.Provider,
				accountID:    accountID,
				upstreamName: model.UpstreamName,
			},
			name:      model.Name,
			canonical: model.Name == model.UpstreamName,
		}
	}

	groups := collapseModelAliasGroups(items)
	collapsed := make([]AccountModel, len(groups))
	for index, group := range groups {
		collapsed[index] = models[group.representative]
		collapsed[index].Aliases = group.aliases
	}
	return collapsed
}

func collapseModelAliases(models []ModelSupport) []ModelSupport {
	items := make([]modelAliasItem, len(models))
	for index, model := range models {
		items[index] = modelAliasItem{
			key: modelAliasKey{
				provider:     model.Provider,
				accountID:    model.AccountID,
				upstreamName: model.UpstreamName,
			},
			name:        model.Name,
			canonical:   model.Name == model.UpstreamName,
			allowlisted: model.Allowlisted,
		}
	}

	groups := collapseModelAliasGroups(items)
	collapsed := make([]ModelSupport, len(groups))
	for index, group := range groups {
		collapsed[index] = models[group.representative]
		collapsed[index].Aliases = group.aliases
		collapsed[index].Allowlisted = group.allowlisted
	}
	return collapsed
}
