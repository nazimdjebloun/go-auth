package handler

import (
	"net/url"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
)

func sortQueryValue(query url.Values, name string) (string, bool) {
	values, supplied := query[name]
	if !supplied {
		return "", false
	}
	if len(values) == 0 {
		return "", true
	}
	return values[0], true
}

func parseSortDirection(query url.Values, fallback api.SortDirection) (api.SortDirection, error) {
	raw, supplied := sortQueryValue(query, "orderDirection")
	if !supplied {
		return fallback, nil
	}
	switch api.SortDirection(raw) {
	case api.SortAscending, api.SortDescending:
		return api.SortDirection(raw), nil
	default:
		return "", domain.NewError("invalid_input", "orderDirection must be asc or desc")
	}
}

func parseUserSort(query url.Values) (api.UserSortField, api.SortDirection, error) {
	orderBy := api.UserSortCreatedAt
	if raw, supplied := sortQueryValue(query, "orderBy"); supplied {
		switch api.UserSortField(raw) {
		case api.UserSortCreatedAt, api.UserSortUpdatedAt:
			orderBy = api.UserSortField(raw)
		default:
			return "", "", domain.NewError("invalid_input", "orderBy must be created_at or updated_at")
		}
	}
	direction, err := parseSortDirection(query, api.SortDescending)
	return orderBy, direction, err
}

func parseSessionSort(query url.Values) (api.SessionSortField, api.SortDirection, error) {
	orderBy := api.SessionSortCreatedAt
	if raw, supplied := sortQueryValue(query, "orderBy"); supplied {
		switch api.SessionSortField(raw) {
		case api.SessionSortCreatedAt, api.SessionSortExpiresAt, api.SessionSortLastActiveAt:
			orderBy = api.SessionSortField(raw)
		default:
			return "", "", domain.NewError("invalid_input", "orderBy must be created_at, expires_at, or last_active_at")
		}
	}
	direction, err := parseSortDirection(query, api.SortDescending)
	return orderBy, direction, err
}

func parseInviteSort(query url.Values) (api.InviteSortField, api.SortDirection, error) {
	orderBy := api.InviteSortCreatedAt
	if raw, supplied := sortQueryValue(query, "orderBy"); supplied {
		switch api.InviteSortField(raw) {
		case api.InviteSortCreatedAt, api.InviteSortExpiresAt, api.InviteSortEmail, api.InviteSortStatus:
			orderBy = api.InviteSortField(raw)
		default:
			return "", "", domain.NewError("invalid_input", "orderBy must be created_at, expires_at, email, or status")
		}
	}
	direction, err := parseSortDirection(query, api.SortDescending)
	return orderBy, direction, err
}

func parseOrgMemberSort(query url.Values) (api.OrgMemberSortField, api.SortDirection, error) {
	orderBy := api.OrgMemberSortJoinedAt
	if raw, supplied := sortQueryValue(query, "orderBy"); supplied {
		switch api.OrgMemberSortField(raw) {
		case api.OrgMemberSortJoinedAt, api.OrgMemberSortRole, api.OrgMemberSortName, api.OrgMemberSortEmail:
			orderBy = api.OrgMemberSortField(raw)
		default:
			return "", "", domain.NewError("invalid_input", "orderBy must be joined_at, role, name, or email")
		}
	}
	direction, err := parseSortDirection(query, api.SortAscending)
	return orderBy, direction, err
}

func parseUserOrgSort(query url.Values) (api.UserOrgSortField, api.SortDirection, error) {
	orderBy := api.UserOrgSortName
	if raw, supplied := sortQueryValue(query, "orderBy"); supplied {
		switch api.UserOrgSortField(raw) {
		case api.UserOrgSortName, api.UserOrgSortCreatedAt, api.UserOrgSortMemberCount:
			orderBy = api.UserOrgSortField(raw)
		default:
			return "", "", domain.NewError("invalid_input", "orderBy must be name, created_at, or member_count")
		}
	}
	direction, err := parseSortDirection(query, api.SortAscending)
	return orderBy, direction, err
}

func parseOrgSort(query url.Values) (api.OrgSortField, api.SortDirection, error) {
	orderBy := api.OrgSortName
	if raw, supplied := sortQueryValue(query, "orderBy"); supplied {
		switch api.OrgSortField(raw) {
		case api.OrgSortName, api.OrgSortCreatedAt, api.OrgSortMemberCount:
			orderBy = api.OrgSortField(raw)
		default:
			return "", "", domain.NewError("invalid_input", "orderBy must be name, created_at, or member_count")
		}
	}
	direction, err := parseSortDirection(query, api.SortAscending)
	return orderBy, direction, err
}

func parseOrgInviteSort(query url.Values) (api.OrgInviteSortField, api.SortDirection, error) {
	orderBy := api.OrgInviteSortCreatedAt
	if raw, supplied := sortQueryValue(query, "orderBy"); supplied {
		switch api.OrgInviteSortField(raw) {
		case api.OrgInviteSortCreatedAt, api.OrgInviteSortExpiresAt, api.OrgInviteSortEmail, api.OrgInviteSortRole:
			orderBy = api.OrgInviteSortField(raw)
		default:
			return "", "", domain.NewError("invalid_input", "orderBy must be created_at, expires_at, email, or role")
		}
	}
	direction, err := parseSortDirection(query, api.SortDescending)
	return orderBy, direction, err
}
