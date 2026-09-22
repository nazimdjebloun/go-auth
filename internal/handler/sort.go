package handler

import (
	"net/url"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
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

func parseSortDirection(query url.Values, fallback port.SortDirection) (port.SortDirection, error) {
	raw, supplied := sortQueryValue(query, "orderDirection")
	if !supplied {
		return fallback, nil
	}
	switch port.SortDirection(raw) {
	case port.SortAscending, port.SortDescending:
		return port.SortDirection(raw), nil
	default:
		return "", domain.NewError("invalid_input", "orderDirection must be asc or desc")
	}
}

func parseUserSort(query url.Values) (port.UserSortField, port.SortDirection, error) {
	orderBy := port.UserSortCreatedAt
	if raw, supplied := sortQueryValue(query, "orderBy"); supplied {
		switch port.UserSortField(raw) {
		case port.UserSortCreatedAt, port.UserSortUpdatedAt:
			orderBy = port.UserSortField(raw)
		default:
			return "", "", domain.NewError("invalid_input", "orderBy must be created_at or updated_at")
		}
	}
	direction, err := parseSortDirection(query, port.SortDescending)
	return orderBy, direction, err
}

func parseSessionSort(query url.Values) (port.SessionSortField, port.SortDirection, error) {
	orderBy := port.SessionSortCreatedAt
	if raw, supplied := sortQueryValue(query, "orderBy"); supplied {
		switch port.SessionSortField(raw) {
		case port.SessionSortCreatedAt, port.SessionSortExpiresAt, port.SessionSortLastActiveAt:
			orderBy = port.SessionSortField(raw)
		default:
			return "", "", domain.NewError("invalid_input", "orderBy must be created_at, expires_at, or last_active_at")
		}
	}
	direction, err := parseSortDirection(query, port.SortDescending)
	return orderBy, direction, err
}

func parseInviteSort(query url.Values) (port.InviteSortField, port.SortDirection, error) {
	orderBy := port.InviteSortCreatedAt
	if raw, supplied := sortQueryValue(query, "orderBy"); supplied {
		switch port.InviteSortField(raw) {
		case port.InviteSortCreatedAt, port.InviteSortExpiresAt, port.InviteSortEmail, port.InviteSortStatus:
			orderBy = port.InviteSortField(raw)
		default:
			return "", "", domain.NewError("invalid_input", "orderBy must be created_at, expires_at, email, or status")
		}
	}
	direction, err := parseSortDirection(query, port.SortDescending)
	return orderBy, direction, err
}

func parseOrgMemberSort(query url.Values) (port.OrgMemberSortField, port.SortDirection, error) {
	orderBy := port.OrgMemberSortJoinedAt
	if raw, supplied := sortQueryValue(query, "orderBy"); supplied {
		switch port.OrgMemberSortField(raw) {
		case port.OrgMemberSortJoinedAt, port.OrgMemberSortRole, port.OrgMemberSortName, port.OrgMemberSortEmail:
			orderBy = port.OrgMemberSortField(raw)
		default:
			return "", "", domain.NewError("invalid_input", "orderBy must be joined_at, role, name, or email")
		}
	}
	direction, err := parseSortDirection(query, port.SortAscending)
	return orderBy, direction, err
}

func parseUserOrgSort(query url.Values) (port.UserOrgSortField, port.SortDirection, error) {
	orderBy := port.UserOrgSortName
	if raw, supplied := sortQueryValue(query, "orderBy"); supplied {
		switch port.UserOrgSortField(raw) {
		case port.UserOrgSortName, port.UserOrgSortCreatedAt, port.UserOrgSortMemberCount:
			orderBy = port.UserOrgSortField(raw)
		default:
			return "", "", domain.NewError("invalid_input", "orderBy must be name, created_at, or member_count")
		}
	}
	direction, err := parseSortDirection(query, port.SortAscending)
	return orderBy, direction, err
}

func parseOrgSort(query url.Values) (port.OrgSortField, port.SortDirection, error) {
	orderBy := port.OrgSortName
	if raw, supplied := sortQueryValue(query, "orderBy"); supplied {
		switch port.OrgSortField(raw) {
		case port.OrgSortName, port.OrgSortCreatedAt, port.OrgSortMemberCount:
			orderBy = port.OrgSortField(raw)
		default:
			return "", "", domain.NewError("invalid_input", "orderBy must be name, created_at, or member_count")
		}
	}
	direction, err := parseSortDirection(query, port.SortAscending)
	return orderBy, direction, err
}

func parseOrgInviteSort(query url.Values) (port.OrgInviteSortField, port.SortDirection, error) {
	orderBy := port.OrgInviteSortCreatedAt
	if raw, supplied := sortQueryValue(query, "orderBy"); supplied {
		switch port.OrgInviteSortField(raw) {
		case port.OrgInviteSortCreatedAt, port.OrgInviteSortExpiresAt, port.OrgInviteSortEmail, port.OrgInviteSortRole:
			orderBy = port.OrgInviteSortField(raw)
		default:
			return "", "", domain.NewError("invalid_input", "orderBy must be created_at, expires_at, email, or role")
		}
	}
	direction, err := parseSortDirection(query, port.SortDescending)
	return orderBy, direction, err
}
