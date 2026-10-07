package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
)

// maxBulkUserIDs caps a bulk request the same way Limit is capped elsewhere
// — go-auth has no atomic batch primitive, so a bulk call is N sequential
// single-user calls; an unbounded list would mean an unbounded number of
// queries per request.
const maxBulkUserIDs = 100

func validateBulkUserActionInput(input api.BulkUserActionInput) error {
	if len(input.UserIDs) == 0 {
		return domain.NewError("invalid_input", "userIds must not be empty")
	}
	if len(input.UserIDs) > maxBulkUserIDs {
		return domain.NewError("invalid_input", fmt.Sprintf("at most %d userIds per bulk request", maxBulkUserIDs))
	}
	return nil
}

func bulkFailure(userID string, err error) api.BulkActionFailure {
	var ae *domain.AuthError
	if errors.As(err, &ae) {
		return api.BulkActionFailure{UserID: userID, Code: ae.Code, Message: ae.Message}
	}
	return api.BulkActionFailure{UserID: userID, Code: "internal_error", Message: "Internal error"}
}

// BulkBanUsers bans each user independently by calling BanUser in a loop —
// not one atomic operation. A failure on one user (already banned, last
// admin) doesn't stop or roll back the rest.
func (s *AdminService) BulkBanUsers(ctx context.Context, input api.BulkUserActionInput) (*api.BulkUserActionResult, error) {
	if err := s.requireOperation(ctx, input.ActorID, input.ActorSessionID, "goauth.app.users.ban"); err != nil {
		return nil, err
	}
	if err := validateBulkUserActionInput(input); err != nil {
		return nil, err
	}
	result := &api.BulkUserActionResult{Succeeded: []string{}, Failed: []api.BulkActionFailure{}}
	for _, id := range input.UserIDs {
		if err := s.BanUser(ctx, api.BanUserInput{UserID: id, ActorID: input.ActorID,
			ActorSessionID: input.ActorSessionID}); err != nil {
			result.Failed = append(result.Failed, bulkFailure(id, err))
			continue
		}
		result.Succeeded = append(result.Succeeded, id)
	}
	return result, nil
}

// BulkUnbanUsers is BulkBanUsers's counterpart — see its comment for the
// partial-failure contract.
func (s *AdminService) BulkUnbanUsers(ctx context.Context, input api.BulkUserActionInput) (*api.BulkUserActionResult, error) {
	if err := s.requireOperation(ctx, input.ActorID, input.ActorSessionID, "goauth.app.users.unban"); err != nil {
		return nil, err
	}
	if err := validateBulkUserActionInput(input); err != nil {
		return nil, err
	}
	result := &api.BulkUserActionResult{Succeeded: []string{}, Failed: []api.BulkActionFailure{}}
	for _, id := range input.UserIDs {
		if err := s.UnbanUser(ctx, api.UnbanUserInput{UserID: id, ActorID: input.ActorID,
			ActorSessionID: input.ActorSessionID}); err != nil {
			result.Failed = append(result.Failed, bulkFailure(id, err))
			continue
		}
		result.Succeeded = append(result.Succeeded, id)
	}
	return result, nil
}

// BulkDeleteUsers is BulkBanUsers's counterpart for deletion — see its
// comment for the partial-failure contract.
func (s *AdminService) BulkDeleteUsers(ctx context.Context, input api.BulkUserActionInput) (*api.BulkUserActionResult, error) {
	if err := s.requireOperation(ctx, input.ActorID, input.ActorSessionID, "goauth.app.users.delete"); err != nil {
		return nil, err
	}
	if err := validateBulkUserActionInput(input); err != nil {
		return nil, err
	}
	result := &api.BulkUserActionResult{Succeeded: []string{}, Failed: []api.BulkActionFailure{}}
	for _, id := range input.UserIDs {
		if err := s.DeleteUser(ctx, api.DeleteUserInput{UserID: id, ActorID: input.ActorID,
			ActorSessionID: input.ActorSessionID}); err != nil {
			result.Failed = append(result.Failed, bulkFailure(id, err))
			continue
		}
		result.Succeeded = append(result.Succeeded, id)
	}
	return result, nil
}

// BulkRevokeUserSessions is BulkBanUsers's counterpart for a mass
// "sign everyone out" action — see its comment for the partial-failure
// contract.
func (s *AdminService) BulkRevokeUserSessions(ctx context.Context, input api.BulkUserActionInput) (*api.BulkUserActionResult, error) {
	if err := s.requireOperation(ctx, input.ActorID, input.ActorSessionID, "goauth.app.sessions.revoke"); err != nil {
		return nil, err
	}
	if err := validateBulkUserActionInput(input); err != nil {
		return nil, err
	}
	result := &api.BulkUserActionResult{Succeeded: []string{}, Failed: []api.BulkActionFailure{}}
	for _, id := range input.UserIDs {
		if err := s.RevokeUserSessions(ctx, api.RevokeUserSessionsInput{UserID: id, ActorID: input.ActorID,
			ActorSessionID: input.ActorSessionID}); err != nil {
			result.Failed = append(result.Failed, bulkFailure(id, err))
			continue
		}
		result.Succeeded = append(result.Succeeded, id)
	}
	return result, nil
}
