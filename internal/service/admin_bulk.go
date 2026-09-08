package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/nazimdjebloun/go-auth/domain"
)

// maxBulkUserIDs caps a bulk request the same way Limit is capped elsewhere
// — go-auth has no atomic batch primitive, so a bulk call is N sequential
// single-user calls; an unbounded list would mean an unbounded number of
// queries per request.
const maxBulkUserIDs = 100

// BulkUserActionInput is the shared input shape for every Bulk*Users method.
type BulkUserActionInput struct {
	UserIDs []string
	ActorID string
}

func (input BulkUserActionInput) validate() error {
	if len(input.UserIDs) == 0 {
		return domain.NewError("invalid_input", "userIds must not be empty")
	}
	if len(input.UserIDs) > maxBulkUserIDs {
		return domain.NewError("invalid_input", fmt.Sprintf("at most %d userIds per bulk request", maxBulkUserIDs))
	}
	return nil
}

// BulkActionFailure reports why one user in a bulk request didn't succeed —
// Code is the same stable AuthError code a single-user call would return
// (e.g. "last_admin", "already_banned"), safe to match on.
type BulkActionFailure struct {
	UserID  string `json:"userId"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// BulkUserActionResult reports per-user outcome, not overall success — a
// bulk request is not transactional. Some users can succeed while others
// fail (already banned, last admin, not found); the caller must read both
// slices rather than treating a nil error as "all succeeded."
type BulkUserActionResult struct {
	Succeeded []string            `json:"succeeded"`
	Failed    []BulkActionFailure `json:"failed"`
}

func bulkFailure(userID string, err error) BulkActionFailure {
	var ae *domain.AuthError
	if errors.As(err, &ae) {
		return BulkActionFailure{UserID: userID, Code: ae.Code, Message: ae.Message}
	}
	return BulkActionFailure{UserID: userID, Code: "internal_error", Message: "Internal error"}
}

// BulkBanUsers bans each user independently by calling BanUser in a loop —
// not one atomic operation. A failure on one user (already banned, last
// admin) doesn't stop or roll back the rest.
func (s *AdminService) BulkBanUsers(ctx context.Context, input BulkUserActionInput) (*BulkUserActionResult, error) {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return nil, err
	}
	if err := input.validate(); err != nil {
		return nil, err
	}
	result := &BulkUserActionResult{Succeeded: []string{}, Failed: []BulkActionFailure{}}
	for _, id := range input.UserIDs {
		if err := s.BanUser(ctx, BanUserInput{UserID: id, ActorID: input.ActorID}); err != nil {
			result.Failed = append(result.Failed, bulkFailure(id, err))
			continue
		}
		result.Succeeded = append(result.Succeeded, id)
	}
	return result, nil
}

// BulkUnbanUsers is BulkBanUsers's counterpart — see its comment for the
// partial-failure contract.
func (s *AdminService) BulkUnbanUsers(ctx context.Context, input BulkUserActionInput) (*BulkUserActionResult, error) {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return nil, err
	}
	if err := input.validate(); err != nil {
		return nil, err
	}
	result := &BulkUserActionResult{Succeeded: []string{}, Failed: []BulkActionFailure{}}
	for _, id := range input.UserIDs {
		if err := s.UnbanUser(ctx, UnbanUserInput{UserID: id, ActorID: input.ActorID}); err != nil {
			result.Failed = append(result.Failed, bulkFailure(id, err))
			continue
		}
		result.Succeeded = append(result.Succeeded, id)
	}
	return result, nil
}

// BulkDeleteUsers is BulkBanUsers's counterpart for deletion — see its
// comment for the partial-failure contract.
func (s *AdminService) BulkDeleteUsers(ctx context.Context, input BulkUserActionInput) (*BulkUserActionResult, error) {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return nil, err
	}
	if err := input.validate(); err != nil {
		return nil, err
	}
	result := &BulkUserActionResult{Succeeded: []string{}, Failed: []BulkActionFailure{}}
	for _, id := range input.UserIDs {
		if err := s.DeleteUser(ctx, DeleteUserInput{UserID: id, ActorID: input.ActorID}); err != nil {
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
func (s *AdminService) BulkRevokeUserSessions(ctx context.Context, input BulkUserActionInput) (*BulkUserActionResult, error) {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return nil, err
	}
	if err := input.validate(); err != nil {
		return nil, err
	}
	result := &BulkUserActionResult{Succeeded: []string{}, Failed: []BulkActionFailure{}}
	for _, id := range input.UserIDs {
		if err := s.RevokeUserSessions(ctx, RevokeUserSessionsInput{UserID: id, ActorID: input.ActorID}); err != nil {
			result.Failed = append(result.Failed, bulkFailure(id, err))
			continue
		}
		result.Succeeded = append(result.Succeeded, id)
	}
	return result, nil
}
