package service

func resolveMaxOrgsPerUser(configured int) int {
	if configured <= 0 {
		return 100
	}
	return configured
}
