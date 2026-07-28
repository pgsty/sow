package cli

// writeDerivedStateFile keeps the legacy error-only surface inside tests. All
// production callers consume the explicit replacement outcome.
func writeDerivedStateFile(stateRoot, relative string, body []byte) error {
	result, err := writeDerivedStateFileOutcome(stateRoot, relative, body)
	return consumeDerivedStateReplacement(result, err)
}

func writeOfflineArchiveProjectionIntent(stateRoot string, intent offlineArchiveProjectionIntent) error {
	result, err := writeOfflineArchiveProjectionIntentOutcome(stateRoot, intent)
	return consumeDerivedStateReplacement(result, err)
}
