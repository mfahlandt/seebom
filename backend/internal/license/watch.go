package license

import "github.com/seebom-labs/bomhort/backend/internal/rulesource"

// ExceptionsWatcher keeps the license exceptions current (see rulesource).
type ExceptionsWatcher = rulesource.Watcher[*ExceptionIndex]

// WatchExceptions returns a watcher for the exceptions document described by
// opts. Nothing is fetched until the first Refresh.
func WatchExceptions(opts rulesource.Options) (*ExceptionsWatcher, error) {
	f, err := rulesource.New(opts)
	if err != nil {
		return nil, err
	}
	return rulesource.NewWatcher(f, func(data []byte) (*ExceptionIndex, error) {
		return ParseExceptions(data, f.Describe())
	}), nil
}
