package memstore

import "time"

// nowFunc is a package-level indirection over time.Now so tests in this
// package can control time without threading a clock through every store.
var nowFunc = time.Now
