package accounting

import (
	"sync"
	"time"
)

// Database interface for traffic accounting
type TrafficDB interface {
	RecordTraffic(userID uint, bytesUp, bytesDown uint64) error
}

// TrafficAccountant handles in-memory traffic stats and flushes to DB
type TrafficAccountant struct {
	db          TrafficDB
	mu          sync.Mutex
	userStats   map[uint]*userTraffic
	flushTicker *time.Ticker
	stopChan    chan struct{}
}

type userTraffic struct {
	bytesUp   uint64
	bytesDown uint64
}

// New creates a new TrafficAccountant
func New(db TrafficDB, flushInterval time.Duration) *TrafficAccountant {
	ta := &TrafficAccountant{
		db:        db,
		userStats: make(map[uint]*userTraffic),
		stopChan:  make(chan struct{}),
	}

	if flushInterval > 0 {
		ta.flushTicker = time.NewTicker(flushInterval)
		go ta.periodicFlush()
	}

	return ta
}

// RecordTraffic records traffic for a user
func (ta *TrafficAccountant) RecordTraffic(userID uint, bytesUp, bytesDown uint64) {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	stats, ok := ta.userStats[userID]
	if !ok {
		stats = &userTraffic{}
		ta.userStats[userID] = stats
	}

	stats.bytesUp += bytesUp
	stats.bytesDown += bytesDown
}

// Flush flushes all in-memory stats to the database
func (ta *TrafficAccountant) Flush() error {
	ta.mu.Lock()
	statsCopy := make(map[uint]*userTraffic, len(ta.userStats))
	for userID, stats := range ta.userStats {
		statsCopy[userID] = &userTraffic{
			bytesUp:   stats.bytesUp,
			bytesDown: stats.bytesDown,
		}
	}
	ta.userStats = make(map[uint]*userTraffic)
	ta.mu.Unlock()

	for userID, stats := range statsCopy {
		if err := ta.db.RecordTraffic(userID, stats.bytesUp, stats.bytesDown); err != nil {
			// Put back the stats that failed to flush
			ta.mu.Lock()
			if existing, ok := ta.userStats[userID]; ok {
				existing.bytesUp += stats.bytesUp
				existing.bytesDown += stats.bytesDown
			} else {
				ta.userStats[userID] = stats
			}
			ta.mu.Unlock()
			return err
		}
	}

	return nil
}

// Stop stops the periodic flushing and flushes remaining stats
func (ta *TrafficAccountant) Stop() error {
	close(ta.stopChan)
	if ta.flushTicker != nil {
		ta.flushTicker.Stop()
	}
	return ta.Flush()
}

func (ta *TrafficAccountant) periodicFlush() {
	for {
		select {
		case <-ta.flushTicker.C:
			_ = ta.Flush() // Ignore error, will retry next interval
		case <-ta.stopChan:
			return
		}
	}
}

// TrafficReader is an io.Reader that counts bytes read
type TrafficReader struct {
	reader   any
	onRead   func(n int)
}

// NewTrafficReader creates a new TrafficReader
func NewTrafficReader(reader any, onRead func(n int)) *TrafficReader {
	return &TrafficReader{reader: reader, onRead: onRead}
}

// TrafficWriter is an io.Writer that counts bytes written
type TrafficWriter struct {
	writer    any
	onWrite   func(n int)
}

// NewTrafficWriter creates a new TrafficWriter
func NewTrafficWriter(writer any, onWrite func(n int)) *TrafficWriter {
	return &TrafficWriter{writer: writer, onWrite: onWrite}
}

// WrapConn wraps a connection with traffic accounting
type WrapConn struct {
	conn     any
	accountant *TrafficAccountant
	userID   uint
}
