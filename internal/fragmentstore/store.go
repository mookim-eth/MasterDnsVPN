// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package fragmentstore

import (
	"sync"
	"time"
)

type Store[K comparable] struct {
	mu        sync.Mutex
	capacity  int
	items     map[K]*entry
	completed map[K]time.Time
	lastPurge time.Time
}

type entry struct {
	createdAt      time.Time
	totalFragments uint8
	chunks         [256][]byte
	count          uint8
}

func New[K comparable](capacity int) *Store[K] {
	if capacity < 1 {
		capacity = 16
	}
	return &Store[K]{
		capacity:  capacity,
		items:     make(map[K]*entry, capacity),
		completed: make(map[K]time.Time, capacity),
	}
}

func (s *Store[K]) Collect(key K, payload []byte, fragmentID uint8, totalFragments uint8, now time.Time, retention time.Duration) ([]byte, bool, bool) {
	if totalFragments <= 1 {
		if retention <= 0 {
			return append([]byte(nil), payload...), true, false
		}

		s.mu.Lock()
		defer s.mu.Unlock()

		if now.Sub(s.lastPurge) >= time.Second {
			s.purgeLocked(now, retention)
			s.lastPurge = now
		}
		if expiresAt, ok := s.completed[key]; ok && now.Before(expiresAt) {
			return nil, false, true
		}

		delete(s.items, key)
		s.addCompletedLocked(key, now.Add(retention))
		return append([]byte(nil), payload...), true, false
	}

	if fragmentID >= totalFragments {
		return nil, false, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if now.Sub(s.lastPurge) >= time.Second {
		s.purgeLocked(now, retention)
		s.lastPurge = now
	}

	if expiresAt, ok := s.completed[key]; ok && now.Before(expiresAt) {
		return nil, false, true
	}

	current, ok := s.items[key]
	if !ok || current.totalFragments != totalFragments {
		if !ok {
			s.evictOldestItemsLocked(s.capacity - 1)
		}
		current = &entry{
			createdAt:      now,
			totalFragments: totalFragments,
		}
		s.items[key] = current
	}

	if current.chunks[fragmentID] == nil {
		current.count++
	}

	current.chunks[fragmentID] = append(current.chunks[fragmentID][:0], payload...)

	if current.count < totalFragments {
		return nil, false, false
	}

	totalSize := 0
	for idx := uint8(0); idx < totalFragments; idx++ {
		chunk := current.chunks[idx]
		if chunk == nil {
			return nil, false, false
		}
		totalSize += len(chunk)
	}

	assembled := make([]byte, 0, totalSize)
	for idx := uint8(0); idx < totalFragments; idx++ {
		assembled = append(assembled, current.chunks[idx]...)
	}

	delete(s.items, key)
	if retention > 0 {
		s.addCompletedLocked(key, now.Add(retention))
	} else {
		delete(s.completed, key)
	}
	return assembled, true, false
}

func (s *Store[K]) Purge(now time.Time, retention time.Duration) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.purgeLocked(now, retention)
	s.mu.Unlock()
}

func (s *Store[K]) Remove(key K) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.items, key)
	delete(s.completed, key)
	s.mu.Unlock()
}

func (s *Store[K]) RemoveIf(match func(K) bool) {
	if s == nil || match == nil {
		return
	}

	s.mu.Lock()
	for key := range s.items {
		if match(key) {
			delete(s.items, key)
		}
	}
	for key := range s.completed {
		if match(key) {
			delete(s.completed, key)
		}
	}
	s.mu.Unlock()
}

func (s *Store[K]) purgeLocked(now time.Time, retention time.Duration) {
	if retention <= 0 {
		for key := range s.items {
			delete(s.items, key)
		}
		for key := range s.completed {
			delete(s.completed, key)
		}
		return
	}

	deadline := now.Add(-retention)
	for key, current := range s.items {
		if current == nil || !current.createdAt.After(deadline) {
			delete(s.items, key)
		}
	}
	for key, expiresAt := range s.completed {
		if !now.Before(expiresAt) {
			delete(s.completed, key)
		}
	}
	s.evictOldestItemsLocked(s.capacity)
	s.evictEarliestCompletedLocked(s.capacity)
}

func (s *Store[K]) addCompletedLocked(key K, expiresAt time.Time) {
	if s == nil {
		return
	}
	if _, exists := s.completed[key]; !exists {
		s.evictEarliestCompletedLocked(s.capacity - 1)
	}
	s.completed[key] = expiresAt
}

func (s *Store[K]) evictOldestItemsLocked(maxEntries int) {
	if s == nil || maxEntries < 0 {
		return
	}
	for len(s.items) > maxEntries {
		var (
			oldestKey K
			oldestSet bool
			oldest    time.Time
		)
		for key, current := range s.items {
			if current == nil {
				delete(s.items, key)
				continue
			}
			if !oldestSet || current.createdAt.Before(oldest) {
				oldestKey = key
				oldest = current.createdAt
				oldestSet = true
			}
		}
		if !oldestSet {
			return
		}
		delete(s.items, oldestKey)
	}
}

func (s *Store[K]) evictEarliestCompletedLocked(maxEntries int) {
	if s == nil || maxEntries < 0 {
		return
	}
	for len(s.completed) > maxEntries {
		var (
			earliestKey K
			earliestSet bool
			earliest    time.Time
		)
		for key, expiresAt := range s.completed {
			if !earliestSet || expiresAt.Before(earliest) {
				earliestKey = key
				earliest = expiresAt
				earliestSet = true
			}
		}
		if !earliestSet {
			return
		}
		delete(s.completed, earliestKey)
	}
}
