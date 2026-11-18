// Package stats computes capture summaries in one streaming pass using
// strictly bounded memory.
package stats

import "sort"

// Entry is one tracked item of a SpaceSaving sketch.
type Entry[K comparable] struct {
	Key   K
	Count uint64 // estimated weight (an upper bound on the true weight)
	Err   uint64 // maximum overestimation; Count-Err is a guaranteed lower bound
	idx   int
}

// SpaceSaving is the Metwally et al. heavy-hitter sketch: it tracks the top
// items of an unbounded stream in O(capacity) memory with a min-heap, giving
// O(log capacity) updates. Any item whose true weight exceeds total/capacity is
// guaranteed to be present.
type SpaceSaving[K comparable] struct {
	cap  int
	m    map[K]*Entry[K]
	heap []*Entry[K] // min-heap on Count
}

// NewSpaceSaving creates a sketch holding at most capacity distinct keys.
func NewSpaceSaving[K comparable](capacity int) *SpaceSaving[K] {
	if capacity < 1 {
		capacity = 1
	}
	return &SpaceSaving[K]{cap: capacity, m: make(map[K]*Entry[K], capacity)}
}

// Add credits weight w to key.
func (s *SpaceSaving[K]) Add(key K, w uint64) {
	if e, ok := s.m[key]; ok {
		e.Count += w
		s.down(e.idx)
		return
	}
	if len(s.heap) < s.cap {
		e := &Entry[K]{Key: key, Count: w, idx: len(s.heap)}
		s.m[key] = e
		s.heap = append(s.heap, e)
		s.up(e.idx)
		return
	}
	min := s.heap[0] // evict the smallest and inherit its count as error bound
	delete(s.m, min.Key)
	min.Err = min.Count
	min.Count += w
	min.Key = key
	s.m[key] = min
	s.down(0)
}

// Top returns up to n entries sorted by descending estimated weight.
func (s *SpaceSaving[K]) Top(n int) []Entry[K] {
	out := make([]Entry[K], 0, len(s.heap))
	for _, e := range s.heap {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// Len returns the number of tracked keys.
func (s *SpaceSaving[K]) Len() int { return len(s.heap) }

func (s *SpaceSaving[K]) swap(i, j int) {
	s.heap[i], s.heap[j] = s.heap[j], s.heap[i]
	s.heap[i].idx, s.heap[j].idx = i, j
}

func (s *SpaceSaving[K]) up(i int) {
	for i > 0 {
		p := (i - 1) / 2
		if s.heap[p].Count <= s.heap[i].Count {
			return
		}
		s.swap(i, p)
		i = p
	}
}

func (s *SpaceSaving[K]) down(i int) {
	n := len(s.heap)
	for {
		l, small := 2*i+1, i
		if l < n && s.heap[l].Count < s.heap[small].Count {
			small = l
		}
		if r := l + 1; r < n && s.heap[r].Count < s.heap[small].Count {
			small = r
		}
		if small == i {
			return
		}
		s.swap(i, small)
		i = small
	}
}
