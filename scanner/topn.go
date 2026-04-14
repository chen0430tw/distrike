package scanner

import "container/heap"

// TopNHeap maintains the N largest DirEntry items using a min-heap.
// Memory usage is fixed at O(N) regardless of total file count.
type TopNHeap struct {
	entries []DirEntry
	n       int
}

func NewTopN(n int) *TopNHeap {
	return &TopNHeap{
		entries: make([]DirEntry, 0, n),
		n:       n,
	}
}

func (h *TopNHeap) Len() int           { return len(h.entries) }
func (h *TopNHeap) Less(i, j int) bool { return h.entries[i].SizeBytes < h.entries[j].SizeBytes }
func (h *TopNHeap) Swap(i, j int)      { h.entries[i], h.entries[j] = h.entries[j], h.entries[i] }

func (h *TopNHeap) Push(x any) {
	h.entries = append(h.entries, x.(DirEntry))
}

func (h *TopNHeap) Pop() any {
	old := h.entries
	n := len(old)
	item := old[n-1]
	h.entries = old[:n-1]
	return item
}

// Add inserts an entry, maintaining only the top N largest.
func (h *TopNHeap) Add(entry DirEntry) {
	if h.Len() < h.n {
		heap.Push(h, entry)
		return
	}
	if entry.SizeBytes > h.entries[0].SizeBytes {
		h.entries[0] = entry
		heap.Fix(h, 0)
	}
}

// Sorted returns entries sorted by size descending.
func (h *TopNHeap) Sorted() []DirEntry {
	result := make([]DirEntry, h.Len())
	copy(result, h.entries)
	// Sort descending
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result
}
