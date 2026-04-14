package scanner

// StorageType indicates the physical storage medium.
type StorageType int

const (
	StorageUnknown StorageType = iota
	StorageSSD
	StorageHDD
)

func (s StorageType) String() string {
	switch s {
	case StorageSSD:
		return "SSD"
	case StorageHDD:
		return "HDD"
	default:
		return "Unknown"
	}
}
