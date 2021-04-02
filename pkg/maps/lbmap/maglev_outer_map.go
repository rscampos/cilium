// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lbmap

import (
	"unsafe"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/ebpf"
)

// maglevOuterMap is the internal representation of a maglev outer map.
type maglevOuterMap struct {
	*ebpf.Map
	TableSize uint32
}

// MaglevOuterKey is the key of a maglev outer map.
type MaglevOuterKey struct {
	RevNatID uint16
}

// MaglevOuterVal is the value of a maglev outer map.
type MaglevOuterVal struct {
	FD uint32
}

// NewMaglevOuterMap returns a new object representing a maglev outer map.
func NewMaglevOuterMap(name string, maxEntries int, tableSize uint32, innerMap *ebpf.MapSpec) (*maglevOuterMap, error) {
	m := ebpf.NewMap(&ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.HashOfMaps,
		KeySize:    uint32(unsafe.Sizeof(MaglevOuterKey{})),
		ValueSize:  uint32(unsafe.Sizeof(MaglevOuterVal{})),
		MaxEntries: uint32(maxEntries),
		InnerMap:   innerMap,
		Pinning:    ebpf.PinByName,
	})

	if err := m.OpenOrCreate(); err != nil {
		return nil, err
	}

	return &maglevOuterMap{
		Map:       m,
		TableSize: tableSize,
	}, nil
}

// MaglevOuterMapTableSize returns the maglev table size for a given maglev
// outer map (if the map exists).
func MaglevOuterMapTableSize(mapName string) (bool, uint32) {
	prevMap, err := ebpf.LoadPinnedMap(mapName)
	if err != nil {
		// No outer map found.
		return false, 0
	}
	defer prevMap.Close()

	var firstKey MaglevOuterKey
	err = prevMap.NextKey(nil, &firstKey)
	if err != nil {
		// The outer map exists but it's empty.
		// Return an invalid table size (0) so the caller can recreate
		// the outer map.
		return true, 0
	}

	var firstVal MaglevOuterVal
	err = prevMap.Lookup(&firstKey, &firstVal)
	if err != nil {
		// The outer map exists but we can't read the first entry.
		// Return an invalid table size (0) so the caller can recreate
		// the outer map.
		return true, 0
	}

	innerMap, err := ebpf.MapFromID(int(firstVal.FD))
	if err != nil {
		// The outer map exists but we can't access the inner map
		// associated with the first entry.
		// Return an invalid table size (0) so the caller can recreate
		// the outer map.
		return true, 0
	}
	defer innerMap.Close()

	return true, innerMap.ValueSize() / uint32(unsafe.Sizeof(uint16(0)))
}

// Update updates the value associated with a given key for a maglev outer map.
func (m *maglevOuterMap) Update(key *MaglevOuterKey, value *MaglevOuterVal) error {
	return m.Map.Update(key, value, 0)
}

// IterateCallback represents the signature of the callback function expected by
// the IterateWithCallback method, which in turn is used to iterate all the
// keys/values of a metrics map.
type MaglevOuterIterateCallback func(*MaglevOuterKey, *MaglevOuterVal)

// IterateWithCallback iterates through all the keys/values of a metrics map,
// passing each key/value pair to the cb callback
func (m maglevOuterMap) IterateWithCallback(cb MaglevOuterIterateCallback) error {
	return m.Map.IterateWithCallback(&MaglevOuterKey{}, &MaglevOuterVal{}, func(k, v interface{}) {
		key := k.(*MaglevOuterKey)
		value := v.(*MaglevOuterVal)

		cb(key, value)
	})
}

// ToNetwork converts a maglev outer map's key to network byte order.
func (k *MaglevOuterKey) ToNetwork() *MaglevOuterKey {
	n := *k
	// For some reasons rev_nat_index is stored in network byte order in
	// the SVC BPF maps
	n.RevNatID = byteorder.HostToNetwork(n.RevNatID).(uint16)
	return &n
}
