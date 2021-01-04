package registry

import (
	"fmt"
	"sync"

	"github.com/ghettovoice/gosip/sip"
)

// MemoryRegistry Address-of-Record registry using memory.
type MemoryRegistry struct {
	mutex *sync.Mutex
	aors  map[sip.Uri]map[string]*ContactInstance
}

func NewMemoryRegistry() *MemoryRegistry {
	mr := &MemoryRegistry{
		aors:  make(map[sip.Uri]map[string]*ContactInstance),
		mutex: new(sync.Mutex),
	}
	return mr
}

func (mr *MemoryRegistry) AddAor(aor sip.Uri, instance *ContactInstance) error {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()
	instances, _ := findInstances(mr.aors, aor)
	if instances != nil {
		(*instances)[instance.Source] = instance
		return nil
	} else {
		mr.aors[aor] = make(map[string]*ContactInstance)
	}
	mr.aors[aor][instance.Source] = instance
	return nil
}

func (mr *MemoryRegistry) RemoveAor(aor sip.Uri) error {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()
	for key := range mr.aors {
		if key.Equals(aor) {
			delete(mr.aors, key)
		}
	}
	return nil
}

func (mr *MemoryRegistry) AorIsRegistered(aor sip.Uri) bool {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()
	_, ok := mr.aors[aor]
	return ok
}

func (mr *MemoryRegistry) UpdateContact(aor sip.Uri, instance *ContactInstance) error {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()
	instances, err := findInstances(mr.aors, aor)
	if err != nil {
		return err
	}
	(*instances)[instance.Source] = instance
	return nil
}

func (mr *MemoryRegistry) RemoveContact(aor sip.Uri, instance *ContactInstance) error {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()
	instances, err := findInstances(mr.aors, aor)
	if instances != nil {
		delete(*instances, instance.Source)
		if len(*instances) == 0 {
			for key := range mr.aors {
				if key.Equals(aor) {
					delete(mr.aors, key)
				}
			}
		}
		return nil
	}
	return err
}

func (mr *MemoryRegistry) GetContacts(aor sip.Uri) (*map[string]*ContactInstance, bool) {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()
	instance, err := findInstances(mr.aors, aor)
	if err != nil {
		return nil, false
	}

	return instance, true
}

func (mr *MemoryRegistry) GetAllContacts() map[sip.Uri]map[string]*ContactInstance {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()
	return mr.aors
}

func findInstances(aors map[sip.Uri]map[string]*ContactInstance, aor sip.Uri) (*map[string]*ContactInstance, error) {
	for key, instances := range aors {
		if key.User() == aor.User() {
			return &instances, nil
		}
	}
	return nil, fmt.Errorf("Not found instances for %v", aor)
}
