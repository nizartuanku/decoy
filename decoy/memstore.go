package decoy

import "sync"

// MemStore is an in-memory decoy Store for tests and ephemeral runs. Safe for
// concurrent use — the honeypot listeners and web callbacks write from many
// goroutines at once.
type MemStore struct {
	mu    sync.RWMutex
	deps  map[string]Deployment
	trips []Trip
}

// NewMemStore builds an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{deps: make(map[string]Deployment)}
}

func (m *MemStore) PutDeployment(d Deployment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deps[d.ID] = d
	return nil
}

func (m *MemStore) GetDeployment(id string) (Deployment, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.deps[id]
	return d, ok, nil
}

func (m *MemStore) ListDeployments() ([]Deployment, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Deployment, 0, len(m.deps))
	for _, d := range m.deps {
		out = append(out, d)
	}
	return out, nil
}

func (m *MemStore) DeleteDeployment(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.deps, id)
	return nil
}

func (m *MemStore) PutTrip(t Trip) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.trips = append(m.trips, t)
	return nil
}

func (m *MemStore) ListTrips() ([]Trip, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Trip, len(m.trips))
	copy(out, m.trips)
	return out, nil
}

func (m *MemStore) ListTripsFor(deploymentID string) ([]Trip, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Trip
	for _, t := range m.trips {
		if t.DeploymentID == deploymentID {
			out = append(out, t)
		}
	}
	return out, nil
}
