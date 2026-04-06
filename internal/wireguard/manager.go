package wireguard

import (
	"sync"
	"time"
)

// DeviceManager manages multiple WireGuard devices (one per user)
type DeviceManager struct {
	devices     map[string]*managedDevice
	mu          sync.Mutex
	cacheTime   time.Duration
	stopChan    chan struct{}
	wg          sync.WaitGroup
}

type managedDevice struct {
	tun        *VirtualTun
	lastUsed   time.Time
	configHash string
}

// NewDeviceManager creates a new DeviceManager
func NewDeviceManager(cacheTime time.Duration) *DeviceManager {
	dm := &DeviceManager{
		devices:   make(map[string]*managedDevice),
		cacheTime: cacheTime,
		stopChan:  make(chan struct{}),
	}

	if cacheTime > 0 {
		dm.wg.Add(1)
		go dm.cleanupLoop()
	}

	return dm
}

// GetDevice gets or creates a WireGuard device for a user
func (dm *DeviceManager) GetDevice(username string, configContent string) (*VirtualTun, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	configHash := hashConfig(configContent)

	// Check if device exists and is up to date
	if md, ok := dm.devices[username]; ok {
		if md.configHash == configHash {
			md.lastUsed = time.Now()
			return md.tun, nil
		}
		// Config changed, close old device
		md.tun.Close()
		delete(dm.devices, username)
	}

	// Parse config
	config, err := ParseConfig(configContent)
	if err != nil {
		return nil, err
	}

	// Start new device
	tun, err := StartWireguard(config, 1) // LogLevelError
	if err != nil {
		return nil, err
	}

	md := &managedDevice{
		tun:        tun,
		lastUsed:   time.Now(),
		configHash: configHash,
	}

	dm.devices[username] = md
	return tun, nil
}

// ReloadUser reloads a user's device (if it exists)
func (dm *DeviceManager) ReloadUser(username string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if md, ok := dm.devices[username]; ok {
		md.tun.Close()
		delete(dm.devices, username)
	}
}

// RemoveUser removes and closes a user's device
func (dm *DeviceManager) RemoveUser(username string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if md, ok := dm.devices[username]; ok {
		md.tun.Close()
		delete(dm.devices, username)
	}
}

// Shutdown closes all devices and stops the manager
func (dm *DeviceManager) Shutdown() {
	close(dm.stopChan)
	dm.wg.Wait()

	dm.mu.Lock()
	defer dm.mu.Unlock()

	for username, md := range dm.devices {
		md.tun.Close()
		delete(dm.devices, username)
	}
}

func (dm *DeviceManager) cleanupLoop() {
	defer dm.wg.Done()

	ticker := time.NewTicker(dm.cacheTime)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dm.cleanup()
		case <-dm.stopChan:
			return
		}
	}
}

func (dm *DeviceManager) cleanup() {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	now := time.Now()
	for username, md := range dm.devices {
		if now.Sub(md.lastUsed) > dm.cacheTime {
			md.tun.Close()
			delete(dm.devices, username)
		}
	}
}

func hashConfig(content string) string {
	// Simple hash - we could use something better but this is fine for cache invalidation
	return string(content)
}
