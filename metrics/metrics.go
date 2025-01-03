package metrics

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

type Metrics struct {
	DurationOfVirusScanning time.Duration `json:"duration_of_virus_scanning"`
	FilesFailedToProcess    int           `json:"files_failed_to_process"`
	TotalFilesScanned       int           `json:"total_files_scanned"`
}

var (
	metrics Metrics
	mu      sync.Mutex
)

func UpdateMetrics(duration time.Duration, failed bool) {
	mu.Lock()
	defer mu.Unlock()
	metrics.DurationOfVirusScanning += duration
	metrics.TotalFilesScanned++
	if failed {
		metrics.FilesFailedToProcess++
	}
}

func MetricsHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	metricsCopy := metrics
	metricsCopy.DurationOfVirusScanning = metrics.DurationOfVirusScanning / time.Millisecond
	json.NewEncoder(w).Encode(metricsCopy)
}
