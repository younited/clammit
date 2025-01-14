package metrics

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"
)

type Metrics struct {
	DurationOfVirusScanningAverage time.Duration `json:"duration_of_virus_scanning_average"`
	DurationOfVirusScanningMedian  time.Duration `json:"duration_of_virus_scanning_median"`
	DurationOfVirusScanningP95     time.Duration `json:"duration_of_virus_scanning_p95"`
	DurationOfVirusScanningMax     time.Duration `json:"duration_of_virus_scanning_max"`
	FilesFailedToProcess           int           `json:"files_failed_to_process"`
	TotalFilesScanned              int           `json:"total_files_scanned"`
}

var (
	metrics   Metrics
	mu        sync.Mutex
	durations []time.Duration
)

func UpdateMetrics(duration time.Duration, failed bool, fileCount int) {
	mu.Lock()
	defer mu.Unlock()

	// Consider the total duration for multipart files as a single entry
	if fileCount > 1 {
		durations = append(durations, duration)
	} else {
		for i := 0; i < fileCount; i++ {
			durations = append(durations, duration/time.Duration(fileCount))
		}
	}
	metrics.TotalFilesScanned += fileCount

	if failed {
		metrics.FilesFailedToProcess++
	}
	updateDurationMetrics()
}

func updateDurationMetrics() {
	if len(durations) == 0 {
		return
	}

	sort.Slice(durations, func(i, j int) bool {
		return durations[i] < durations[j]
	})

	totalDuration := time.Duration(0)
	for _, d := range durations {
		totalDuration += d
	}

	metrics.DurationOfVirusScanningAverage = totalDuration / time.Duration(len(durations))
	metrics.DurationOfVirusScanningMedian = calcMedian(durations)
	metrics.DurationOfVirusScanningMax = durations[len(durations)-1]
	metrics.DurationOfVirusScanningP95 = calcP95(durations)
}

func calcMedian(durations []time.Duration) time.Duration {
	n := len(durations)
	if n == 0 {
		return 0
	}

	sort.Slice(durations, func(i, j int) bool {
		return durations[i] < durations[j]
	})

	middle := n / 2
	if n%2 == 0 {
		return (durations[middle-1] + durations[middle]) / 2
	}
	return durations[middle]
}

func calcP95(durations []time.Duration) time.Duration {
	n := len(durations)
	if n == 0 {
		return 0
	}

	index := int(float64(n) * 0.95)
	if index >= n {
		index = n - 1
	}
	return durations[index]
}

func MetricsHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	metricsCopy := metrics
	metricsCopy.DurationOfVirusScanningAverage = metrics.DurationOfVirusScanningAverage / time.Millisecond
	metricsCopy.DurationOfVirusScanningMedian = metrics.DurationOfVirusScanningMedian / time.Millisecond
	metricsCopy.DurationOfVirusScanningP95 = metrics.DurationOfVirusScanningP95 / time.Millisecond
	metricsCopy.DurationOfVirusScanningMax = metrics.DurationOfVirusScanningMax / time.Millisecond
	json.NewEncoder(w).Encode(metricsCopy)
}
