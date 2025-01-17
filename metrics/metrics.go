package metrics

import (
	"log"
	"sort"
	"sync"
	"time"

	"github.com/DataDog/datadog-go/v5/statsd"
)

type Metrics struct {
	FilesFailedToProcess int `json:"files_failed_to_process"`
	TotalFilesScanned    int `json:"total_files_scanned"`
	TotalVirusesFound    int `json:"total_viruses_found"`
}

var (
	metrics      Metrics
	mu           sync.Mutex
	durations    []time.Duration
	statsdClient *statsd.Client
)

func InitStatsdClient(address, namespace string, tags []string, log *log.Logger) {
	if address == "" {
		log.Println("StatsD address not provided, skipping initialization")
		return
	}
	var err error
	statsdClient, err = statsd.New(address, statsd.WithNamespace(namespace), statsd.WithTags(tags))
	if err != nil {
		log.Println("Failed to initialize StatsD client:", err)
		return
	}
	log.Println("StatsD client initialized successfully with tags:", tags)
}

func CloseStatsdClient(log *log.Logger) {
	if statsdClient != nil {
		statsdClient.Close()
		log.Println("StatsD client closed successfully")
	}
}

func UpdateMetrics(duration time.Duration, failed bool, fileCount int, virusesFound int, log *log.Logger) {
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
	metrics.TotalVirusesFound += virusesFound

	if failed {
		metrics.FilesFailedToProcess++
	}
	sendMetricsToDatadog(duration, fileCount, virusesFound, log)
}

func sendMetricsToDatadog(duration time.Duration, fileCount int, virusesFound int, log *log.Logger) {
	if statsdClient == nil {
		log.Println("StatsD client not initialized, skipping metrics sending")
		return
	}

	durations = append(durations, duration)
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	count := len(durations)
	sum := 0.0
	for _, d := range durations {
		sum += float64(d / time.Millisecond)
	}
	avg := sum / float64(count)
	median := float64(durations[count/2] / time.Millisecond)
	max := float64(durations[count-1] / time.Millisecond)
	p95 := float64(durations[int(float64(count)*0.95)] / time.Millisecond)

	// Send custom metrics
	statsdClient.Gauge("scan.response_time_avg", avg, nil, 1)
	statsdClient.Gauge("scan.response_time_median", median, nil, 1)
	statsdClient.Gauge("scan.response_time_max", max, nil, 1)
	statsdClient.Gauge("scan.response_time_p95", p95, nil, 1)

	// Send other metrics
	statsdClient.Count("scan.failed", int64(metrics.FilesFailedToProcess), nil, 1)
	statsdClient.Count("scan.processed", int64(fileCount), nil, 1)
	statsdClient.Count("scan.viruses_found", int64(virusesFound), nil, 1)
}
