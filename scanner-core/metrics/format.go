package metrics

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"
)

// FormatPrometheus converts structured metrics data to Prometheus text format
func FormatPrometheus(data *MetricsData) string {
	var output strings.Builder

	for _, family := range data.Families {
		// Write HELP line
		fmt.Fprintf(&output, "# HELP %s %s\n", family.Name, family.Help)
		// Write TYPE line
		fmt.Fprintf(&output, "# TYPE %s %s\n", family.Name, family.Type)

		// Write each metric
		for _, metric := range family.Metrics {
			// Format labels
			labels := formatLabels(metric.Labels)
			fmt.Fprintf(&output, "%s{%s} %g\n", family.Name, labels, metric.Value)
		}
	}

	return output.String()
}

// WritePrometheus streams metrics data directly to a writer in Prometheus text format.
// This avoids buffering the entire output in memory, which is critical for large datasets.
func WritePrometheus(w io.Writer, data *MetricsData) error {
	bw := bufio.NewWriterSize(w, 64*1024) // 64KB buffer for efficient writes

	for _, family := range data.Families {
		if err := WritePrometheusFamily(bw, family); err != nil {
			return err
		}
	}

	return bw.Flush()
}

// WritePrometheusFamily writes a single metric family to a writer.
// This allows streaming one family at a time to minimize memory usage.
func WritePrometheusFamily(w io.Writer, family MetricFamily) error {
	// Write HELP line
	if _, err := fmt.Fprintf(w, "# HELP %s %s\n", family.Name, family.Help); err != nil {
		return err
	}
	// Write TYPE line
	if _, err := fmt.Fprintf(w, "# TYPE %s %s\n", family.Name, family.Type); err != nil {
		return err
	}

	// Write each metric
	for _, metric := range family.Metrics {
		labels := formatLabels(metric.Labels)
		if _, err := fmt.Fprintf(w, "%s{%s} %g\n", family.Name, labels, metric.Value); err != nil {
			return err
		}
	}

	return nil
}

// formatLabels converts a label map to Prometheus label string format
// Labels are sorted alphabetically for consistent output
func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}

	// Sort label keys for consistent output
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build label string
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := escapeLabelValue(labels[k])
		parts = append(parts, fmt.Sprintf(`%s="%s"`, k, v))
	}

	return strings.Join(parts, ",")
}

// escapeLabelValue escapes special characters in Prometheus label values
func escapeLabelValue(value string) string {
	// Escape backslash, newline, and double quote
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return value
}
