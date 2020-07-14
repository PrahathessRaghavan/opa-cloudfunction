package opacf

import (
	"fmt"
	"context"
	"bytes"
	"errors"
	"regexp"
	"strings"
	"encoding/json"
	"io/ioutil"

	"github.com/spf13/viper"
	"github.com/open-policy-agent/opa/storage/inmem"

	"github.com/open-policy-agent/conftest/policy"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/topdown"
	"google.golang.org/api/iterator"
	gcs "cloud.google.com/go/storage"
    "github.com/rs/zerolog/log"
)

var (
	denyQ                 = regexp.MustCompile("^(deny|violation)(_[a-zA-Z0-9]+)*$")
	warnQ                 = regexp.MustCompile("^warn(_[a-zA-Z0-9]+)*$")
	combineConfigFlagName = "combine"
)
// PubSubMessage is the payload of a Pub/Sub event.
type PubSubMessage struct {
	Data []byte `json:"data"`
}

// Result describes the result of a single rule evaluation.
type Result struct {
	Message  string
	Metadata map[string]interface{}
	Traces   []error
}

func (r Result) Error() string {
	return r.Message
}

// CheckResult describes the result of a conftest evaluation.
// warning and failure "errors" produced by rego should be considered separate
// from other classes of exceptions.
type CheckResult struct {
	FileName   string
	Warnings   []Result
	Failures   []Result
	Exceptions []Result
	Successes  []Result
}

// NewResult creates a new result from the given message
func NewResult(message string, traces []error) Result {
	result := Result{
		Message:  message,
		Metadata: make(map[string]interface{}),
		Traces:   traces,
	}

	return result
}

// TestRun stores the compiler and store for a test run
type TestRun struct {
	Compiler *ast.Compiler
	Store    storage.Store
}

func OpaCF(ctx context.Context, m PubSubMessage) error {

policyBucket := "pr-policies"

// dataJson := `{
//     "protoPayload": {
//       "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
//       "status": {
//         "code": 7,
//         "message": "PERMISSION_DENIED"
//       },
//       "authenticationInfo": {
//         "principalEmail": "service-138029750974@container-engine-robot.iam.gserviceaccount.com"
//       },
//       "requestMetadata": {
//         "callerIp": "104.198.243.148",
//         "callerSuppliedUserAgent": "google-api-go-client/0.5 Kubernetes/1.14.10 (linux amd64),gzip(gfe)",
//         "requestAttributes": {
//           "time": "2020-03-02T16:41:47.126Z",
//           "auth": {}
//         },
//         "destinationAttributes": {}
//       },
//       "serviceName": "compute.googleapis.com",
//       "methodName": "v1.compute.firewalls.insert",
//       "authorizationInfo": [
//         {
//           "permission": "compute.firewalls.create",
//           "resourceAttributes": {
//             "service": "compute",
//             "name": "projects/corp-shared-vpc-host-project/global/firewalls/k8s-fw-a91a0a5495ca411eaa64942010abc002",
//             "type": "compute.firewalls"
//           }
//         },
//         {
//           "permission": "compute.networks.updatePolicy",
//           "resourceAttributes": {
//             "service": "compute",
//             "name": "projects/corp-shared-vpc-host-project/global/networks/corp-shared-vpc-network-10-128-0-0-14",
//             "type": "compute.networks"
//           }
//         }
//       ],
//       "resourceName": "projects/corp-shared-vpc-host-project/global/firewalls/a--test1--to--test2",
//       "request": {
//         "@type": "type.googleapis.com/compute.firewalls.insert",
//         "network": "https://www.googleapis.com/compute/v1/projects/corp-shared-vpc-host-project/global/networks/corp-shared-vpc-network-10-128-0-0-14",
//         "sourceRanges": [
//           "0.0.0.0/0"
//         ],
//         "description": "{\"kubernetes.io/service-name\":\"istio-system/istio-ingressgateway\", \"kubernetes.io/service-ip\":\"35.223.96.215\"}",
//         "alloweds": [
//           {
//             "IPProtocol": "tcp",
//             "ports": [
//               "15020",
//               "80",
//               "443",
//               "31400",
//               "15029",
//               "15030",
//               "15031",
//               "15032",
//               "15443"
//             ]
//           }
//         ],
//         "targetTags": [
//           "gke-ck-paas-gke-3-9c6aaee4-node"
//         ],
//         "name": "k8s-fw-a91a0a5495ca411eaa64942010abc002"
//       },
//       "response": {
//         "@type": "type.googleapis.com/error",
//         "error": {
//           "errors": [
//             {
//               "reason": "forbidden",
//               "message": "Required 'compute.firewalls.create' permission for 'projects/corp-shared-vpc-host-project/global/firewalls/k8s-fw-a91a0a5495ca411eaa64942010abc002'",
//               "domain": "global"
//             }
//           ],
//           "code": 403,
//           "message": "Required 'compute.firewalls.create' permission for 'projects/corp-shared-vpc-host-project/global/firewalls/k8s-fw-a91a0a5495ca411eaa64942010abc002'"
//         }
//       },
//       "resourceLocation": {
//         "currentLocations": [
//           "global"
//         ]
//       }
//     },
//     "insertId": "32f48mdv5xo",
//     "resource": {
//       "type": "gce_firewall_rule",
//       "labels": {
//         "project_id": "corp-shared-vpc-host-project",
//         "firewall_rule_id": ""
//       }
//     },
//     "timestamp": "2020-03-02T16:41:46.931Z",
//     "severity": "ERROR",
//     "logName": "projects/corp-shared-vpc-host-project/logs/cloudaudit.googleapis.com%2Factivity",
//     "receiveTimestamp": "2020-03-02T16:41:47.663518158Z"
//   }`
 dataJson := string(m.Data)

policies,err := downloadPolicies(policyBucket)
if err != nil {
	log.Printf("unable to read policy files: %w", err)
}


compiler, err := getCompiler(policies)
			if err != nil {
				 log.Printf("build compiler: %w", err)
			}
store := inmem.NewFromReader(bytes.NewBufferString(dataJson))		
testRun := TestRun{
				Compiler: compiler,
				Store:    store,
			}
var namespaces []string

namespaces = []string {"main"}
var jsonConfig interface{}
	err = json.Unmarshal([]byte(dataJson), &jsonConfig)
	if err != nil {
		log.Printf("could not unmarshal yaml: %s", err)
	}
result, err := testRun.GetResult(ctx, namespaces, jsonConfig)
				if err != nil {
					 log.Printf("get combined test result: %w", err)
				}
log.Print(result.Failures)
return nil
}
// GetResult returns the result of testing the structured data against their policies
func (t TestRun) GetResult(ctx context.Context, namespaces []string, input interface{}) (CheckResult, error) {
	var totalWarnings []Result
	var totalFailures []Result
	var totalExceptions []Result
	var totalSuccesses []Result

	for _, namespace := range namespaces {
		warnings, warnExceptions, successes, err := t.runRules(ctx, namespace, input, warnQ)
		if err != nil {
			return CheckResult{}, fmt.Errorf("running warn rules: %w", err)
		}
		totalSuccesses = append(totalSuccesses, successes...)

		failures, denyExceptions, successes, err := t.runRules(ctx, namespace, input, denyQ)
		if err != nil {
			return CheckResult{}, fmt.Errorf("running deny rules: %w", err)
		}
		totalSuccesses = append(totalSuccesses, successes...)

		totalFailures = append(totalFailures, failures...)
		totalWarnings = append(totalWarnings, warnings...)
		totalExceptions = append(totalExceptions, warnExceptions...)
		totalExceptions = append(totalExceptions, denyExceptions...)
	}

	result := CheckResult{
		Warnings:   totalWarnings,
		Failures:   totalFailures,
		Exceptions: totalExceptions,
		Successes:  totalSuccesses,
	}

	return result, nil
}

func (t TestRun) runRules(ctx context.Context, namespace string, input interface{}, regex *regexp.Regexp) ([]Result, []Result, []Result, error) {
	var successes []Result
	var exceptions []Result
	var errors []Result

	var rules []string
	var numberRules int = 0
	for _, module := range t.Compiler.Modules {
		currentNamespace := strings.Replace(module.Package.Path.String(), "data.", "", 1)
		if currentNamespace == namespace {
			for _, rule := range module.Rules {
				ruleName := rule.Head.Name.String()

				if regex.MatchString(ruleName) {
					numberRules += 1
					if !stringInSlice(ruleName, rules) {
						rules = append(rules, ruleName)
					}
				}
			}
		}
	}

	var err error
	var totalErrors []Result
	var totalExceptions []Result
	var totalSuccesses []Result
	for _, rule := range rules {
		query := fmt.Sprintf("data.%s.%s", namespace, rule)

		switch input.(type) {
		case []interface{}:
			exceptionQuery := fmt.Sprintf("data.%s.exception[_][_] == %q", namespace, removeDenyPrefix(rule))
			errors, exceptions, successes, err = t.runMultipleQueries(ctx, query, exceptionQuery, input)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("run multiple queries: %w", err)
			}
		default:
			errors, successes, err = t.runQuery(ctx, query, input)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("run query: %w", err)
			}
		}

		totalErrors = append(totalErrors, errors...)
		totalExceptions = append(totalExceptions, exceptions...)
		totalSuccesses = append(totalSuccesses, successes...)
	}

	for i := len(totalErrors) + len(totalSuccesses); i < numberRules; i++ {
		totalSuccesses = append(totalSuccesses, Result{})
	}

	return totalErrors, totalExceptions, totalSuccesses, nil
}

func removeDenyPrefix(rule string) string {
	if strings.HasPrefix(rule, "deny_") {
		return strings.TrimPrefix(rule, "deny_")
	} else if strings.HasPrefix(rule, "violation_") {
		return strings.TrimPrefix(rule, "violation_")
	}
	return rule
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}

	return false
}

func (t TestRun) runMultipleQueries(ctx context.Context, query string, exceptionQuery string, inputs interface{}) ([]Result, []Result, []Result, error) {
	var totalViolations []Result
	var totalExceptions []Result
	var totalSuccesses []Result
	for _, input := range inputs.([]interface{}) {
		violations, successes, err := t.runQuery(ctx, query, input)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("run query: %w", err)
		}
		_, exceptions, err := t.runQuery(ctx, exceptionQuery, input)
		if len(exceptions) > 0 {
			totalExceptions = append(totalExceptions, exceptions...)
		} else {
			totalViolations = append(totalViolations, violations...)
		}
		totalSuccesses = append(totalSuccesses, successes...)
	}
	return totalViolations, totalExceptions, totalSuccesses, nil
}

func (t TestRun) runQuery(ctx context.Context, query string, input interface{}) ([]Result, []Result, error) {
	rego, stdout := t.buildRego(viper.GetBool("trace"), query, input)
	resultSet, err := rego.Eval(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("evaluating policy: %w", err)
	}

	buf := new(bytes.Buffer)
	topdown.PrettyTrace(buf, *stdout)
	var traces []error
	for _, line := range strings.Split(buf.String(), "\n") {
		if len(line) > 0 {
			traces = append(traces, errors.New(line))
		}
	}

	hasResults := func(expression interface{}) bool {
		if v, ok := expression.([]interface{}); ok {
			return len(v) > 0
		}

		return false
	}

	var errs []Result
	var successes []Result
	for _, result := range resultSet {
		for _, expression := range result.Expressions {
			if !hasResults(expression.Value) {
				successes = append(successes, NewResult(expression.Text, traces))
				continue
			}

			for _, v := range expression.Value.([]interface{}) {
				switch val := v.(type) {
				case string:
					errs = append(errs, NewResult(val, traces))
				case map[string]interface{}:
					if _, ok := val["msg"]; !ok {
						return nil, nil, fmt.Errorf("rule missing msg field: %v", val)
					}
					if _, ok := val["msg"].(string); !ok {
						return nil, nil, fmt.Errorf("msg field must be string: %v", val)
					}

					result := NewResult(val["msg"].(string), traces)
					for k, v := range val {
						if k != "msg" {
							result.Metadata[k] = v
						}

					}
					errs = append(errs, result)
				}
			}
		}
	}

	return errs, successes, nil
}

func (t TestRun) buildRego(trace bool, query string, input interface{}) (*rego.Rego, *topdown.BufferTracer) {
	var regoObj *rego.Rego
	var regoFunc []func(r *rego.Rego)
	buf := topdown.NewBufferTracer()
	runtime := policy.RuntimeTerm()

	regoFunc = append(regoFunc, rego.Query(query), rego.Compiler(t.Compiler), rego.Input(input), rego.Store(t.Store), rego.Runtime(runtime))
	if trace {
		regoFunc = append(regoFunc, rego.Tracer(buf))
	}

	regoObj = rego.New(regoFunc...)

	return regoObj, buf
}




//StorageRead read stuff from GCS
func StorageRead(bucket, object string, client *gcs.Client) ([]byte, error) {
	ctx := context.Background()
	// [START download_file]
	rc, err := client.Bucket(bucket).Object(object).NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	data, err := ioutil.ReadAll(rc)
	if err != nil {
		return nil, err
	}
	return data, nil
	// [END download_file]
}

func downloadPolicies(bucket string) ([]string , error){
	ctx := context.Background()
	policies := []string {}
	client, err := gcs.NewClient(ctx)
	if err != nil {
		fmt.Println(err)
		log.Print(err)
		
	}
	fmt.Println("Storage client created")
	
   
	// [START storage_list_files]
	it := client.Bucket(bucket).Objects(ctx, nil)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			fmt.Println(err)
			log.Print(err)
			
		}
		fmt.Println(attrs.Name)
	
		tempFile, err := StorageRead(bucket, attrs.Name, client)
		if err != nil {
				fmt.Println(err)
				log.Print(err)
				break
			}
			policies = append(policies, string(tempFile))
		 
	}
	fmt.Println("All policies have been locally downloaded to memory")
	// [END storage_list_files]
	return policies,nil

}


const (

	outputJSON  = "json"

)

// ValidOutputs returns the available output formats for reporting tests
func ValidOutputs() []string {
	return []string{
		outputJSON,
	}
	
}

// GetOutputManager returns the OutputManager based on the user input
func GetOutputManager(outputFormat string, color bool) OutputManager {

		return NewDefaultJSONOutputManager()
	
}

// OutputManager controls how results of an evaluation will be recorded and reported to the end user
type OutputManager interface {
	Put(cr CheckResult) error
	Flush() error
}


// NewDefaultStandardOutputManager creates a new StandardOutputManager using the default logger


// Put puts the result of the check to the manager in the managers buffer
type jsonResult struct {
	Message  string                 `json:"msg"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	Traces   []string               `json:"traces,omitempty"`
}

type jsonCheckResult struct {
	Filename  string       `json:"filename"`
	Warnings  []jsonResult `json:"warnings"`
	Failures  []jsonResult `json:"failures"`
	Successes []jsonResult `json:"successes"`
}

// JSONOutputManager formats its output to JSON
type JSONOutputManager struct {
	data   []jsonCheckResult
}

// NewDefaultJSONOutputManager creates a new JSONOutputManager using the default logger
func NewDefaultJSONOutputManager() *JSONOutputManager {
	return NewJSONOutputManager()
}

// NewJSONOutputManager creates a new JSONOutputManager with a given logger instance
func NewJSONOutputManager() *JSONOutputManager {
	return &JSONOutputManager{
	}
}

func errsToStrings(errs []error) []string {
	res := []string{}
	for _, err := range errs {
		res = append(res, err.Error())
	}
	return res
}

// Put puts the result of the check to the manager in the managers buffer
func (j *JSONOutputManager) Put(cr CheckResult) error {
	if cr.FileName == "-" {
		cr.FileName = ""
	}

	result := jsonCheckResult{
		Filename:  cr.FileName,
		Warnings:  []jsonResult{},
		Failures:  []jsonResult{},
		Successes: []jsonResult{},
	}

	for _, warning := range cr.Warnings {
		result.Warnings = append(result.Warnings, jsonResult{
			Message:  warning.Message,
			Metadata: warning.Metadata,
			Traces:   errsToStrings(warning.Traces),
		})
	}

	for _, failure := range cr.Failures {
		result.Failures = append(result.Failures, jsonResult{
			Message:  failure.Message,
			Metadata: failure.Metadata,
			Traces:   errsToStrings(failure.Traces),
		})
	}

	for _, successes := range cr.Successes {
		result.Successes = append(result.Successes, jsonResult{
			Message:  successes.Message,
			Metadata: successes.Metadata,
			Traces:   errsToStrings(successes.Traces),
		})
	}

	j.data = append(j.data, result)

	return nil
}

// Flush writes the contents of the managers buffer to the console
func (j *JSONOutputManager) Flush() error {
	b, err := json.Marshal(j.data)
	if err != nil {
		return err
	}

	var out bytes.Buffer
	err = json.Indent(&out, b, "", "\t")
	if err != nil {
		return err
	}

	log.Print(out.String())
	return nil
}

func getCompiler(files []string) (*ast.Compiler, error) {
	modules := map[string]*ast.Module{}

	for _, file := range files {

		parsed, err := ast.ParseModule("test",file)
		if err != nil {
			return nil, fmt.Errorf("parse module: %w", err)
		}

		modules[file] = parsed
	}

	compiler := ast.NewCompiler()
	compiler.Compile(modules)
	if compiler.Failed() {
		return nil, fmt.Errorf("compiling: %w", compiler.Errors)
	}

	return compiler, nil
}