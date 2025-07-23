package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/pqswitch/scanner/internal/types"
)

// GenerateSARIF generates a SARIF report from scan results
func GenerateSARIF(result *types.ScanResult) *sarif.Report {
	report, _ := sarif.New(sarif.Version210)

	// Create a run
	run := sarif.NewRunWithInformationURI("pqswitch-scanner", "https://github.com/pqswitch/scanner")
	version := result.Metadata.Version
	run.Tool.Driver.Version = &version
	informationURI := "https://github.com/pqswitch/scanner"
	run.Tool.Driver.InformationURI = &informationURI

	// Add rules
	ruleMap := make(map[string]*sarif.ReportingDescriptor)
	for _, finding := range result.Findings {
		if _, exists := ruleMap[finding.RuleID]; !exists {
			rule := sarif.NewRule(finding.RuleID)
			rule.Name = &finding.RuleID
			rule.ShortDescription = sarif.NewMultiformatMessageString(finding.Message)
			rule.FullDescription = sarif.NewMultiformatMessageString(finding.Message)

			// Set help text
			helpText := fmt.Sprintf("Suggestion: %s", finding.Suggestion)
			if len(finding.References) > 0 {
				helpText += "\n\nReferences:\n"
				for _, ref := range finding.References {
					helpText += fmt.Sprintf("- %s\n", ref)
				}
			}
			rule.Help = sarif.NewMultiformatMessageString(helpText)

			// Set severity level
			level := "warning"
			switch strings.ToLower(finding.Severity) {
			case "critical", "high":
				level = "error"
			case "medium":
				level = "warning"
			case "low", "info":
				level = "note"
			}
			rule.DefaultConfiguration = sarif.NewReportingConfiguration().WithLevel(level)

			ruleMap[finding.RuleID] = rule
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
		}
	}

	// Add results
	for _, finding := range result.Findings {
		sarifResult := sarif.NewRuleResult(finding.RuleID)
		sarifResult.Message = *sarif.NewTextMessage(finding.Message)

		// Set level
		level := "warning"
		switch strings.ToLower(finding.Severity) {
		case "critical", "high":
			level = "error"
		case "medium":
			level = "warning"
		case "low", "info":
			level = "note"
		}
		sarifResult.Level = &level

		// Add location
		location := sarif.NewPhysicalLocation()
		location.ArtifactLocation = sarif.NewSimpleArtifactLocation(finding.File)
		location.Region = sarif.NewSimpleRegion(finding.Line, finding.Column)

		sarifResult.Locations = []*sarif.Location{
			sarif.NewLocationWithPhysicalLocation(location),
		}

		// Add properties
		properties := make(map[string]interface{})
		properties["crypto_type"] = finding.CryptoType
		properties["algorithm"] = finding.Algorithm
		properties["confidence"] = finding.Confidence
		properties["suggestion"] = finding.Suggestion
		if finding.KeySize > 0 {
			properties["key_size"] = finding.KeySize
		}
		for k, v := range finding.Metadata {
			properties[k] = v
		}
		sarifResult.Properties = properties

		run.AddResult(sarifResult)
	}

	// Add run properties
	runProperties := make(map[string]interface{})
	runProperties["scan_path"] = result.Metadata.ScanPath
	runProperties["start_time"] = result.Metadata.StartTime.Format(time.RFC3339)
	runProperties["end_time"] = result.Metadata.EndTime.Format(time.RFC3339)
	runProperties["rules_loaded"] = result.Metadata.RulesLoaded
	runProperties["total_findings"] = result.Summary.TotalFindings
	runProperties["risk_score"] = result.Summary.RiskScore
	run.Properties = runProperties

	report.AddRun(run)
	return report
}

// GenerateHTML generates an HTML report from scan results
func GenerateHTML(result *types.ScanResult) string {
	tmpl := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PQSwitch Scanner Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .summary-card h3 {
            margin: 0 0 10px 0;
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .summary-card .value {
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }
        .risk-score {
            font-size: 3em !important;
        }
        .risk-high { color: #dc3545; }
        .risk-medium { color: #fd7e14; }
        .risk-low { color: #28a745; }
        .content {
            padding: 30px;
        }
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            color: #333;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        .findings-table th,
        .findings-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        .findings-table th {
            background: #f8f9fa;
            font-weight: 600;
            color: #666;
        }
        .findings-table tr:hover {
            background: #f8f9fa;
        }
        .severity {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.9em;
            font-weight: 500;
        }
        .severity-critical { background: #dc3545; color: white; }
        .severity-high { background: #fd7e14; color: white; }
        .severity-medium { background: #ffc107; color: #333; }
        .severity-low { background: #28a745; color: white; }
        .severity-info { background: #17a2b8; color: white; }
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>PQSwitch Scanner Report</h1>
            <p>Scan completed at {{.Metadata.EndTime.Format "2006-01-02 15:04:05"}}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Total Files</h3>
                <div class="value">{{.Summary.TotalFiles}}</div>
            </div>
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="value">{{.Summary.TotalFindings}}</div>
            </div>
            <div class="summary-card">
                <h3>Risk Score</h3>
                <div class="value risk-score {{if gt .Summary.RiskScore 0.7}}risk-high{{else if gt .Summary.RiskScore 0.3}}risk-medium{{else}}risk-low{{end}}">
                    {{printf "%.2f" .Summary.RiskScore}}
                </div>
            </div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>Findings by Severity</h2>
                <table class="findings-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range $severity, $count := .Summary.FindingsBySeverity}}
                        <tr>
                            <td><span class="severity severity-{{$severity}}">{{$severity}}</span></td>
                            <td>{{$count}}</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>Detailed Findings</h2>
                <table class="findings-table">
                    <thead>
                        <tr>
                            <th>File</th>
                            <th>Line</th>
                            <th>Severity</th>
                            <th>Message</th>
                            <th>Type</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .Findings}}
                        <tr>
                            <td>{{.File}}</td>
                            <td>{{.Line}}</td>
                            <td><span class="severity severity-{{.Severity}}">{{.Severity}}</span></td>
                            <td>{{.Message}}</td>
                            <td>{{.CryptoType}}</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by PQSwitch Scanner v{{.Metadata.Version}}</p>
        </div>
    </div>
</body>
</html>`

	t, err := template.New("report").Parse(tmpl)
	if err != nil {
		return fmt.Sprintf("Error generating HTML report: %v", err)
	}

	var buf strings.Builder
	if err := t.Execute(&buf, result); err != nil {
		return fmt.Sprintf("Error executing HTML template: %v", err)
	}

	return buf.String()
}

// GenerateJSON generates a JSON report from scan results
func GenerateJSON(result *types.ScanResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}

// GenerateMarkdown generates a Markdown report from scan results
func GenerateMarkdown(result *types.ScanResult) string {
	var buf strings.Builder

	// Header
	buf.WriteString("# PQSwitch Scanner Report\n\n")
	buf.WriteString(fmt.Sprintf("Scan completed at %s\n\n", result.Metadata.EndTime.Format("2006-01-02 15:04:05")))

	// Summary
	buf.WriteString("## Summary\n\n")
	buf.WriteString(fmt.Sprintf("- Total Files: %d\n", result.Summary.TotalFiles))
	buf.WriteString(fmt.Sprintf("- Total Findings: %d\n", result.Summary.TotalFindings))
	buf.WriteString(fmt.Sprintf("- Risk Score: %.2f\n\n", result.Summary.RiskScore))

	// Findings by Severity
	buf.WriteString("## Findings by Severity\n\n")
	for severity, count := range result.Summary.FindingsBySeverity {
		buf.WriteString(fmt.Sprintf("- %s: %d\n", severity, count))
	}
	buf.WriteString("\n")

	// Detailed Findings
	buf.WriteString("## Detailed Findings\n\n")
	for _, finding := range result.Findings {
		buf.WriteString(fmt.Sprintf("### %s\n\n", finding.Message))
		buf.WriteString(fmt.Sprintf("- File: %s\n", finding.File))
		buf.WriteString(fmt.Sprintf("- Line: %d\n", finding.Line))
		buf.WriteString(fmt.Sprintf("- Severity: %s\n", finding.Severity))
		buf.WriteString(fmt.Sprintf("- Type: %s\n", finding.CryptoType))
		if finding.Algorithm != "" {
			buf.WriteString(fmt.Sprintf("- Algorithm: %s\n", finding.Algorithm))
		}
		if finding.KeySize > 0 {
			buf.WriteString(fmt.Sprintf("- Key Size: %d\n", finding.KeySize))
		}
		if finding.Suggestion != "" {
			buf.WriteString(fmt.Sprintf("- Suggestion: %s\n", finding.Suggestion))
		}
		if len(finding.References) > 0 {
			buf.WriteString("- References:\n")
			for _, ref := range finding.References {
				buf.WriteString(fmt.Sprintf("  - %s\n", ref))
			}
		}
		buf.WriteString("\n")
	}

	return buf.String()
}

// GenerateCSV generates a CSV report from scan results
func GenerateCSV(result *types.ScanResult) string {
	var buf strings.Builder

	// Header
	buf.WriteString("File,Line,Severity,Message,Type,Algorithm,KeySize,Suggestion\n")

	// Findings
	for _, finding := range result.Findings {
		buf.WriteString(fmt.Sprintf("%s,%d,%s,%s,%s,%s,%d,%s\n",
			finding.File,
			finding.Line,
			finding.Severity,
			finding.Message,
			finding.CryptoType,
			finding.Algorithm,
			finding.KeySize,
			finding.Suggestion,
		))
	}

	return buf.String()
}

// GenerateExecutiveSummary generates a concise executive summary
func GenerateExecutiveSummary(result *types.ScanResult) string {
	var buf strings.Builder

	// Header
	buf.WriteString("# Executive Summary\n\n")
	buf.WriteString(fmt.Sprintf("Scan completed at %s\n\n", result.Metadata.EndTime.Format("2006-01-02 15:04:05")))

	// Risk Assessment
	buf.WriteString("## Risk Assessment\n\n")
	riskLevel := "Low"
	if result.Summary.RiskScore > 0.7 {
		riskLevel = "High"
	} else if result.Summary.RiskScore > 0.3 {
		riskLevel = "Medium"
	}
	buf.WriteString(fmt.Sprintf("Overall Risk Level: %s (Score: %.2f)\n\n", riskLevel, result.Summary.RiskScore))

	// Key Findings
	buf.WriteString("## Key Findings\n\n")
	buf.WriteString(fmt.Sprintf("- Total Files Scanned: %d\n", result.Summary.TotalFiles))
	buf.WriteString(fmt.Sprintf("- Total Issues Found: %d\n", result.Summary.TotalFindings))

	// Severity Breakdown
	buf.WriteString("\n### Severity Breakdown\n\n")
	for severity, count := range result.Summary.FindingsBySeverity {
		buf.WriteString(fmt.Sprintf("- %s: %d\n", severity, count))
	}

	// Recommendations
	buf.WriteString("\n## Recommendations\n\n")
	if result.Summary.TotalFindings == 0 {
		buf.WriteString("No security issues were found in the scanned codebase.\n")
	} else {
		buf.WriteString("Based on the scan results, we recommend:\n\n")
		if result.Summary.FindingsBySeverity["critical"] > 0 || result.Summary.FindingsBySeverity["high"] > 0 {
			buf.WriteString("1. Address critical and high severity findings immediately\n")
		}
		if result.Summary.FindingsBySeverity["medium"] > 0 {
			buf.WriteString("2. Review and remediate medium severity findings in the next sprint\n")
		}
		if result.Summary.FindingsBySeverity["low"] > 0 {
			buf.WriteString("3. Plan to address low severity findings in future updates\n")
		}
	}

	return buf.String()
}
