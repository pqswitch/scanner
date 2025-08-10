package ml

import (
	"math"
	"strings"
)

// MLModels contains all converted ML models
type MLModels struct {
	FalsePositiveDetector *LogisticRegressionModel
	ConfidencePredictor   *RandomForestModel
	SeverityClassifier    *RandomForestModel
	Encoders              map[string]*LabelEncoder
}

// LogisticRegressionModel represents a logistic regression model
type LogisticRegressionModel struct {
	Coefficients []float64
	Intercept    float64
	Classes      []int
	NFeatures    int
}

// RandomForestModel represents a simplified random forest model
type RandomForestModel struct {
	FeatureImportances []float64
	Classes            []string
	NFeatures          int
	NEstimators        int
}

// LabelEncoder represents a label encoder
type LabelEncoder struct {
	LabelToInt map[string]int
	IntToLabel map[int]string
	NClasses   int
}

// Predict using logistic regression
func (lr *LogisticRegressionModel) Predict(features []float64) float64 {
	if len(features) != lr.NFeatures {
		return 0.0
	}

	// Calculate linear combination
	linearCombination := lr.Intercept
	for i, coef := range lr.Coefficients {
		if i < len(features) {
			linearCombination += coef * features[i]
		}
	}

	// Apply sigmoid function
	return 1.0 / (1.0 + math.Exp(-linearCombination))
}

// PredictClass using random forest (simplified)
func (rf *RandomForestModel) PredictClass(features []float64) string {
	if len(features) != rf.NFeatures || len(rf.Classes) == 0 {
		return "unknown"
	}

	// Simplified prediction based on feature importances
	score := 0.0
	for i, importance := range rf.FeatureImportances {
		if i < len(features) {
			score += importance * features[i]
		}
	}

	// Map score to class (simplified)
	if score > 0.5 {
		return rf.Classes[len(rf.Classes)-1] // Return highest class
	}
	return rf.Classes[0] // Return lowest class
}

// Encode converts a string label to integer
func (le *LabelEncoder) Encode(label string) int {
	if val, exists := le.LabelToInt[label]; exists {
		return val
	}
	return 0 // Default to 0 for unknown labels
}

// Decode converts an integer to string label
func (le *LabelEncoder) Decode(value int) string {
	if label, exists := le.IntToLabel[value]; exists {
		return label
	}
	return "unknown"
}

// NewMLModels creates a new MLModels instance with trained models
func NewMLModels() *MLModels {
	return &MLModels{
		FalsePositiveDetector: &LogisticRegressionModel{
			Coefficients: []float64{-0.023360, -0.375178, 1.148658, -0.013398, 0.000000, 0.051287, 0.000054, -0.095136, -0.068401, -0.027441, -1.076803, -0.457554, -1.347710, 0.000000, 0.000000, 0.000000, 0.581829, 0.000000, 0.026293, 0.000000, 0.000000, 1.089180, 1.601141, -0.988160, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000},
			Intercept:    5.003588,
			Classes:      []int{0, 1},
			NFeatures:    29,
		},
		ConfidencePredictor: &RandomForestModel{
			FeatureImportances: []float64{0.036907, 0.024339, 0.368220, 0.016651, 0.000000, 0.027167, 0.154834, 0.060193, 0.125240, 0.077752, 0.022151, 0.027699, 0.006278, 0.000000, 0.000000, 0.000000, 0.007998, 0.000000, 0.005814, 0.000000, 0.000000, 0.011280, 0.021723, 0.005752, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000},
			Classes:            []string{"high", "medium"},
			NFeatures:          29,
			NEstimators:        5,
		},
		SeverityClassifier: &RandomForestModel{
			FeatureImportances: []float64{0.063584, 0.102103, 0.073065, 0.050864, 0.000000, 0.054103, 0.143723, 0.015611, 0.033139, 0.056853, 0.005246, 0.013137, 0.018602, 0.000000, 0.000000, 0.000000, 0.011673, 0.000000, 0.005023, 0.000000, 0.000000, 0.076796, 0.170800, 0.105678, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000},
			Classes:            []string{"critical", "high", "info", "medium"},
			NFeatures:          29,
			NEstimators:        5,
		},
		Encoders: map[string]*LabelEncoder{
			"algorithm": {
				LabelToInt: map[string]int{"AES": 0, "ECDH": 1, "ECDSA": 2, "FALCON": 3, "MD5": 4, "RSA": 5, "SHA1": 6, "SPHINCS": 7},
				IntToLabel: map[int]string{0: "AES", 1: "ECDH", 2: "ECDSA", 3: "FALCON", 4: "MD5", 5: "RSA", 6: "SHA1", 7: "SPHINCS"},
				NClasses:   8,
			},
			"severity": {
				LabelToInt: map[string]int{"critical": 0, "high": 1, "medium": 2},
				IntToLabel: map[int]string{0: "critical", 1: "high", 2: "medium"},
				NClasses:   3,
			},
			"crypto_type": {
				LabelToInt: map[string]int{"asymmetric": 0, "crypto_usage": 1, "hash": 2, "key_agreement": 3, "key_generation": 4, "post_quantum": 5, "signature": 6},
				IntToLabel: map[int]string{0: "asymmetric", 1: "crypto_usage", 2: "hash", 3: "key_agreement", 4: "key_generation", 5: "post_quantum", 6: "signature"},
				NClasses:   7,
			},
			"language": {
				LabelToInt: map[string]int{"unknown": 0},
				IntToLabel: map[int]string{0: "unknown"},
				NClasses:   1,
			},
			"rule_id": {
				LabelToInt: map[string]int{"dotnet-rsa-keygen": 0, "go-ecdsa-keygen": 1, "go-rsa-keygen": 2, "java-ecdh-usage": 3, "java-rsa-keygen": 4, "l0-crypto-functions": 5, "l0-key-generation": 6, "l0-pq-algorithms": 7, "openssl-ecdh-usage": 8, "openssl-rsa-keygen": 9, "python-rsa-usage": 10, "rust-ecdsa-usage": 11, "weak-hash-md5": 12, "weak-hash-sha1": 13, "weak-rsa-keylength": 14},
				IntToLabel: map[int]string{0: "dotnet-rsa-keygen", 1: "go-ecdsa-keygen", 2: "go-rsa-keygen", 3: "java-ecdh-usage", 4: "java-rsa-keygen", 5: "l0-crypto-functions", 6: "l0-key-generation", 7: "l0-pq-algorithms", 8: "openssl-ecdh-usage", 9: "openssl-rsa-keygen", 10: "python-rsa-usage", 11: "rust-ecdsa-usage", 12: "weak-hash-md5", 13: "weak-hash-sha1", 14: "weak-rsa-keylength"},
				NClasses:   15,
			},
			"file_extension": {
				LabelToInt: map[string]int{"c": 0, "cc": 1, "cmake": 2, "cpp": 3, "cs": 4, "go": 5, "h": 6, "java": 7, "js": 8, "patch": 9, "py": 10, "repos/bc-java/buildj2me": 11, "rs": 12},
				IntToLabel: map[int]string{0: "c", 1: "cc", 2: "cmake", 3: "cpp", 4: "cs", 5: "go", 6: "h", 7: "java", 8: "js", 9: "patch", 10: "py", 11: "repos/bc-java/buildj2me", 12: "rs"},
				NClasses:   13,
			},
		},
	}
}

// getString gets a string value from the finding map.
func getString(finding map[string]interface{}, key string) string {
	if val, ok := finding[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return "unknown"
}

// getFloat gets a float value from the finding map.
func getFloat(finding map[string]interface{}, key string) float64 {
	if val, ok := finding[key]; ok {
		if f, ok := val.(float64); ok {
			return f
		}
	}
	return 0.0
}

func extractCategoricalFeatures(finding map[string]interface{}, encoders map[string]*LabelEncoder, features []float64) {
	algorithm := getString(finding, "algorithm")
	severity := getString(finding, "severity")
	cryptoType := getString(finding, "crypto_type")
	language := getString(finding, "language")
	ruleID := getString(finding, "rule_id")

	features[0] = float64(encoders["algorithm"].Encode(algorithm))
	features[1] = float64(encoders["severity"].Encode(severity))
	features[2] = getFloat(finding, "confidence")
	features[3] = float64(encoders["crypto_type"].Encode(cryptoType))
	features[4] = float64(encoders["language"].Encode(language))
	features[5] = float64(encoders["rule_id"].Encode(ruleID))
	features[6] = getFloat(finding, "line")
}

func extractFileFeatures(finding map[string]interface{}, encoders map[string]*LabelEncoder, features []float64) {
	file := getString(finding, "file")

	fileExt := "unknown"
	if file != "" && strings.Contains(file, ".") {
		parts := strings.Split(file, ".")
		fileExt = parts[len(parts)-1]
	}
	features[7] = float64(encoders["file_extension"].Encode(fileExt))

	features[8] = float64(len(strings.Split(file, "/")))

	features[9] = float64(len(file))

	features[10] = getBool(strings.Contains(strings.ToLower(file), "test"))
	features[11] = getBool(strings.Contains(strings.ToLower(file), "crypto") ||
		strings.Contains(strings.ToLower(file), "ssl") ||
		strings.Contains(strings.ToLower(file), "tls") ||
		strings.Contains(strings.ToLower(file), "hash"))
	features[12] = getBool(strings.HasSuffix(file, ".c") ||
		strings.HasSuffix(file, ".cpp") ||
		strings.HasSuffix(file, ".h") ||
		strings.HasSuffix(file, ".hpp"))
}

func extractPatternFeatures(finding map[string]interface{}, features []float64) {
	pattern := getString(finding, "pattern")
	features[13] = float64(len(pattern))
	features[14] = getBool(strings.Contains(pattern, "("))
	features[15] = getBool(strings.Contains(strings.ToLower(pattern), "import"))
}

func extractAlgorithmFeatures(finding map[string]interface{}, encoders map[string]*LabelEncoder, features []float64) {
	features[16] = getBool(encoders["crypto_type"].Encode(getString(finding, "crypto_type")) == 2) // crypto_type == "hash"
	features[17] = getBool(encoders["crypto_type"].Encode(getString(finding, "crypto_type")) == 1) // crypto_type == "crypto_usage"
	features[18] = getBool(encoders["crypto_type"].Encode(getString(finding, "crypto_type")) == 0) // crypto_type == "asymmetric"
	features[19] = getBool(encoders["algorithm"].Encode(getString(finding, "algorithm")) == 4 ||   // algorithm == "md5"
		encoders["algorithm"].Encode(getString(finding, "algorithm")) == 6 || // algorithm == "sha1"
		encoders["algorithm"].Encode(getString(finding, "algorithm")) == 5 || // algorithm == "des"
		encoders["algorithm"].Encode(getString(finding, "algorithm")) == 10) // algorithm == "rc4"
	features[20] = getBool(encoders["algorithm"].Encode(getString(finding, "algorithm")) == 6 || // algorithm == "sha256"
		encoders["algorithm"].Encode(getString(finding, "algorithm")) == 7 || // algorithm == "sha512"
		encoders["algorithm"].Encode(getString(finding, "algorithm")) == 0 || // algorithm == "aes"
		encoders["algorithm"].Encode(getString(finding, "algorithm")) == 1) // algorithm == "chacha20"
}

func extractSeverityFeatures(finding map[string]interface{}, encoders map[string]*LabelEncoder, features []float64) {
	features[21] = getBool(encoders["severity"].Encode(getString(finding, "severity")) == 0) // severity == "critical"
	features[22] = getBool(encoders["severity"].Encode(getString(finding, "severity")) == 1) // severity == "high"
	features[23] = getBool(encoders["severity"].Encode(getString(finding, "severity")) == 2) // severity == "medium"
	features[24] = getBool(encoders["severity"].Encode(getString(finding, "severity")) == 3) // severity == "low"
	features[25] = getBool(encoders["severity"].Encode(getString(finding, "severity")) == 4) // severity == "info"
}

func extractLanguageFeatures(finding map[string]interface{}, encoders map[string]*LabelEncoder, features []float64) {
	features[26] = getBool(encoders["language"].Encode(getString(finding, "language")) == 0)   // language == "c" || language == "cpp" || language == "c++"
	features[27] = getBool(encoders["language"].Encode(getString(finding, "language")) == 1 || // language == "python"
		encoders["language"].Encode(getString(finding, "language")) == 4 || // language == "java"
		encoders["language"].Encode(getString(finding, "language")) == 8 || // language == "javascript"
		encoders["language"].Encode(getString(finding, "language")) == 5) // language == "go"
	features[28] = getBool(encoders["language"].Encode(getString(finding, "language")) == 0 || // language == "c" || language == "cpp"
		encoders["language"].Encode(getString(finding, "language")) == 5 || // language == "rust"
		encoders["language"].Encode(getString(finding, "language")) == 5) // language == "go"
}

// getBool converts a boolean to a float64.
func getBool(condition bool) float64 {
	if condition {
		return 1.0
	}
	return 0.0
}

// ExtractFeatures extracts features from a finding for ML prediction
func ExtractFeatures(finding map[string]interface{}, encoders map[string]*LabelEncoder) []float64 {
	features := make([]float64, 34) // Match the number of features from training

	extractCategoricalFeatures(finding, encoders, features)
	extractFileFeatures(finding, encoders, features)
	extractPatternFeatures(finding, features)
	extractAlgorithmFeatures(finding, encoders, features)
	extractSeverityFeatures(finding, encoders, features)
	extractLanguageFeatures(finding, encoders, features)

	// Additional features to match training
	features[29] = 0.0 // ai_is_valid (not available during prediction)
	features[30] = 0.0 // ai_confidence (not available during prediction)
	features[31] = 0.0 // ai_severity encoded (not available during prediction)
	features[32] = 0.0 // has_ai_evaluation (always false during prediction)
	features[33] = 0.0 // finding_id (not used for prediction)

	return features
}

// EnhanceFindingWithML enhances a finding with ML predictions
func EnhanceFindingWithML(finding map[string]interface{}, models *MLModels) map[string]interface{} {
	// Extract features
	features := ExtractFeatures(finding, models.Encoders)

	// Make predictions
	enhanced := make(map[string]interface{})
	for k, v := range finding {
		enhanced[k] = v
	}

	// False positive prediction
	if models.FalsePositiveDetector != nil {
		fpScore := models.FalsePositiveDetector.Predict(features)
		enhanced["ml_false_positive_score"] = fpScore
		enhanced["ml_is_likely_valid"] = fpScore > 0.5
	}

	// Confidence prediction
	if models.ConfidencePredictor != nil {
		confClass := models.ConfidencePredictor.PredictClass(features)
		enhanced["ml_confidence_class"] = confClass
	}

	// Severity prediction
	if models.SeverityClassifier != nil {
		sevClass := models.SeverityClassifier.PredictClass(features)
		enhanced["ml_predicted_severity"] = sevClass
	}

	return enhanced
}
