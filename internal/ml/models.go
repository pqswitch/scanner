package ml

import (
	"encoding/json"
	"fmt"
	"math"
)

// MLModel represents a lightweight ML model for confidence scoring
type MLModel interface {
	Predict(features []float64) float64
	GetFeatureNames() []string
	GetModelType() string
	GetVersion() string
}

// DecisionTreeNode represents a node in a decision tree
type DecisionTreeNode struct {
	FeatureIndex int               `json:"feature_index"`
	Threshold    float64           `json:"threshold"`
	Value        float64           `json:"value"` // For leaf nodes
	Left         *DecisionTreeNode `json:"left"`
	Right        *DecisionTreeNode `json:"right"`
	IsLeaf       bool              `json:"is_leaf"`
}

// DecisionTree implements a lightweight decision tree model
type DecisionTree struct {
	Root         *DecisionTreeNode      `json:"root"`
	FeatureNames []string               `json:"feature_names"`
	Version      string                 `json:"version"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// NewDecisionTree creates a new decision tree model
func NewDecisionTree(featureNames []string) *DecisionTree {
	return &DecisionTree{
		FeatureNames: featureNames,
		Version:      "1.0",
		Metadata:     make(map[string]interface{}),
	}
}

// Predict returns the prediction for given features
func (dt *DecisionTree) Predict(features []float64) float64 {
	if dt.Root == nil {
		return 0.5 // Default confidence
	}
	return dt.predictNode(dt.Root, features)
}

// predictNode recursively traverses the tree
func (dt *DecisionTree) predictNode(node *DecisionTreeNode, features []float64) float64 {
	if node.IsLeaf {
		return node.Value
	}

	if node.FeatureIndex >= len(features) {
		return 0.5 // Default if feature missing
	}

	if features[node.FeatureIndex] <= node.Threshold {
		if node.Left != nil {
			return dt.predictNode(node.Left, features)
		}
	} else {
		if node.Right != nil {
			return dt.predictNode(node.Right, features)
		}
	}

	return 0.5 // Default fallback
}

// GetFeatureNames returns the feature names
func (dt *DecisionTree) GetFeatureNames() []string {
	return dt.FeatureNames
}

// GetModelType returns the model type
func (dt *DecisionTree) GetModelType() string {
	return "decision_tree"
}

// GetVersion returns the model version
func (dt *DecisionTree) GetVersion() string {
	return dt.Version
}

// LinearRegression implements a lightweight linear regression model
type LinearRegression struct {
	Weights      []float64              `json:"weights"`
	Bias         float64                `json:"bias"`
	FeatureNames []string               `json:"feature_names"`
	Version      string                 `json:"version"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// NewLinearRegression creates a new linear regression model
func NewLinearRegression(featureNames []string) *LinearRegression {
	return &LinearRegression{
		Weights:      make([]float64, len(featureNames)),
		Bias:         0.0,
		FeatureNames: featureNames,
		Version:      "1.0",
		Metadata:     make(map[string]interface{}),
	}
}

// Predict returns the prediction for given features
func (lr *LinearRegression) Predict(features []float64) float64 {
	if len(features) != len(lr.Weights) {
		return 0.5 // Default if feature count mismatch
	}

	prediction := lr.Bias
	for i, feature := range features {
		prediction += feature * lr.Weights[i]
	}

	// Apply sigmoid to get confidence score between 0 and 1
	return sigmoid(prediction)
}

// GetFeatureNames returns the feature names
func (lr *LinearRegression) GetFeatureNames() []string {
	return lr.FeatureNames
}

// GetModelType returns the model type
func (lr *LinearRegression) GetModelType() string {
	return "linear_regression"
}

// GetVersion returns the model version
func (lr *LinearRegression) GetVersion() string {
	return lr.Version
}

// RandomForest implements a lightweight random forest model
type RandomForest struct {
	Trees        []*DecisionTree        `json:"trees"`
	FeatureNames []string               `json:"feature_names"`
	Version      string                 `json:"version"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// NewRandomForest creates a new random forest model
func NewRandomForest(featureNames []string) *RandomForest {
	return &RandomForest{
		Trees:        make([]*DecisionTree, 0),
		FeatureNames: featureNames,
		Version:      "1.0",
		Metadata:     make(map[string]interface{}),
	}
}

// AddTree adds a decision tree to the forest
func (rf *RandomForest) AddTree(tree *DecisionTree) {
	rf.Trees = append(rf.Trees, tree)
}

// Predict returns the average prediction from all trees
func (rf *RandomForest) Predict(features []float64) float64 {
	if len(rf.Trees) == 0 {
		return 0.5
	}

	sum := 0.0
	for _, tree := range rf.Trees {
		sum += tree.Predict(features)
	}

	return sum / float64(len(rf.Trees))
}

// GetFeatureNames returns the feature names
func (rf *RandomForest) GetFeatureNames() []string {
	return rf.FeatureNames
}

// GetModelType returns the model type
func (rf *RandomForest) GetModelType() string {
	return "random_forest"
}

// GetVersion returns the model version
func (rf *RandomForest) GetVersion() string {
	return rf.Version
}

// ModelRegistry manages multiple ML models
type ModelRegistry struct {
	models map[string]MLModel
}

// NewModelRegistry creates a new model registry
func NewModelRegistry() *ModelRegistry {
	return &ModelRegistry{
		models: make(map[string]MLModel),
	}
}

// RegisterModel registers a model with a name
func (mr *ModelRegistry) RegisterModel(name string, model MLModel) {
	mr.models[name] = model
}

// GetModel retrieves a model by name
func (mr *ModelRegistry) GetModel(name string) (MLModel, bool) {
	model, exists := mr.models[name]
	return model, exists
}

// ListModels returns all registered model names
func (mr *ModelRegistry) ListModels() []string {
	names := make([]string, 0, len(mr.models))
	for name := range mr.models {
		names = append(names, name)
	}
	return names
}

// PredictWithFallback tries multiple models with fallback
func (mr *ModelRegistry) PredictWithFallback(features []float64, modelNames ...string) float64 {
	for _, name := range modelNames {
		if model, exists := mr.models[name]; exists {
			prediction := model.Predict(features)
			if prediction > 0 && prediction < 1 { // Valid confidence range
				return prediction
			}
		}
	}
	return 0.5 // Default fallback
}

// Helper functions

// sigmoid applies sigmoid function to convert to 0-1 range
func sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

// LoadModelFromJSON loads a model from JSON data
func LoadModelFromJSON(data []byte, modelType string) (MLModel, error) {
	switch modelType {
	case "decision_tree":
		var model DecisionTree
		if err := json.Unmarshal(data, &model); err != nil {
			return nil, fmt.Errorf("failed to unmarshal decision tree: %w", err)
		}
		return &model, nil

	case "linear_regression":
		var model LinearRegression
		if err := json.Unmarshal(data, &model); err != nil {
			return nil, fmt.Errorf("failed to unmarshal linear regression: %w", err)
		}
		return &model, nil

	case "random_forest":
		var model RandomForest
		if err := json.Unmarshal(data, &model); err != nil {
			return nil, fmt.Errorf("failed to unmarshal random forest: %w", err)
		}
		return &model, nil

	default:
		return nil, fmt.Errorf("unknown model type: %s", modelType)
	}
}

// SaveModelToJSON saves a model to JSON
func SaveModelToJSON(model MLModel) ([]byte, error) {
	return json.MarshalIndent(model, "", "  ")
}
