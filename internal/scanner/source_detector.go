package scanner

import (
	"os"
	"path/filepath"
	"strings"
)

// LanguageInfo represents detected programming language information
type LanguageInfo struct {
	Language    string   `json:"language"`
	Files       []string `json:"files"`
	Confidence  float64  `json:"confidence"`
	PackageFile string   `json:"package_file,omitempty"`
}

// ProjectInfo contains detected project structure information
type ProjectInfo struct {
	Languages         []LanguageInfo `json:"languages"`
	PackageManagers   []string       `json:"package_managers"`
	SourceDirectories []string       `json:"source_directories"`
	ExcludedPaths     []string       `json:"excluded_paths"`
}

// ExclusionPattern defines a pattern for excluding files from scanning
type ExclusionPattern struct {
	Pattern  string `json:"pattern"`
	Priority int    `json:"priority"`
	Reason   string `json:"reason"`
}

// SourceDetector intelligently detects source code vs. build artifacts
type SourceDetector struct {
	rootPath string
	info     *ProjectInfo
}

// NewSourceDetector creates a new source detector
func NewSourceDetector(rootPath string) *SourceDetector {
	return &SourceDetector{
		rootPath: rootPath,
		info: &ProjectInfo{
			Languages:         make([]LanguageInfo, 0),
			PackageManagers:   make([]string, 0),
			SourceDirectories: make([]string, 0),
			ExcludedPaths:     make([]string, 0),
		},
	}
}

// Language detection patterns
var languageDetectors = map[string]struct {
	files       []string
	extensions  []string
	directories []string
	confidence  float64
}{
	"javascript": {
		files:       []string{"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"},
		extensions:  []string{".js", ".mjs", ".jsx"},
		directories: []string{"src", "lib", "app", "components"},
		confidence:  0.9,
	},
	"typescript": {
		files:       []string{"tsconfig.json", "tsconfig.build.json"},
		extensions:  []string{".ts", ".tsx"},
		directories: []string{"src", "lib", "app", "components"},
		confidence:  0.9,
	},
	"python": {
		files:       []string{"requirements.txt", "setup.py", "pyproject.toml", "Pipfile"},
		extensions:  []string{".py", ".pyx"},
		directories: []string{"src", "lib", "app", "modules"},
		confidence:  0.9,
	},
	"go": {
		files:       []string{"go.mod", "go.sum"},
		extensions:  []string{".go"},
		directories: []string{"cmd", "internal", "pkg", "api"},
		confidence:  0.95,
	},
	"rust": {
		files:       []string{"Cargo.toml", "Cargo.lock"},
		extensions:  []string{".rs"},
		directories: []string{"src", "lib"},
		confidence:  0.95,
	},
	"java": {
		files:       []string{"pom.xml", "build.gradle", "build.gradle.kts"},
		extensions:  []string{".java", ".kt", ".scala"},
		directories: []string{"src/main", "src/test", "app/src"},
		confidence:  0.9,
	},
	"csharp": {
		files:       []string{"*.csproj", "*.sln", "packages.config"},
		extensions:  []string{".cs", ".vb", ".fs"},
		directories: []string{"src", "app", "lib"},
		confidence:  0.9,
	},
	"ruby": {
		files:       []string{"Gemfile", "Gemfile.lock", "*.gemspec"},
		extensions:  []string{".rb", ".rake"},
		directories: []string{"lib", "app", "config"},
		confidence:  0.9,
	},
	"php": {
		files:       []string{"composer.json", "composer.lock"},
		extensions:  []string{".php", ".phtml"},
		directories: []string{"src", "app", "lib"},
		confidence:  0.9,
	},
	"cpp": {
		files:       []string{"CMakeLists.txt", "Makefile", "configure.ac"},
		extensions:  []string{".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"},
		directories: []string{"src", "include", "lib"},
		confidence:  0.8,
	},
}

// DetectProject analyzes the project structure and programming languages
func (sd *SourceDetector) DetectProject() (*ProjectInfo, error) {
	// Walk the directory tree
	err := filepath.Walk(sd.rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, _ := filepath.Rel(sd.rootPath, path)

		// Skip excluded paths
		if sd.shouldExclude(relPath) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Detect languages by files and extensions
		if !info.IsDir() {
			sd.analyzeFile(relPath, info.Name())
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Calculate final language scores and package managers
	sd.finalizeDetection()

	return sd.info, nil
}

// shouldExclude checks if a path should be excluded from scanning
func (sd *SourceDetector) shouldExclude(relPath string) bool {
	// During project detection, only exclude the most obvious non-source content
	// This is much less aggressive than the full exclusion patterns used during scanning

	// Critical exclusions - always exclude these during project detection
	criticalExclusions := []string{
		// Version control
		".git/", ".svn/", ".hg/",

		// Dependencies (these are never source code we want to analyze)
		"node_modules/", "vendor/", "venv/", "env/", ".cargo/",

		// Build outputs (these are generated, not source)
		"target/", "build/", "dist/", "out/", "bin/",

		// Package lock files (dependency metadata)
		"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.lock",
		"Pipfile.lock", "poetry.lock", "go.sum", "composer.lock", "Gemfile.lock",

		// Temporary and cache
		"tmp/", "temp/", ".cache/", "cache/",
	}

	// Check for critical exclusions
	for _, exclusion := range criticalExclusions {
		if strings.HasPrefix(relPath, exclusion) || relPath == strings.TrimSuffix(exclusion, "/") {
			sd.info.ExcludedPaths = append(sd.info.ExcludedPaths, relPath)
			return true
		}
	}

	// Check if it's a binary file by extension (but be permissive with header files)
	if sd.isBinaryFile(relPath) {
		sd.info.ExcludedPaths = append(sd.info.ExcludedPaths, relPath)
		return true
	}

	return false
}

// isBinaryFile determines if a file is binary and should be skipped
func (sd *SourceDetector) isBinaryFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))

	// Image files
	imageExts := []string{
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif",
		".webp", ".svg", ".ico", ".cur", ".psd", ".raw",
	}

	// Video files
	videoExts := []string{
		".mp4", ".avi", ".mov", ".wmv", ".flv", ".webm", ".mkv",
		".m4v", ".3gp", ".ogv", ".f4v",
	}

	// Audio files
	audioExts := []string{
		".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma", ".m4a",
		".opus", ".amr", ".aiff",
	}

	// Archive files
	archiveExts := []string{
		".zip", ".tar", ".gz", ".rar", ".7z", ".bz2", ".xz",
		".lz", ".z", ".jar", ".war", ".ear",
	}

	// Binary/executable files
	binaryExts := []string{
		".exe", ".dll", ".so", ".dylib", ".bin", ".out", ".app",
		".deb", ".rpm", ".msi", ".dmg", ".pkg", ".apk",
	}

	// Font files
	fontExts := []string{
		".ttf", ".otf", ".woff", ".woff2", ".eot",
	}

	// Database files
	dbExts := []string{
		".db", ".sqlite", ".sqlite3", ".mdb", ".accdb",
	}

	// Office/document files (often contain binary data)
	officeExts := []string{
		".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".pdf", ".odt", ".ods", ".odp",
	}

	// Combine all binary extensions
	allBinaryExts := make([]string, 0, len(imageExts)+len(videoExts)+len(audioExts)+len(archiveExts)+len(binaryExts)+len(fontExts)+len(dbExts)+len(officeExts))
	allBinaryExts = append(allBinaryExts, imageExts...)
	allBinaryExts = append(allBinaryExts, videoExts...)
	allBinaryExts = append(allBinaryExts, audioExts...)
	allBinaryExts = append(allBinaryExts, archiveExts...)
	allBinaryExts = append(allBinaryExts, binaryExts...)
	allBinaryExts = append(allBinaryExts, fontExts...)
	allBinaryExts = append(allBinaryExts, dbExts...)
	allBinaryExts = append(allBinaryExts, officeExts...)

	// Check if file extension matches any binary type
	for _, binExt := range allBinaryExts {
		if ext == binExt {
			return true
		}
	}

	return false
}

// analyzeFile analyzes a single file for language detection
func (sd *SourceDetector) analyzeFile(relPath, fileName string) {
	ext := filepath.Ext(fileName)

	for lang, detector := range languageDetectors {
		confidence := 0.0

		// Check file name matches
		for _, file := range detector.files {
			if matched, _ := filepath.Match(file, fileName); matched {
				confidence = detector.confidence
				if file == "go.mod" || file == "Cargo.toml" || file == "package.json" {
					sd.detectPackageManager(file)
				}
				break
			}
		}

		// Check extension matches
		if confidence == 0 {
			for _, validExt := range detector.extensions {
				if ext == validExt {
					confidence = 0.7 // Lower confidence for extension-only match
					break
				}
			}
		}

		// Check if in typical source directory
		for _, dir := range detector.directories {
			if strings.HasPrefix(relPath, dir+"/") {
				confidence += 0.1
			}
		}

		if confidence > 0 {
			sd.addLanguageEvidence(lang, relPath, confidence)
		}
	}
}

// addLanguageEvidence adds evidence for a programming language
func (sd *SourceDetector) addLanguageEvidence(language, file string, confidence float64) {
	// Find existing language info or create new
	for i := range sd.info.Languages {
		if sd.info.Languages[i].Language == language {
			sd.info.Languages[i].Files = append(sd.info.Languages[i].Files, file)
			sd.info.Languages[i].Confidence = (sd.info.Languages[i].Confidence + confidence) / 2
			return
		}
	}

	// Add new language
	sd.info.Languages = append(sd.info.Languages, LanguageInfo{
		Language:   language,
		Files:      []string{file},
		Confidence: confidence,
	})
}

// detectPackageManager identifies package managers from files
func (sd *SourceDetector) detectPackageManager(fileName string) {
	var pm string
	switch fileName {
	case "package.json", "package-lock.json":
		pm = "npm"
	case "yarn.lock":
		pm = "yarn"
	case "pnpm-lock.yaml":
		pm = "pnpm"
	case "go.mod":
		pm = "go"
	case "Cargo.toml":
		pm = "cargo"
	case "requirements.txt", "setup.py", "pyproject.toml":
		pm = "pip"
	case "Pipfile":
		pm = "pipenv"
	case "poetry.lock":
		pm = "poetry"
	case "composer.json":
		pm = "composer"
	case "Gemfile":
		pm = "bundler"
	case "pom.xml":
		pm = "maven"
	case "build.gradle":
		pm = "gradle"
	}

	if pm != "" && !contains(sd.info.PackageManagers, pm) {
		sd.info.PackageManagers = append(sd.info.PackageManagers, pm)
	}
}

// finalizeDetection calculates final scores and determines primary languages
func (sd *SourceDetector) finalizeDetection() {
	// Sort languages by confidence
	for i := 0; i < len(sd.info.Languages); i++ {
		for j := i + 1; j < len(sd.info.Languages); j++ {
			if sd.info.Languages[i].Confidence < sd.info.Languages[j].Confidence {
				sd.info.Languages[i], sd.info.Languages[j] = sd.info.Languages[j], sd.info.Languages[i]
			}
		}
	}

	// Identify source directories based on detected languages
	sd.identifySourceDirectories()
}

// identifySourceDirectories finds likely source code directories
func (sd *SourceDetector) identifySourceDirectories() {
	commonSourceDirs := []string{"src", "lib", "app", "internal", "pkg", "cmd", "components", "modules"}

	for _, dir := range commonSourceDirs {
		fullPath := filepath.Join(sd.rootPath, dir)
		if _, err := os.Stat(fullPath); err == nil {
			sd.info.SourceDirectories = append(sd.info.SourceDirectories, dir)
		}
	}
}

// GetEnhancedIgnorePatterns returns ignore patterns based on detected project structure
func (sd *SourceDetector) GetEnhancedIgnorePatterns() []string {
	patterns := make([]string, 0)

	// High priority exclusions - always exclude these
	highPriorityPatterns := []string{
		// Version control and metadata (critical)
		".git/*", ".svn/*", ".hg/*",

		// Dependencies and package managers (critical)
		"node_modules/*", "vendor/*", "venv/*", "env/*",
		"target/*", "build/*", "dist/*", "out/*", "bin/*",

		// Package lock files (critical - these contain dependency metadata, not source)
		"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.lock",
		"Pipfile.lock", "poetry.lock", "go.sum", "composer.lock", "Gemfile.lock",

		// Binary and archive files (critical)
		"*.exe", "*.dll", "*.so", "*.dylib", "*.a", "*.lib", "*.o", "*.obj", "*.bin",
		"*.zip", "*.tar", "*.tar.gz", "*.tar.bz2", "*.tar.xz", "*.rar", "*.7z",

		// Image and media files (critical)
		"*.jpg", "*.jpeg", "*.png", "*.gif", "*.bmp", "*.svg", "*.ico",
		"*.mp3", "*.mp4", "*.avi", "*.mov", "*.pdf",

		// Scanner rules (prevent self-scanning)
		"internal/scanner/rules/*", "*/scanner/rules/*", "*.rules.yaml", "*.rules.yml",

		// Temporary and cache files (only within project, not if project is in /tmp/)
		"./tmp/*", "./temp/*", ".cache/*", "cache/*", "*.tmp", "*.temp", "*.bak",
		"*.orig", "*.swp", ".DS_Store", "Thumbs.db",
	}

	patterns = append(patterns, highPriorityPatterns...)

	// Add language-specific patterns based on detected languages
	for _, lang := range sd.info.Languages {
		switch lang.Language {
		case "javascript", "typescript":
			patterns = append(patterns, "*.bundle.js", "*.chunk.js", "*.min.js", "*.min.css")
		case "python":
			patterns = append(patterns, "*.pyc", "*.pyo", "__pycache__/*", "*.egg-info/*")
		case "java":
			patterns = append(patterns, "*.class", "*.jar", "*.war", "target/classes/*")
		case "go":
			patterns = append(patterns, "go.work", "go.work.sum")
		case "rust":
			patterns = append(patterns, "target/debug/*", "target/release/*")
		}
	}

	// Only add moderate exclusions for smaller projects to avoid over-exclusion
	// For large projects like Kubernetes, don't exclude test directories or documentation
	totalFiles := 0
	for _, lang := range sd.info.Languages {
		totalFiles += len(lang.Files)
	}

	if totalFiles < 1000 {
		// Small project - more aggressive exclusions are OK
		moderatePriorityPatterns := []string{
			// Test files (only exclude in small projects)
			"*_test.go", "*_test.py", "*_test.js", "*_test.ts",
			"*.test.js", "*.test.ts", "*.spec.js", "*.spec.ts",

			// Documentation (only for small projects)
			"docs/*", "doc/*", "*.md", "README*", "CHANGELOG*", "LICENSE*",

			// Test directories (only for small projects)
			"test/*.js", "test/*.py", "tests/*.js", "tests/*.py",
			"__tests__/*", "spec/*", "testing/*",

			// Build system files
			"cmake/*", "m4/*", "configure", "configure.ac", "Makefile.am",
			"*.am", "*.in", "CMakeLists.txt", "*.cmake",
		}
		patterns = append(patterns, moderatePriorityPatterns...)
	}

	return patterns
}

// GetSourceCodePaths returns paths that likely contain source code
func (sd *SourceDetector) GetSourceCodePaths() []string {
	paths := make([]string, 0)

	// Add identified source directories
	paths = append(paths, sd.info.SourceDirectories...)

	// If no specific source directories found, suggest scanning root with exclusions
	if len(paths) == 0 {
		paths = append(paths, ".")
	}

	return paths
}

// contains checks if a string slice contains a value
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
