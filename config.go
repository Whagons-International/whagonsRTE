package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

// Config holds all configuration values
type Config struct {
	DBHost      string `json:"db_host"`
	DBPort      string `json:"db_port"`
	DBUsername  string `json:"db_username"`
	DBPassword  string `json:"db_password"`
	DBLandlord  string `json:"db_landlord"`
	DBTelemetry string `json:"db_telemetry"` // Separate database for error telemetry
	ServerPort  string `json:"server_port"`
}

var config Config
var setupMode bool

const configFileName = ".whagons-config.json"

func init() {
	// Parse command line flags
	flag.BoolVar(&setupMode, "setup", false, "Run interactive setup to configure all variables")
	flag.Parse()

	if setupMode {
		// Run full interactive setup
		runInteractiveSetup()
		return
	}

	// Load configuration in priority order:
	// 1. .env file
	// 2. Custom config file (.whagons-config.json)
	// 3. Environment variables
	// 4. Defaults (with prompts for missing critical values)
	loadConfiguration()
}

// loadConfiguration loads config from multiple sources with fallbacks
func loadConfiguration() {
	var fromEnvFile, fromConfigFile bool

	// Try to load from .env file first
	if err := godotenv.Load(); err == nil {
		log.Println("✅ Loaded configuration from .env file")
		fromEnvFile = true
	} else {
		log.Printf("⚠️  No .env file found: %v", err)

		// Try to load from custom config file
		if loadFromConfigFile() {
			log.Println("✅ Loaded configuration from " + configFileName)
			fromConfigFile = true
		} else {
			log.Println("⚠️  No " + configFileName + " file found")
		}
	}

	// Initialize configuration from environment variables (with defaults)
	config = Config{
		DBHost:      getEnv("DB_HOST", "127.0.0.1"),
		DBPort:      getEnv("DB_PORT", "5432"),
		DBUsername:  getEnv("DB_USERNAME", "postgres"),
		DBPassword:  getEnv("DB_PASSWORD", ""),
		DBLandlord:  getEnv("DB_LANDLORD", "landlord"),
		DBTelemetry: getEnv("DB_TELEMETRY", "rte_telemetry"),
		ServerPort:  getEnv("SERVER_PORT", "8082"),
	}

	// If neither .env nor config file was found, prefer real environment variables (common in Docker/K8s).
	// Only fall back to interactive setup when we're truly missing all config sources.
	if !fromEnvFile && !fromConfigFile {
		hasAnyEnv := os.Getenv("DB_HOST") != "" ||
			os.Getenv("DB_PORT") != "" ||
			os.Getenv("DB_USERNAME") != "" ||
			os.Getenv("DB_PASSWORD") != "" ||
			os.Getenv("DB_LANDLORD") != "" ||
			os.Getenv("SERVER_PORT") != ""

		if hasAnyEnv {
			log.Println("✅ Loaded configuration from environment variables")
		} else {
			log.Println("🛠️  No configuration sources found (.env / config file / env vars) - running automatic setup...")
			log.Println("💡 You can also run with --setup flag to reconfigure anytime")
			runInteractiveSetup()
			return
		}
	}

	// Final validation
	if config.DBPassword == "" {
		log.Println("⚠️  Warning: DB_PASSWORD is not set")
		log.Println("🔍 Database connection may fail without proper credentials")
	}

	log.Println("✅ Configuration loaded successfully")
}

// runInteractiveSetup prompts user for all configuration values
func runInteractiveSetup() {
	log.Println("🛠️  Running interactive setup...")

	// Check if we're in an interactive environment
	if !isInteractive() {
		log.Println("⚠️  Non-interactive environment detected")
		log.Println("🔧 Using default values for all configuration")

		// Use all defaults in non-interactive mode
		config = Config{
			DBHost:     "127.0.0.1",
			DBPort:     "5432",
			DBUsername: "postgres",
			DBPassword: "", // Will need to be set manually
			DBLandlord: "landlord",
			ServerPort: "8082",
		}

		log.Println("⚠️  Database password not set - you'll need to:")
		log.Println("   1. Create a .env file with DB_PASSWORD=your_password")
		log.Println("   2. Or run with --setup in an interactive terminal")
		log.Println("   3. Or manually edit .whagons-config.json")

		// Save configuration
		if err := saveToConfigFile(); err != nil {
			log.Printf("❌ Error saving configuration: %v", err)
			os.Exit(1)
		}

		log.Println("✅ Default configuration saved to " + configFileName)
		return
	}

	log.Println("Press Enter to use default values shown in [brackets]")

	reader := bufio.NewReader(os.Stdin)

	// Collect all configuration values
	config.DBHost = promptWithDefault(reader, "Database Host", "127.0.0.1")
	config.DBPort = promptWithDefault(reader, "Database Port", "5432")
	config.DBUsername = promptWithDefault(reader, "Database Username", "postgres")
	config.DBPassword = promptWithDefault(reader, "Database Password", "")
	config.DBLandlord = promptWithDefault(reader, "Landlord Database Name", "landlord")
	config.ServerPort = promptWithDefault(reader, "Server Port", "8082")

	// Save configuration
	if err := saveToConfigFile(); err != nil {
		log.Printf("❌ Error saving configuration: %v", err)
		os.Exit(1)
	}

	log.Println("✅ Configuration saved to " + configFileName)
	log.Println("🚀 Setup complete! You can now run the application normally.")
	os.Exit(0)
}

// promptWithDefault prompts user for input with a default value
func promptWithDefault(reader *bufio.Reader, name, defaultValue string) string {
	if defaultValue != "" {
		fmt.Printf("%s [%s]: ", name, defaultValue)
	} else {
		fmt.Printf("%s: ", name)
	}

	input, err := reader.ReadString('\n')
	if err != nil {
		// In containers / non-interactive pipes, stdin can be closed and return EOF.
		// Treat this as "use default" instead of logging scary errors.
		if err == io.EOF {
			return defaultValue
		}
		log.Printf("⚠️  Error reading input for %s: %v", name, err)
		return defaultValue
	}

	input = strings.TrimSpace(input)
	if input == "" {
		return defaultValue
	}
	return input
}

// loadFromConfigFile loads configuration from JSON file
func loadFromConfigFile() bool {
	if _, err := os.Stat(configFileName); os.IsNotExist(err) {
		return false
	}

	data, err := os.ReadFile(configFileName)
	if err != nil {
		log.Printf("⚠️  Error reading %s: %v", configFileName, err)
		return false
	}

	var fileConfig Config
	if err := json.Unmarshal(data, &fileConfig); err != nil {
		log.Printf("⚠️  Error parsing %s: %v", configFileName, err)
		return false
	}

	// Set environment variables from config file so getEnv() works
	if fileConfig.DBHost != "" {
		os.Setenv("DB_HOST", fileConfig.DBHost)
	}
	if fileConfig.DBPort != "" {
		os.Setenv("DB_PORT", fileConfig.DBPort)
	}
	if fileConfig.DBUsername != "" {
		os.Setenv("DB_USERNAME", fileConfig.DBUsername)
	}
	if fileConfig.DBPassword != "" {
		os.Setenv("DB_PASSWORD", fileConfig.DBPassword)
	}
	if fileConfig.DBLandlord != "" {
		os.Setenv("DB_LANDLORD", fileConfig.DBLandlord)
	}
	if fileConfig.ServerPort != "" {
		os.Setenv("SERVER_PORT", fileConfig.ServerPort)
	}

	return true
}

// saveToConfigFile saves current configuration to JSON file
func saveToConfigFile() error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configFileName, data, 0600) // Read/write for owner only
}

// getEnv gets environment variable with fallback to default
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// isInteractive checks if the application is running in an interactive terminal
func isInteractive() bool {
	// Check if stdin is a terminal
	fileInfo, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	// Check if it's a character device (terminal)
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}
