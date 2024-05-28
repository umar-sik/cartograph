package main

import (
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/TheHackerDev/cartograph/internal/analyzer"
	"github.com/TheHackerDev/cartograph/internal/config"
)

func main() {
	startTime := time.Now()

	// DEBUG: set debug output level
	log.SetLevel(log.DebugLevel)

	// Enable timestamps in logging (including milliseconds)
	log.SetFormatter(&log.TextFormatter{TimestampFormat: "2006-01-02 15:04:05.0000", FullTimestamp: true})

	log.Info("vectorizer started.")

	// Get the config object, which is used by all plugins, and performs various initialization checks.
	// That is where the flags are all parsed as well.
	cfg, configErr := config.NewConfig()
	if configErr != nil {
		log.WithError(configErr).Fatal("unable to initialize application configuration")
	}

	// Initialize analyzer
	pluginAnalyzer, analyzerErr := analyzer.NewAnalyzer(cfg)
	if analyzerErr != nil {
		log.WithError(analyzerErr).Fatal("unable to initialize analyzer plugin")
	}

	// Create vectors in the database
	err := pluginAnalyzer.CreateVectors()
	if err != nil {
		log.WithError(err).Fatal("unable to create vectors")
	}

	log.Infof("successfully created vectors in %s", time.Since(startTime))
}
