package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/TheHackerDev/cartograph/internal/apiHunter"

	log "github.com/sirupsen/logrus"

	"github.com/TheHackerDev/cartograph/internal/analyzer"
	"github.com/TheHackerDev/cartograph/internal/config"
	"github.com/TheHackerDev/cartograph/internal/mapper"
	"github.com/TheHackerDev/cartograph/internal/proxy"
	"github.com/TheHackerDev/cartograph/internal/proxy/injector"
	"github.com/TheHackerDev/cartograph/internal/proxy/logger"
	"github.com/TheHackerDev/cartograph/internal/webui"
)

func main() {
	// Set logging output level
	if os.Getenv("DEBUG") == "true" {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	// Enable timestamps in logging (including milliseconds)
	log.SetFormatter(&log.TextFormatter{TimestampFormat: "2006-01-02 15:04:05.0000", FullTimestamp: true})

	log.Info("cartograph started.")

	// fatalErrChan is an error channel for use by all goroutines that send fatal error messages from the plugins.
	fatalErrChan := make(chan error, 1)

	// Get the config object, which is used by all plugins, and performs various initialization checks.
	// That is where the flags are all parsed as well.
	cfg, configErr := config.NewConfig()
	if configErr != nil {
		log.WithError(configErr).Fatal("unable to initialize application configuration")
	}

	// Start injector
	pluginInjector, injectorConfigErr := injector.NewInjector(cfg)
	if injectorConfigErr != nil {
		log.WithError(injectorConfigErr).Fatal("unable to initialize injector plugin")
	}
	go func() {
		if err := pluginInjector.Run(); err != nil {
			fatalErrChan <- fmt.Errorf("problem with injector plugin: %w", err)
		}
	}()

	// Start logger
	pluginLogger, loggerErr := logger.NewLogger(cfg)
	if loggerErr != nil {
		log.WithError(loggerErr).Fatal("unable to initialize logger plugin")
	}
	go func() {
		if err := pluginLogger.Run(); err != nil {
			fatalErrChan <- fmt.Errorf("problem with logger plugin: %w", err)
		}
	}()

	// Start mapper
	pluginMapper, mapperErr := mapper.NewMapper(cfg)
	if mapperErr != nil {
		log.WithError(mapperErr).Fatal("unable to initialize mapper plugin")
	}
	go func() {
		if err := pluginMapper.Run(); err != nil {
			fatalErrChan <- fmt.Errorf("problem with mapper plugin: %w", err)
		}
	}()

	// Start analyzer
	pluginAnalyzer, analyzerErr := analyzer.NewAnalyzer(cfg)
	if analyzerErr != nil {
		log.WithError(analyzerErr).Fatal("unable to initialize analyzer plugin")
	}
	go func() {
		if err := pluginAnalyzer.Run(); err != nil {
			fatalErrChan <- fmt.Errorf("problem with analyzer plugin: %w", err)
		}
	}()

	// Start API Hunter
	pluginAPIHunter := apiHunter.NewAPIHunter()

	// Start proxy
	pluginProxy := proxy.NewProxy(cfg, pluginInjector, pluginLogger, pluginMapper, pluginAnalyzer, pluginAPIHunter)
	go func() {
		if proxyErr := pluginProxy.Run(); proxyErr != nil {
			fatalErrChan <- fmt.Errorf("problem with proxy server: %w", proxyErr)
		}
	}()

	// Create API server
	mux := http.NewServeMux()

	// Config API
	mux.HandleFunc("/api/v1/config/targets/", cfg.TargetsHandler)

	// Injector API
	mux.Handle("/api/v1/injector/config/payloads/javascript/", injector.NewPayloadsJavaScriptAPIHandler(pluginInjector))

	// Logger data API
	// mux.Handle("/api/v1/logger/data/", logger.DataAPIHandler(pluginLogger))

	// Mapper API
	mux.HandleFunc("/api/v1/mapper/data/hosts/", pluginMapper.HostsDataAPIHandler)
	mux.HandleFunc("/api/v1/mapper/data/paths/", pluginMapper.PathsDataAPIHandler)
	mux.HandleFunc("/api/v1/mapper/data/hosts/all/gexf/", pluginMapper.AllHostsGexf)
	mux.HandleFunc("/api/v1/mapper/data/hosts/two-degrees/gexf/", pluginMapper.HostTwoDegreesGexf)
	mux.HandleFunc("/api/v1/mapper/data/hosts/one-degree/gexf/", pluginMapper.HostsOneDegreeGexf)
	mux.HandleFunc("/api/v1/mapper/data/paths-hosts/gexf/", pluginMapper.PathsAndConnectionsForHostsGexf)

	// Start API server
	go func() {
		if apiServerErr := http.ListenAndServe(":8000", mux); apiServerErr != nil {
			fatalErrChan <- fmt.Errorf("problem with API server: %w", apiServerErr)
		}
	}()

	// Start web UI plugin
	pluginWebUI, webUIErr := webui.NewWebUI(cfg)
	if webUIErr != nil {
		log.WithError(webUIErr).Fatal("unable to initialize web UI plugin")
	}
	go func() {
		if err := pluginWebUI.Run(); err != nil {
			fatalErrChan <- fmt.Errorf("problem with web UI plugin: %w", err)
		}
	}()

	// Listen for fatal errors
	fatalErr := <-fatalErrChan
	log.WithError(fatalErr).Fatal("fatal error received. Exiting.")
}
