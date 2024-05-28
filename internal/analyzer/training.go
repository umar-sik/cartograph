package analyzer

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/TheHackerDev/cartograph/internal/shared/datatypes"
)

// LogCorpusData saves the given corpus data to the analyzer, which will be saved to the database.
func (a *Analyzer) LogCorpusData(httpReqResp *datatypes.HttpReqResp) {
	// Check if the analyzer is enabled and in training mode
	if !a.enabled || !a.training {
		return
	}

	// Send the corpus data to the input channel
	a.corpusDataInput <- httpReqResp
}

// saveToCorpusCache saves the given corpus data to the cache.
func (a *Analyzer) saveToCorpusCache(corpusData *datatypes.CorpusData) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.corpusDataCache = append(a.corpusDataCache, corpusData)
}

// saveCorpusCacheToDatabase saves the corpus data cache to the database.
func (a *Analyzer) saveCorpusCacheToDatabase() {
	ctx := context.Background()

	// Lock the mutex, so we can safely access the cache
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Iterate through the cache and save the data to the database
	for _, corpusData := range a.corpusDataCache {
		// Save the URL path parts to the database
		_, saveUrlPathPartsErr := a.dbConnPool.Exec(ctx, `INSERT INTO corpus_url_path_parts (name, count)
			SELECT distinct unnest($1::text[]) AS name, 1 AS count
			ON CONFLICT (name)
			DO UPDATE SET count = corpus_url_path_parts.count + 1;`, corpusData.URLPathParts)
		if saveUrlPathPartsErr != nil {
			log.WithError(saveUrlPathPartsErr).WithField("parts", corpusData.URLPathParts).Error("unable to save URL path parts to database")
		}

		// Save the header keys to the database
		_, saveHeaderKeysErr := a.dbConnPool.Exec(ctx, `INSERT INTO corpus_http_header_keys (name, count)
			SELECT distinct unnest($1::text[]) AS name, 1 AS count
			ON CONFLICT (name)
			DO UPDATE SET count = corpus_http_header_keys.count + 1;`, corpusData.HeaderKeys)
		if saveHeaderKeysErr != nil {
			log.WithError(saveHeaderKeysErr).WithField("keys", corpusData.HeaderKeys).Error("unable to save header keys to database")
		}

		// Save the URL query parameter keys to the database
		_, saveUrlQueryKeysErr := a.dbConnPool.Exec(ctx, `INSERT INTO corpus_url_param_keys (name, count)
			SELECT distinct unnest($1::text[]) AS name, 1 AS count
			ON CONFLICT (name)
			DO UPDATE SET count = corpus_url_param_keys.count + 1;`, corpusData.ParameterKeys)
		if saveUrlQueryKeysErr != nil {
			log.WithError(saveUrlQueryKeysErr).WithField("keys", corpusData.ParameterKeys).Error("unable to save URL query parameter keys to database")
		}

		// Save the server header value to the database
		_, saveServerHeaderValueErr := a.dbConnPool.Exec(ctx, `INSERT INTO corpus_server_header_values (name, count)
			VALUES ($1, 1)
			ON CONFLICT (name)
			DO UPDATE SET count = corpus_server_header_values.count + 1;`, corpusData.ServerValue)
		if saveServerHeaderValueErr != nil {
			log.WithError(saveServerHeaderValueErr).WithField("value", corpusData.ServerValue).Error("unable to save server header value to database")
		}

		// Save the file extension value to the database
		// _, saveFileExtensionValuesErr := a.dbConnPool.Exec(ctx, `INSERT INTO corpus_file_extensions (name, count)
		//		VALUES ($1, 1)
		//		ON CONFLICT (name)
		//		DO UPDATE SET count = corpus_file_extensions.count + 1;`, corpusData.FileExtension)
		// if saveFileExtensionValuesErr != nil {
		//	log.WithError(saveFileExtensionValuesErr).WithField("value", corpusData.FileExtension).Error("unable to save file extension value to database")
		// }

		// Save the cookie keys to the database
		_, saveCookieKeysErr := a.dbConnPool.Exec(ctx, `INSERT INTO corpus_cookie_keys (name, count)
    			SELECT distinct unnest($1::text[]) AS name, 1 AS count
    			ON CONFLICT (name)
				DO UPDATE SET count = corpus_cookie_keys.count + 1;`, corpusData.CookieKeys)
		if saveCookieKeysErr != nil {
			log.WithError(saveCookieKeysErr).WithField("keys", corpusData.CookieKeys).Error("unable to save cookie keys to database")
		}
	}
}

func (a *Analyzer) clearCorpusCache() {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Clear the cache, while keeping the allocated memory
	a.corpusDataCache = a.corpusDataCache[:0]
}
