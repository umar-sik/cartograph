
function sendUrlsToCartographMapper() {
    const currentUrl = window.location.href;
    const urlMap = new Map();

    // Array of non-standard URL schemes
    const nonStandardSchemes = [
        "javascript:",
        "data:",
        "mailto:",
        "tel:",
        "sms:",
        "whatsapp:",
        "skype:",
        "viber:",
        "callto:",
        "facetime:",
        "facetime-audio:",
        "whatsapp-web:",
        "skypeconference:",
        "skypeim:",
        "facetime-messaging:",
        "#", // This is a special case, since it's not a URL scheme, just a fragment
    ];

    // Find all URLs in various HTML elements
    Array.from(document.getElementsByTagName("a")).forEach((a) => {
        // Remove any links using non-standard URL schemes
        if (nonStandardSchemes.some((scheme) => a.href.startsWith(scheme))) {
            return;
        }

        const url = new URL(a.href, currentUrl);
        urlMap.set(url.href, true);
    });
    Array.from(document.getElementsByTagName("img")).forEach((img) => {
        // Don't add links that use the "data:" URL scheme
        if (img.src.startsWith("data:")) {
            return;
        }

        const url = new URL(img.src, currentUrl);
        urlMap.set(url.href, true);
    });
    Array.from(document.getElementsByTagName("link")).forEach((link) => {
        const url = new URL(link.href, currentUrl);
        urlMap.set(url.href, true);
    });
    Array.from(document.getElementsByTagName("script")).forEach((script) => {
        // Do not add references to our own scripts
        if (script.src.includes("mapper.js")) {
            return;
        }

        const url = new URL(script.src, currentUrl);
        urlMap.set(url.href, true);
    });
    Array.from(document.getElementsByTagName("iframe")).forEach((iframe) => {
        // Don't add links that use the "data:" URL scheme
        if (iframe.src.startsWith("data:")) {
            return;
        }

        const url = new URL(iframe.src, currentUrl);
        urlMap.set(url.href, true);
    });
    Array.from(document.getElementsByTagName("embed")).forEach((embed) => {
        // Don't add links that use the "data:" URL scheme
        if (embed.src.startsWith("data:")) {
            return;
        }

        const url = new URL(embed.src, currentUrl);
        urlMap.set(url.href, true);
    });
    ["video", "audio"].forEach((tagName) => {
        Array.from(document.getElementsByTagName(tagName)).forEach(
            (mediaElement) => {
                Array.from(mediaElement.getElementsByTagName("source")).forEach(
                    (source) => {
                        const url = new URL(source.src, currentUrl);
                        urlMap.set(url.href, true);
                    }
                );
            }
        );
    });
    Array.from(document.getElementsByTagName("track")).forEach((track) => {
        const url = new URL(track.src, currentUrl);
        urlMap.set(url.href, true);
    });
    Array.from(document.getElementsByTagName("object")).forEach((obj) => {
        // Don't add links that use the "data:" URL scheme
        if (obj.data.startsWith("data:")) {
            return;
        }

        const url = new URL(obj.data, currentUrl);
        urlMap.set(url.href, true);
    });
    Array.from(document.getElementsByTagName("form")).forEach((form) => {
        const url = new URL(form.action || currentUrl, currentUrl);
        urlMap.set(url.href, true);
    });

    // Fetch and create web worker as blob, so I can add a custom header to the
    // request
    const xhr = new XMLHttpRequest();
    xhr.open("GET", "mapper-worker.js");
    xhr.responseType = "blob";
    xhr.onload = function () {
        const workerBlob = this.response;
        const worker = new Worker(URL.createObjectURL(workerBlob));

        // Send a message to the web worker with the current URL and URLs to map
        worker.postMessage({currentUrl, urls: Array.from(urlMap.keys())});

        // Listen for messages from the web worker
        worker.addEventListener("message", (event) => {
            // console.log(event.data);
        });

        // Monitor the DOM for newly added URLs
        const observer = new MutationObserver((mutationsList) => {
            for (const mutation of mutationsList) {
                for (const target of mutation.addedNodes) {
                    if (target instanceof Element) {
                        const urlAttributes = ["href", "src", "data", "action"];
                        const urlValues = urlAttributes
                            .map((attr) => target.getAttribute(attr))
                            .filter(Boolean);

                        urlValues.forEach((url) => {
                            const absoluteUrl = new URL(url, currentUrl).href;
                            if (!urlMap.has(absoluteUrl)) {
                                // Add the URL to the list of URLs to map
                                urlMap.set(absoluteUrl, true);

                                // Send a message to the web worker with the current URL and new URL to map
                                worker.postMessage({currentUrl, urls: [absoluteUrl]});
                            }
                        });
                    }
                }
            }
        });

        // Start observing changes to the DOM tree
        observer.observe(document.body, {childList: true, subtree: true});
    };

    xhr.send();
}

// Check if the window has loaded.
// If it has, run the script.
// If it hasn't, wait for the window to load and then run the script.
if (document.readyState === "complete") {
    sendUrlsToCartographMapper();
} else {
    window.addEventListener("load", function () {
        sendUrlsToCartographMapper();
    });
}
