
// This code will run in the web worker

// Listen for messages from the main thread
self.addEventListener("message", (event) => {
    const currentUrl = event.data.currentUrl;
    const urls = event.data.urls;

    // Return if there is no data left to send
    if (urls.length === 0) {
        return;
    }

    // Send the URLs to Cartograph Mapper
    const data = {source: currentUrl, destinations: urls};
    fetch(currentUrl, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-Cartograph": "mapper-data",
        },
        body: JSON.stringify(data),
    })
        .then((response) =>
            self.postMessage(
                `Sent URLs to Cartograph Mapper with response: ${response.status}`
            )
        )
        .catch((error) =>
            console.error(`Error sending URLs to Cartograph Mapper: ${error}`)
        );
});
