class BlockbookWebSocketLib {

    constructor(api_url) {
        this.api_url = api_url;

        this.messageId = 0;
        this.pendingMessages = {};
        this.init_socket();
    }

    init_socket() {
        this.webSocket = new WebSocket(this.api_url);
        this.closed = false;

        this.webSocket.onopen = (event) => {
            console.log(`WebSocket to ${this.api_url} was opened.`);

            // Resend pending requests
            for (let [_, pendingMessage] of Object.entries(this.pendingMessages)) {
                console.log("Resending request ", pendingMessage);
                this.webSocket.send(JSON.stringify(pendingMessage["request"]))
            }
        };

        this.webSocket.onclose = (event) => {
            this.closed = true;
            console.log(`WebSocket to ${this.api_url} was closed!`);
            if (event.code !== 1001) { // 1001 - CLOSE_GOING_AWAY
                if (this.pendingMessages.length > 0) {
                    this.init_socket(this.api_url)
                }
            }
        }

        this.webSocket.onmessage = (event) => {
            const response = JSON.parse(event.data);
            if (this.pendingMessages[response.id]) {
                const callback = this.pendingMessages[response.id]["callback"];
                delete this.pendingMessages[response.id];
                callback(response["data"]);
            } else {
                console.log(`Received message over web socket for unknown request with id ${response.id} ${response}`)
            }
        }
    }

    send(request, callback) {
        if (this.closed) {
            this.init_socket()
        }
        this.pendingMessages[request.id] = {"callback": callback, "request": request, "tries": 0};
        if (this.webSocket.readyState === WebSocket.OPEN) {
            this.webSocket.send(JSON.stringify(request))
        }
    }

    sendAsync(request) {
        return new Promise((resolve, reject) => {
            let timeoutId = setTimeout(() => {
                delete this.pendingMessages[request.id];
                reject()
            }, 30000)

            this.send(request, (response) => {
                clearTimeout(timeoutId)
                resolve(response)
            })
        })
    }

    get newMessageId() {
        return this.messageId++;
    }

    async getTransactionsByAddressAsync(address) {
        let tries = 0;
        while(true) {
            tries++;
            try {
                var response = await this.sendAsync({
                    "id": `${this.newMessageId}`,
                    "method": "getAccountInfo",
                    "params": {
                        "gap": 20,
                        "details": "txids",
                        "descriptor": `${address}`
                    }
                });

                if ("txids" in response) {
                    return new Result(response["txids"], null);
                }
                return new Result([], null);
            } catch (error) {
                if (tries >= 3) {
                    return new Result(null, error)
                }
            }
        }
    }

    async getTransactionsAndAddressesByXPubAsync(xpub) {
        try {
            var response = await this.sendAsync({
                "id": `${this.newMessageId}`,
                "method": "getAccountInfo",
                "params": {
                    "gap": 20,
                    "details": "txids",
                    "descriptor": `${xpub}`
                }
            });

            if ("txids" in response) {
                return new Result({
                    "txids": response["txids"],
                    "addresses": response["tokens"]
                        .filter(token => token["transfers"] > 0)
                        .map(token => {
                            return {
                                "path": token["path"],
                                "address": token["name"],
                                "transfers": token["transfers"],
                            }
                        })
                }, null);
            }
            return new Result({
                "txids": [],
                "addresses": []
            }, null);
        } catch (error) {
            return new Result(null, error)
        }
    }
}

class Result {

    constructor(result, error) {
        this.result = result;
        this.error = error;
    }

    get success() {
        return !this.error && this.result
    }

    get failed() {
        return this.error && !this.result
    }
}
