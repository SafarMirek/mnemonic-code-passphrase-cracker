class DictionaryReader {

    constructor(file) {
        this.file = file;
    }

    async* getWords() {
        const lines = this.file.stream()
            .pipeThrough(new TextDecoderStream())
            .pipeThrough(new TextLineStream());

        // Tests empty passphrase first
        yield "";

        for await (const line of streamAsyncIterator(lines)) {
            // TODO: This is a place where we can apply some modifications on the provided word, for example try it with cap letters, etc..
            yield line;
        }
    }
}

async function* streamAsyncIterator(stream) {
    // Get a lock on the stream
    const reader = stream.getReader();

    try {
        while (true) {
            // Read from the stream
            const {done, value} = await reader.read();
            // Exit if we're done
            if (done) return;
            // Else yield the chunk
            yield value;
        }
    } finally {
        reader.releaseLock();
    }
}
