// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.
// https://deno.com/
// This module is browser compatible.

class TextLineStream extends TransformStream {

    constructor() {
        super({
            transform: (chunk, controller) => this.handle(chunk, controller),
            flush: (controller) => {
                if (this.buffer.length > 0) {
                    controller.enqueue(this.buffer)
                }
            },
        });
        this.buffer = ""
    }

    handle(chunk, controller) {
        chunk = this.buffer + chunk;

        let lfIndex = chunk.indexOf("\n")
        while (lfIndex !== -1) {
            controller.enqueue(chunk.slice(0, lfIndex));
            chunk = chunk.slice(lfIndex + 1);
            lfIndex = chunk.indexOf("\n")
        }
    }
}
