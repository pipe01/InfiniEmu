console.log("hello");

var Module = {
    preRun: [],
    onRuntimeInitialized() {
        console.log("InfiniEmu initialized");

        postMessage({ type: "ready" });
    },
};

importScripts("infiniemu.js");

const iterations = 700000;

var pt, lcd, touch, pins;

var displayBufferPointer;

function sendScreenUpdate() {
    Module._st7789_read_screen(lcd, displayBufferPointer, 240, 240);

    const arr = new Uint8Array(Module.HEAPU8.buffer, displayBufferPointer, 240 * 240 * 2);

    postMessage({
        type: "screenLoaded",
        data: arr,
    });
}

onmessage = (e) => {
    console.log(e);
    
    switch (e.data.type) {
        case "doTouch":
            Module._cst816s_do_touch(touch, e.data.gesture, e.data.x, e.data.y);

            if (e.data.duration)
                setTimeout(() => Module._cst816s_release_touch(touch), e.data.duration);
            break;

        case "clearTouch":
            Module._cst816s_release_touch(touch);
            break;
        
        case "pressButton":
            Module._pins_set(pins, 13);
            break;

        case "releaseButton":
            Module._pins_clear(pins, 13);
            break;

        case "loadProgramFile":
            if (pt) {
                console.error("Pinetime already loaded");
                return;
            }

            const reader = new FileReader();
            reader.onload = function (e) {
                const program = new Uint8Array(e.target.result);

                pt = Module.ccall("pinetime_new", "any", ["array", "number", "boolean"], [program, program.length, true]);
                lcd = Module._pinetime_get_st7789(pt);
                touch = Module._pinetime_get_cst816s(pt);
                pins = Module._nrf52832_get_pins(Module._pinetime_get_nrf52832(pt));

                displayBufferPointer = Module._malloc(240 * 240 * 2);

                let screenUpdated = false;

                const displayInterval = setInterval(() => {
                    if (screenUpdated) {
                        sendScreenUpdate();
                        screenUpdated = false;
                    }
                }, 1000 / 30);

                const interval = setInterval(() => {
                    const start = new Date().valueOf();

                    try {
                        if (Module._pinetime_loop(pt, iterations))
                            screenUpdated = true;
                    } catch (error) {
                        clearInterval(displayInterval);
                        clearInterval(interval);
                        throw error;
                    }

                    const end = new Date().valueOf();

                    postMessage({
                        type: "performance",
                        data: {
                            loopTime: end - start,
                            ips: iterations / ((end - start) / 1000)
                        },
                    });
                }, 1);
            }
            reader.readAsArrayBuffer(e.data.file);
            break;
    }
};
