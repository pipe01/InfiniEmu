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

var isLcdSleeping = false;
var displayBufferPointer, rgbaBufferPointer;

let imageData, ctx2d;

function sendScreenUpdate() {
    Module._st7789_read_screen_rgba(lcd, displayBufferPointer, rgbaBufferPointer, 240, 240);

    const arr = new Uint8Array(Module.HEAPU8.buffer, rgbaBufferPointer, 240 * 240 * 4);

    imageData.data.set(arr);
    ctx2d.putImageData(imageData, 0, 0);
}

onmessage = (e) => {
    switch (e.data.type) {
        case "init":
            const canvas = e.data.canvas;
            ctx2d = canvas.getContext("2d");
            imageData = ctx2d.createImageData(240, 240);
            break;

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

        case "loadProgram":
            if (pt) {
                console.error("Pinetime already loaded");
                return;
            }

            const program = Module._program_new(0x800000);
            const args = [program, 0, e.data.program, e.data.program.length];
            if (Module.ccall("program_load_elf", "number", ["number", "number", "array", "number"], args) === 0)
                Module.ccall("program_load_binary", null, ["number", "number", "array", "number"], args);

            pt = Module._pinetime_new(program, true);
            lcd = Module._pinetime_get_st7789(pt);
            touch = Module._pinetime_get_cst816s(pt);
            pins = Module._nrf52832_get_pins(Module._pinetime_get_nrf52832(pt));

            displayBufferPointer = Module._malloc(240 * 240 * 2);
            rgbaBufferPointer = Module._malloc(240 * 240 * 4);

            const interval = setInterval(() => {
                const start = new Date().valueOf();
                let screenUpdated;

                try {
                    screenUpdated = Module._pinetime_loop(pt, iterations);
                } catch (error) {
                    clearInterval(interval);
                    postMessage({ type: "error", data: error.stack.toString() });
                    return;
                }

                const end = new Date().valueOf();

                if (screenUpdated)
                    sendScreenUpdate();

                const lcdSleepingNow = Module._st7789_is_sleeping(lcd);
                if (lcdSleepingNow !== isLcdSleeping) {
                    isLcdSleeping = lcdSleepingNow;

                    postMessage({
                        type: "lcdSleeping",
                        data: isLcdSleeping,
                    });
                }

                postMessage({
                    type: "performance",
                    data: {
                        loopTime: end - start,
                        ips: iterations / ((end - start) / 1000)
                    },
                });
            }, 1);
            break;
    }
};
