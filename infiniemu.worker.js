var Module = {
    preRun: [],
    onRuntimeInitialized() {
        console.log("InfiniEmu initialized");
    },
};

importScripts("infiniemu.js");

const pinetime_new = Module.cwrap("pinetime_new", "any", ["array", "number", "boolean"]);
const pinetime_get_st7789 = Module.cwrap("pinetime_get_st7789", "any", ["any"]);

const st7789_read_screen = Module.cwrap("st7789_read_screen", "any", ["any", "number", "number", "number"]);
const st7789_is_sleeping = Module.cwrap("st7789_is_sleeping", "boolean", ["any"]);

const memset_test = Module.cwrap("memset_test", null, ["any", "number"]);

const iterations = 5000000;

var pt, lcd;

// let instCounter = 0;

// setInterval(() => {
//     console.log(instCounter);
//     instCounter = 0;
// }, 1000);

var displayBufferPointer;

onmessage = (e) => {
    console.log("Message received from main script", e.data);

    switch (e.data.type) {
        case "loadScreen":
            Module._st7789_read_screen(lcd, displayBufferPointer, 240, 240);
            
            const arr = new Uint8Array(Module.HEAPU8.buffer, displayBufferPointer, 240 * 240 * 2);
            console.log(arr.filter((v) => v !== 0).length, arr.length);

            postMessage({
                type: "screenLoaded",
                data: arr,
            });

            console.log("load screen", arr);
            break;

        case "loadProgramFile":
            if (pt) {
                console.error("Pinetime already loaded");
                return;
            }

            const reader = new FileReader();
            reader.onload = function (e) {
                const program = new Uint8Array(e.target.result);

                pt = pinetime_new(program, program.length, true);
                lcd = pinetime_get_st7789(pt);

                displayBufferPointer = Module._malloc(240 * 240 * 2);

                setInterval(() => {
                    const start = new Date().valueOf();

                    Module._pinetime_loop(pt, iterations);

                    const end = new Date().valueOf();

                    // console.log("Instructions per second", iterations / ((end - start) / 1000));
                }, 1);
            }
            reader.readAsArrayBuffer(e.data.file);
            break;
    }
};
