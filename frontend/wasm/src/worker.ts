import type { CPU, CST816S, Commander, NRF52832, Pinetime, Pins, Pointer, RTT, ST7789 } from "../infiniemu.js"
import createModule from "../infiniemu.js"

const iterations = 700000;

type PromiseResult<T> = T extends Promise<infer U> ? U : T;

type Module = PromiseResult<ReturnType<typeof createModule>>;

function pointerToNumber(ptr: Pointer) {
    return ptr as unknown as number;
}
function numberToPointer(num: number) {
    return num as unknown as Pointer;
}

class Emulator {
    private readonly rttReadBufferSize = 1024;

    private readonly pinetime: Pinetime;
    private readonly nrf52: NRF52832;
    private readonly lcd: ST7789;
    private readonly touch: CST816S;
    private readonly cpu: CPU;
    private readonly pins: Pins;
    private readonly cmd: Commander;
    private readonly rtt: RTT;

    private readonly rttReadBuffer: Pointer;

    private readonly displayBuffer: Pointer;
    private readonly rgbaBuffer: Pointer;

    private ctx2d: OffscreenCanvasRenderingContext2D | null = null;
    private imageData: ImageData | null = null;

    private runInterval: number | null = null;
    private isLcdSleeping = false;
    private isCPUSleeping = false;

    private rttFoundBlock = false;

    constructor(private readonly Module: Module, programFile: Uint8Array) {
        const program = Module._program_new(0x800000);

        const args = [program, 0, programFile, programFile.length];
        if (Module.ccall("program_load_elf", "number", ["number", "number", "array", "number"], args) === 0)
            Module.ccall("program_load_binary", null, ["number", "number", "array", "number"], args);

        this.pinetime = Module._pinetime_new(program, true);
        this.nrf52 = Module._pinetime_get_nrf52832(this.pinetime);
        this.lcd = Module._pinetime_get_st7789(this.pinetime);
        this.touch = Module._pinetime_get_cst816s(this.pinetime);
        this.pins = Module._nrf52832_get_pins(this.nrf52);
        this.cpu = Module._nrf52832_get_cpu(this.nrf52);
        this.cmd = Module._commander_new(this.pinetime);
        this.rtt = Module._rtt_new(Module._cpu_mem(this.cpu));

        Module._commander_set_output(this.cmd, Module._commander_output);

        this.displayBuffer = numberToPointer(Module._malloc(240 * 240 * 2));
        this.rgbaBuffer = numberToPointer(Module._malloc(240 * 240 * 4));
        this.rttReadBuffer = numberToPointer(Module._malloc(this.rttReadBufferSize));
    }

    private async run() {
        const start = performance.now();
        let screenUpdated: boolean;

        try {
            screenUpdated = this.Module._pinetime_loop(this.pinetime, iterations);
        } catch (error: any) {
            this.stop();
            postMessage({
                type: "error", data: {
                    message: "message" in error ? error.message : undefined,
                    stack: "stack" in error ? error.stack : undefined,
                    string: error.toString(),
                }
            });
            return;
        }

        if (!this.rttFoundBlock) {
            this.rttFoundBlock = !!this.Module._rtt_find_control(this.rtt);
        }
        if (this.rttFoundBlock) {
            const readBytes = this.Module._rtt_flush_buffers(this.rtt, this.rttReadBuffer, this.rttReadBufferSize);

            if (readBytes > 0) {
                const msg = this.Module.UTF8ToString(this.rttReadBuffer, readBytes);

                postMessage({
                    type: "rttData",
                    data: msg,
                });
            }
        }

        const end = performance.now();

        if (screenUpdated)
            this.sendScreenUpdate();

        const lcdSleepingNow = this.Module._st7789_is_sleeping(this.lcd);
        if (lcdSleepingNow !== this.isLcdSleeping) {
            this.isLcdSleeping = lcdSleepingNow;

            postMessage({
                type: "lcdSleeping",
                data: !!this.isLcdSleeping,
            });
        }

        const cpuSleepingNow = this.Module._cpu_is_sleeping(this.cpu);
        if (cpuSleepingNow !== this.isCPUSleeping) {
            this.isCPUSleeping = cpuSleepingNow;

            postMessage({
                type: "cpuSleeping",
                data: !!this.isCPUSleeping,
            });
        }

        postMessage({
            type: "performance",
            data: {
                loopTime: end - start,
                ips: iterations / ((end - start) / 1000),
                usedRam: this.Module._nrf52832_get_used_sram(this.nrf52),
            },
        });
    }

    private sendScreenUpdate() {
        this.Module._st7789_read_screen_rgba(this.lcd, this.displayBuffer, this.rgbaBuffer, 240, 240);

        const arr = new Uint8Array(this.Module.HEAPU8.buffer, this.rgbaBuffer as unknown as number, 240 * 240 * 4);

        if (this.ctx2d && this.imageData) {
            this.imageData.data.set(arr);
            this.ctx2d.putImageData(this.imageData, 0, 0);
        }
    }

    setCanvas(canvas: OffscreenCanvas) {
        this.ctx2d = canvas.getContext("2d")!;
        this.imageData = this.ctx2d.createImageData(240, 240);
    }

    start() {
        if (!this.runInterval) {
            this.runInterval = setInterval(() => this.run(), 1); // TODO: Maybe use 0 here?
            postMessage({ type: "running", data: true });
        }
    }

    stop() {
        if (this.runInterval) {
            clearInterval(this.runInterval);
            this.runInterval = null;
            postMessage({ type: "running", data: false });
        }
    }

    doTouch(gesture: number, x: number, y: number, duration?: number) {
        this.Module._cst816s_do_touch(this.touch, gesture, x, y);

        if (duration && duration > 0)
            setTimeout(() => this.Module._cst816s_release_touch(this.touch), duration);
    }

    clearTouch() {
        this.Module._cst816s_release_touch(this.touch);
    }

    changePin(pin: number, isSet: boolean) {
        if (isSet)
            this.Module._pins_set(this.pins, pin);
        else
            this.Module._pins_clear(this.pins, pin);
    }
};

let emulator: Emulator | null = null;
let Module: Module | null = null;

createModule({
    print(text) {
        console.log("text", text);
    },
    printErr(text) {
        console.log("got error");
    },
    onAbort(what: any) {
        console.log("abort");
    },
}).then((mod) => {
    Module = mod;
    postMessage({ type: "ready" });
});

onmessage = event => {
    const { type, data } = event.data;

    switch (type) {
        case "loadProgram":
            if (!Module) {
                postMessage({ type: "error", data: "Module not loaded" });
                return;
            }

            const buf = data as ArrayBuffer;

            emulator = new Emulator(Module, new Uint8Array(buf));
            break;

        case "setCanvas":
            if (emulator)
                emulator.setCanvas(data);
            break;

        case "start":
            if (emulator)
                emulator.start();
            break;

        case "stop":
            if (emulator)
                emulator.stop();
            break;

        case "doTouch":
            if (emulator)
                emulator.doTouch(data.gesture, data.x, data.y);
            break;

        case "clearTouch":
            if (emulator)
                emulator.clearTouch();
            break;

        case "pressButton":
            if (emulator)
                emulator.changePin(13, true);
            break;

        case "releaseButton":
            if (emulator)
                emulator.changePin(13, false);
            break;
    }
}
