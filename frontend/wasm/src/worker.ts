import type { CPU, CST816S, Commander, Pinetime, Pins, Pointer, ST7789 } from "../infiniemu.js"
import createModule from "../infiniemu.js"

const iterations = 700000;

type PromiseResult<T> = T extends Promise<infer U> ? U : T;

type Module = PromiseResult<ReturnType<typeof createModule>>;

class Emulator {
    private readonly pinetime: Pinetime;
    private readonly lcd: ST7789;
    private readonly touch: CST816S;
    private readonly cpu: CPU;
    private readonly pins: Pins;
    private readonly cmd: Commander;

    private readonly displayBuffer: Pointer;
    private readonly rgbaBuffer: Pointer;

    private ctx2d: OffscreenCanvasRenderingContext2D | null = null;
    private imageData: ImageData | null = null;

    private runInterval: number | null = null;
    private isLcdSleeping = false;
    private isCPUSleeping = false;

    constructor(private readonly Module: Module, programFile: Uint8Array) {
        const program = Module._program_new(0x800000);

        const args = [program, 0, programFile, programFile.length];
        if (Module.ccall("program_load_elf", "number", ["number", "number", "array", "number"], args) === 0)
            Module.ccall("program_load_binary", null, ["number", "number", "array", "number"], args);

        this.pinetime = Module._pinetime_new(program, true);
        this.lcd = Module._pinetime_get_st7789(this.pinetime);
        this.touch = Module._pinetime_get_cst816s(this.pinetime);
        this.pins = Module._nrf52832_get_pins(Module._pinetime_get_nrf52832(this.pinetime));
        this.cpu = Module._nrf52832_get_cpu(Module._pinetime_get_nrf52832(this.pinetime));
        this.cmd = Module._commander_new(this.pinetime);

        Module._commander_set_output(this.cmd, Module._commander_output);

        this.displayBuffer = Module._malloc(240 * 240 * 2) as unknown as Pointer;
        this.rgbaBuffer = Module._malloc(240 * 240 * 4) as unknown as Pointer;
    }

    private async run() {
        const start = new Date().valueOf();
        let screenUpdated;

        try {
            screenUpdated = this.Module._pinetime_loop(this.pinetime, iterations);
        } catch (error: any) {
            this.stop();
            postMessage({ type: "error", data: error.stack?.toString() ?? error });
            return;
        }

        const end = new Date().valueOf();

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
                ips: iterations / ((end - start) / 1000)
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
        if (!this.runInterval)
            this.runInterval = setInterval(() => this.run(), 1); // TODO: Maybe use 0 here?
    }

    stop() {
        if (this.runInterval) {
            clearInterval(this.runInterval);
            this.runInterval = null;
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

createModule().then((mod) => {
    Module = mod;
    postMessage({ type: "ready" });
});

onmessage = event => {
    const { type, data } = event.data;
    console.log("Worker received message", type, data);

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
