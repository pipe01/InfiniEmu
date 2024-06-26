import type { CPU, CST816S, Commander, LFS, NRF52832, Pinetime, Pins, Pointer, RTT, SPINorFlash, ST7789 } from "../infiniemu.js"
import createModule from "../infiniemu.js"
import type { FileInfo, MessageFromWorkerType, MessageToWorkerType } from "./common";
import { joinLFSPaths } from "./utils.js";

const iterations = 700000;

const fsStart = 0x0B4000;
const fsEnd = 0x400000;

type PromiseResult<T> = T extends Promise<infer U> ? U : T;

type Module = PromiseResult<ReturnType<typeof createModule>>;

function pointerToNumber(ptr: Pointer) {
    return ptr as unknown as number;
}
function numberToPointer(num: number) {
    return num as unknown as Pointer;
}
function pointerAdd(ptr: Pointer, offset: number) {
    return numberToPointer(pointerToNumber(ptr) + offset);
}

function sendMessage<Type extends MessageFromWorkerType["type"]>(type: Type, data: Extract<MessageFromWorkerType, { type: Type }>["data"], replyTo?: number) {
    postMessage({ type, data, replyToId: replyTo });
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
    private readonly spiFlash: SPINorFlash;

    private readonly rttReadBuffer: Pointer;

    private readonly displayBuffer: Pointer;
    private readonly rgbaBuffer: Pointer;

    private ctx2d: OffscreenCanvasRenderingContext2D | null = null;
    private imageData: ImageData | null = null;

    private runInterval: number | null = null;
    private isLcdSleeping = false;
    private isCPUSleeping = false;

    private rttFoundBlock = false;

    private instructionCount = 0;

    constructor(private readonly Module: Module, programFile: Uint8Array) {
        const program = Module._program_new(0x800000);

        const args = [program, 0, programFile, programFile.length];
        if (Module.ccall("program_load_elf", "number", ["number", "number", "array", "number"], args) === 0)
            Module.ccall("program_load_binary", null, ["number", "number", "array", "number"], args);

        this.pinetime = Module._pinetime_new(program);
        this.nrf52 = Module._pinetime_get_nrf52832(this.pinetime);
        this.lcd = Module._pinetime_get_st7789(this.pinetime);
        this.touch = Module._pinetime_get_cst816s(this.pinetime);
        this.pins = Module._nrf52832_get_pins(this.nrf52);
        this.cpu = Module._nrf52832_get_cpu(this.nrf52);
        this.cmd = Module._commander_new(this.pinetime);
        this.rtt = Module._rtt_new(Module._cpu_mem(this.cpu));
        this.spiFlash = Module._pinetime_get_spinorflash(this.pinetime);

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
            sendMessage("error", {
                message: "message" in error ? error.message : undefined,
                stack: "stack" in error ? error.stack : undefined,
                string: error.toString(),
            });
            return;
        }

        this.instructionCount += iterations;

        if (this.instructionCount < 1000000 && !this.rttFoundBlock) {
            this.rttFoundBlock = !!this.Module._rtt_find_control(this.rtt);
            if (this.rttFoundBlock)
                sendMessage("rttFound", undefined);
        }
        if (this.rttFoundBlock) {
            const readBytes = this.Module._rtt_flush_buffers(this.rtt, this.rttReadBuffer, this.rttReadBufferSize);

            if (readBytes > 0) {
                const msg = this.Module.UTF8ToString(this.rttReadBuffer, readBytes);

                sendMessage("rttData", msg);
            }
        }

        const end = performance.now();

        if (screenUpdated)
            this.sendScreenUpdate();

        const lcdSleepingNow = this.Module._st7789_is_sleeping(this.lcd);
        if (lcdSleepingNow !== this.isLcdSleeping) {
            this.isLcdSleeping = !!lcdSleepingNow;

            sendMessage("lcdSleeping", this.isLcdSleeping);
        }

        const cpuSleepingNow = this.Module._cpu_is_sleeping(this.cpu);
        if (cpuSleepingNow !== this.isCPUSleeping) {
            this.isCPUSleeping = !!cpuSleepingNow;

            sendMessage("cpuSleeping", this.isCPUSleeping);
        }

        sendMessage("performance", {
            loopTime: end - start,
            ips: iterations / ((end - start) / 1000),
            totalSRAM: this.Module._nrf52832_get_sram_size(this.nrf52),
        });
    }

    private sendScreenUpdate() {
        this.Module._st7789_read_screen_rgba(this.lcd, this.displayBuffer, this.rgbaBuffer, 240, 240);

        const arr = new Uint8Array(this.Module.HEAPU8.buffer, pointerToNumber(this.rgbaBuffer), 240 * 240 * 4);

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
            this.runInterval = setInterval(() => this.run(), 0); // TODO: Maybe use 0 here?
            sendMessage("running", true);
        }
    }

    stop() {
        if (this.runInterval) {
            clearInterval(this.runInterval);
            this.runInterval = null;
            sendMessage("running", false);
        }
    }

    doTouch(gesture: number, x: number, y: number, duration?: number) {
        this.readDir("");

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

    private useLFS<T>(fn: (lfs: LFS) => T) {
        const bufferPtr = this.Module._spinorflash_get_buffer(this.spiFlash);
        const lfs = this.Module._lfs_init(pointerAdd(bufferPtr, fsStart), fsEnd - fsStart);

        let ret: T;
        try {
            ret = fn(lfs);
        } finally {
            this.Module._lfs_free_wasm(lfs);
        }

        return ret;
    }

    readDir(path: string) {
        return this.useLFS(lfs => {
            const info = this.Module._lfs_info_malloc();
            const pathBytes = this.Module.stringToNewUTF8(path);

            const dir = this.Module._lfs_open_dir(lfs, pathBytes);
            if (!dir)
                throw new Error("Error opening dir");

            const files: FileInfo[] = [];

            while (true) {
                const err = this.Module._lfs_dir_read(lfs, dir, info);
                if (err < 0) {
                    throw new Error("Error reading dir: " + err);
                }
                else if (err > 0) {
                    const name = this.Module.UTF8ToString(this.Module._lfs_info_name(info));
                    files.push({
                        name,
                        fullPath: joinLFSPaths(path, name),
                        size: this.Module._lfs_info_size(info),
                        type: this.Module._lfs_info_type(info) == 1 ? "file" : "dir",
                    });
                }
                else {
                    break; // No more files
                }
            }

            this.Module._free(pointerToNumber(dir as unknown as Pointer));
            this.Module._free(pointerToNumber(info as unknown as Pointer));
            this.Module._free(pointerToNumber(pathBytes));

            return files;
        });
    }

    readFile(path: string) {
        return this.useLFS(lfs => {
            const pathBytes = this.Module.stringToNewUTF8(path);

            const file = this.Module._lfs_open_file(lfs, pathBytes, 0);
            if (!file)
                throw new Error("Error opening file");

            const bufferSize = 1024;
            const buffer = numberToPointer(this.Module._malloc(bufferSize));

            let fullBuffer = new Uint8Array(1);
            let totalReadBytes = 0;

            while (true) {
                const readBytes = this.Module._lfs_file_read(lfs, file, buffer, bufferSize);
                if (readBytes <= 0)
                    break;

                const data = new Uint8Array(this.Module.HEAPU8.buffer, pointerToNumber(buffer), readBytes);

                if (totalReadBytes + readBytes > fullBuffer.byteLength) {
                    let newSize = fullBuffer.byteLength;
                    while (newSize < totalReadBytes + readBytes) {
                        newSize *= 2;
                    }

                    const newBuffer = new Uint8Array(newSize);
                    newBuffer.set(new Uint8Array(fullBuffer));
                    fullBuffer = newBuffer;
                } else {
                    fullBuffer.set(data, totalReadBytes);
                }

                totalReadBytes += readBytes;
            }

            this.Module._free(pointerToNumber(file as unknown as Pointer));
            this.Module._free(pointerToNumber(buffer));

            return fullBuffer.slice(0, totalReadBytes);
        });
    }

    createDir(path: string) {
        return this.useLFS(lfs => {
            const pathBytes = this.Module.stringToNewUTF8(path);

            const ret = this.Module._lfs_mkdir(lfs, pathBytes);
            if (ret < 0)
                throw new Error("Error creating dir: " + ret);

            this.Module._free(pointerToNumber(pathBytes));
        });
    }

    backupFS() {
        const bufferPtr = this.Module._spinorflash_get_buffer(this.spiFlash);
        const data = new Uint8Array(this.Module.HEAPU8.buffer, pointerToNumber(bufferPtr) + fsStart, fsEnd - fsStart);

        return new Uint8Array(data);
    }

    restoreFS(backup: ArrayBuffer) {
        const bufferPtr = this.Module._spinorflash_get_buffer(this.spiFlash);
        const data = new Uint8Array(this.Module.HEAPU8.buffer, pointerToNumber(bufferPtr) + fsStart, fsEnd - fsStart);

        data.set(new Uint8Array(backup));
    }
};

let emulator: Emulator | null = null;
let Module: Module | null = null;

createModule({
    print(text) {
        console.log("text", text);
    },
    printErr(text) {
        console.log("got error", text);
    },
    onAbort(what: any) {
        console.log("abort", what);
    },
}).then((mod) => {
    Module = mod;
    sendMessage("ready", undefined);
});

function handleMessage(msg: MessageToWorkerType) {
    const { type, data } = msg;

    switch (type) {
        case "setProgram":
            if (!Module) {
                sendMessage("error", {
                    message: "Module not loaded",
                    stack: undefined,
                    string: "Module not loaded",
                });
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

        case "readDir":
            if (emulator)
                sendMessage("dirFiles", emulator.readDir(data), msg.messageId);
            break;

        case "readFile":
            if (emulator)
                sendMessage("fileData", { path: data, data: emulator.readFile(data) }, msg.messageId);
            break;

        case "createDir":
            if (emulator) {
                emulator.createDir(data);
                sendMessage("done", undefined, msg.messageId);
            }
            break;

        case "backupFS":
            if (emulator)
                sendMessage("backupData", emulator.backupFS().buffer, msg.messageId);
            break;

        case "restoreFS":
            if (emulator) {
                emulator.restoreFS(data);
                sendMessage("done", undefined, msg.messageId);
            }
            break;
    }
}

onmessage = event => {
    try {
        handleMessage(event.data as MessageToWorkerType);
    } catch (error: any) {
        sendMessage("error", {
            message: "message" in error ? error.message : undefined,
            stack: "stack" in error ? error.stack : undefined,
            string: error.toString(),
        });
    }
}
