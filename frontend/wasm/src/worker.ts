import { ZipEntry, ZipFileEntry, fs } from "@zip.js/zip.js";
import type { CPU, CST816S, Commander, LFS, NRF52832, Pinetime, Pins, Pointer, Program, RTT, SPINorFlash, ST7789 } from "../infiniemu.js"
import createModule from "../infiniemu.js"
import type { FileInfo, MessageFromWorkerType, MessageToWorkerType } from "./common";
import { joinLFSPaths } from "./utils.js";

const iterations = 100000;

const fsStart = 0x0B4000;
const fsEnd = 0x400000;

const LFS_O_RDONLY = 1;         // Open a file as read only
const LFS_O_WRONLY = 2;         // Open a file as write only
const LFS_O_RDWR = 3;         // Open a file as read and write
const LFS_O_CREAT = 0x0100;    // Create a file if it does not exist
const LFS_O_EXCL = 0x0200;    // Fail if a file already exists
const LFS_O_TRUNC = 0x0400;    // Truncate the existing file to zero size
const LFS_O_APPEND = 0x0800;    // Move to end of file on every write

const LFS_ERR_OK = 0;    // No error
const LFS_ERR_IO = -5;   // Error during device operation
const LFS_ERR_CORRUPT = -84;  // Corrupted
const LFS_ERR_NOENT = -2;   // No directory entry
const LFS_ERR_EXIST = -17;  // Entry already exists
const LFS_ERR_NOTDIR = -20;  // Entry is not a dir
const LFS_ERR_ISDIR = -21;  // Entry is a dir
const LFS_ERR_NOTEMPTY = -39;  // Dir is not empty
const LFS_ERR_BADF = -9;   // Bad file number
const LFS_ERR_FBIG = -27;  // File too large
const LFS_ERR_INVAL = -22;  // Invalid parameter
const LFS_ERR_NOSPC = -28;  // No space left on device
const LFS_ERR_NOMEM = -12;  // No more memory available
const LFS_ERR_NOATTR = -61;  // No data/attr available
const LFS_ERR_NAMETOOLONG = -36;  // File name too long

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

function isFile(file: ZipEntry): file is ZipFileEntry<void, void> {
    return !(file as any).directory;
}

class Emulator {
    private readonly rttReadBufferSize = 1024;

    private readonly program: Program;
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

    turboMode = false;

    private rttFoundBlock = false;

    private instructionCount = 0;

    get isRunning() {
        return !!this.runInterval;
    }

    constructor(private readonly Module: Module, programFile: Uint8Array) {
        this.program = Module._program_new(0x800000);

        const args = [this.program, 0, programFile, programFile.length];
        if (Module.ccall("program_load_elf", "number", ["number", "number", "array", "number"], args) === 0)
            Module.ccall("program_load_binary", null, ["number", "number", "array", "number"], args);

        this.pinetime = Module._pinetime_new(this.program);
        this.nrf52 = Module._pinetime_get_nrf52832(this.pinetime);
        this.lcd = Module._pinetime_get_st7789(this.pinetime);
        this.touch = Module._pinetime_get_cst816s(this.pinetime);
        this.pins = Module._nrf52832_get_pins(this.nrf52);
        this.cpu = Module._nrf52832_get_cpu(this.nrf52);
        this.cmd = Module._commander_new(this.pinetime);
        this.rtt = Module._rtt_new(Module._cpu_mem(this.cpu));
        this.spiFlash = Module._pinetime_get_spinorflash(this.pinetime);

        (globalThis as any).commander_output = (msgPointer: Pointer) => {
            const msg = Module.UTF8ToString(msgPointer);
            sendMessage("commandOutput", msg);
        };

        Module._commander_set_wasm_output(this.cmd);

        this.displayBuffer = numberToPointer(Module._malloc(240 * 240 * 2));
        this.rgbaBuffer = numberToPointer(Module._malloc(240 * 240 * 4));
        this.rttReadBuffer = numberToPointer(Module._malloc(this.rttReadBufferSize));
    }

    private doLoop(iterations: number) {
        this.instructionCount += iterations;
        return this.Module._pinetime_loop(this.pinetime, iterations);
    }

    private run() {
        const start = performance.now();
        const instructionCountStart = this.instructionCount;
        let screenUpdated = false;

        if (this.turboMode) {
            screenUpdated = this.doLoop(10000000);
        }
        else {
            while (this.isRunning && !screenUpdated && performance.now() - start < 50) {
                screenUpdated ||= this.doLoop(iterations);
            }
        }

        if (this.instructionCount < 10000000 && !this.rttFoundBlock) {
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
            ips: (this.instructionCount - instructionCountStart) / ((end - start) / 1000),
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
            this.runInterval = setInterval(() => this.run(), 0);
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

    reset() {
        this.Module._pinetime_reset(this.pinetime);
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

            const file = this.Module._lfs_open_file(lfs, pathBytes, LFS_O_RDONLY);
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

    writeFile(path: string, data: Uint8Array) {
        return this.useLFS(lfs => {
            const pathBytes = this.Module.stringToNewUTF8(path);

            const file = this.Module._lfs_open_file(lfs, pathBytes, LFS_O_CREAT | LFS_O_WRONLY | LFS_O_TRUNC);
            if (!file)
                throw new Error("Error opening file");

            const buffer = this.Module._malloc(data.length);
            this.Module.HEAPU8.set(data, buffer);

            const ret = this.Module._lfs_file_write(lfs, file, numberToPointer(buffer), data.length);
            if (ret < 0)
                throw new Error("Error writing file: " + ret);

            this.Module._lfs_file_close(lfs, file);

            this.Module._free(pointerToNumber(file as unknown as Pointer));
            this.Module._free(buffer);
            this.Module._free(pointerToNumber(pathBytes));
        });
    }

    createDir(path: string) {
        return this.useLFS(lfs => {
            const pathBytes = this.Module.stringToNewUTF8(path);

            const ret = this.Module._lfs_mkdir(lfs, pathBytes);
            if (ret < 0 && ret != LFS_ERR_EXIST)
                throw new Error("Error creating dir: " + ret);

            this.Module._free(pointerToNumber(pathBytes));
        });
    }

    async loadArchiveFS(toPath: string, data: Uint8Array) {
        const zip = new fs.FS();
        await zip.importUint8Array(data);

        let importedResources = false;

        const resourcesFile = zip.find("resources.json");
        if (resourcesFile && isFile(resourcesFile)) {
            const resourcesData = await resourcesFile.getText();
            const manifest = JSON.parse(resourcesData) as { resources: { filename: string, path: string }[] };

            if ("resources" in manifest) {
                const createdDirs = new Set<string>();

                for (const res of manifest.resources) {
                    const file = zip.find(res.filename);
                    if (file && isFile(file)) {
                        const path = joinLFSPaths(toPath, res.path);
                        const fileData = await file.getUint8Array();

                        const parts = res.path.split("/").reduce((acc, part) => [...acc, joinLFSPaths(...acc, part)], [] as string[]);
                        for (const dir of parts.slice(1, -1)) {
                            const path = joinLFSPaths(toPath, dir);

                            if (!createdDirs.has(path)) {
                                this.createDir(path);
                                createdDirs.add(path);
                            }
                        }

                        this.writeFile(path, fileData);
                    }
                }

                importedResources = true;
            }
        }

        if (!importedResources) {
            // TODO: Implement
            alert("Only InfiniTime resource archives are supported at the moment.");
        }
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

    setBackupTime(date: Date) {
        const name1 = this.Module.stringToNewUTF8("NoInit_MagicWord");
        const name2 = this.Module.stringToNewUTF8("NoInit_BackUpTime");

        try {
            if (this.Module._program_write_variable(this.program, this.cpu, name1, 0xDEAD0000, 0)) {
                const unixNano = BigInt(date.getTime()) * BigInt(1000000);
                this.Module._program_write_variable(this.program, this.cpu, name2, Number(unixNano & 0xFFFFFFFFn), Number(unixNano >> 32n));
            }
        } finally {
            this.Module._free(pointerToNumber(name1));
            this.Module._free(pointerToNumber(name2));
        }
    }

    runCommand(command: string) {
        const commandBytes = this.Module.stringToNewUTF8(command);

        try {
            this.Module._commander_run_command(this.cmd, commandBytes);
        } finally {
            this.Module._free(pointerToNumber(commandBytes));
        }
    }
};

let emulator: Emulator | null = null;
let Module: Module | null = null;

createModule({
    print(text) {
        console.log("stdout", text);
    },
    printErr(text) {
        console.log("got error", text);
    },
    onAbort(what: any) {
        console.error("wasm aborted", what);
        sendMessage("aborted", what);
    },
}).then((mod) => {
    Module = mod;
    sendMessage("ready", undefined);
});

function handleMessage(msg: MessageToWorkerType) {
    const { type, data } = msg;

    if (type == "setProgram") {
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
    }
    else if (emulator) {
        switch (type) {
            case "setCanvas":
                emulator.setCanvas(data);
                break;

            case "setBackupTime":
                emulator.setBackupTime(data);
                break;

            case "start":
                emulator.start();
                break;

            case "stop":
                emulator.stop();
                break;

            case "doTouch":
                emulator.doTouch(data.gesture, data.x, data.y);
                break;

            case "clearTouch":
                emulator.clearTouch();
                break;

            case "pressButton":
                emulator.changePin(13, true);
                break;

            case "releaseButton":
                emulator.changePin(13, false);
                break;

            case "readDir":
                sendMessage("dirFiles", emulator.readDir(data), msg.messageId);
                break;

            case "readFile":
                sendMessage("fileData", { path: data, data: emulator.readFile(data) }, msg.messageId);
                break;

            case "createDir":
                emulator.createDir(data);
                break;

            case "writeFile":
                emulator.writeFile(data.path, new Uint8Array(data.data));
                break;

            case "loadArchiveFS":
                emulator.loadArchiveFS(data.path, new Uint8Array(data.zipData));
                break;

            case "backupFS":
                sendMessage("backupData", emulator.backupFS().buffer, msg.messageId);
                break;

            case "restoreFS":
                emulator.restoreFS(data);
                break;

            case "turboMode":
                emulator.turboMode = data;
                break;

            case "reset":
                emulator.reset();
                break;

            case "runCommand":
                emulator.runCommand(data);
                break;
        }
    }
    else {
        sendMessage("error", {
            message: "Emulator not initialized",
            stack: undefined,
            string: "Emulator not initialized",
        });

        return;
    }

    sendMessage("done", undefined, msg.messageId);
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
